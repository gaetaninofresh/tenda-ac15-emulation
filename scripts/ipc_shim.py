#!/usr/bin/env python3
from __future__ import annotations

import atexit
import ctypes
import ctypes.util
import errno
import os
import struct
import time
from pathlib import Path
from typing import Optional

from emu_logging import hook_logger

IPC_CREAT, IPC_EXCL, IPC_NOWAIT = 0o1000, 0o2000, 0o4000
MSG_NOERROR = 0o10000
IPC_RMID = 0

_log = hook_logger('ipc_shim')

_libc = ctypes.CDLL(ctypes.util.find_library('c')
                    or 'libc.so.6', use_errno=True)
_libc.msgget.argtypes = [ctypes.c_int, ctypes.c_int]
_libc.msgget.restype = ctypes.c_int
_libc.msgsnd.argtypes = [ctypes.c_int,
                         ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
_libc.msgsnd.restype = ctypes.c_int
_libc.msgrcv.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                         ctypes.c_long, ctypes.c_int]
_libc.msgrcv.restype = ctypes.c_ssize_t
_libc.msgctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_libc.msgctl.restype = ctypes.c_int

_HOST_LONG = ctypes.sizeof(ctypes.c_long)
_HOST_FMT = '=q' if _HOST_LONG == 8 else '=l'


def _s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def _sguest(v: int, size: int) -> int:
    bits = size * 8
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def _errno() -> int:
    return ctypes.get_errno() or errno.EIO


class IpcShim:
    def __init__(self,
                 registry_dir: str = '.',
                 force_create: bool = True,
                 drop_oldest_when_full: bool = True,
                 rcv_timeout: Optional[float] = 3.0,
                 max_logged_payload: int = 200):
        """
        force_create           make msgget() succeed even without IPC_CREAT
        drop_oldest_when_full  a full queue (nobody reading) drops its oldest
                               message instead of blocking the sender forever
        rcv_timeout            seconds a blocking msgrcv() waits before failing
                               with EINTR (None = block like a real kernel)
        """
        self.force_create = force_create
        self.drop_oldest_when_full = drop_oldest_when_full
        self.rcv_timeout = rcv_timeout
        self.max_logged_payload = max_logged_payload

        self._owner_pid = os.getpid()
        self._registry = Path(registry_dir) / 'ipc_queues.txt'
        self._registry.parent.mkdir(parents=True, exist_ok=True)
        self._cleanup_registry()          # stale queues from earlier runs
        atexit.register(self._atexit)

    # ---------------------------------------------------------------- install
    def install(self, ql) -> None:
        ql.os.set_syscall('msgget', self.msgget)
        ql.os.set_syscall('msgsnd', self.msgsnd)
        ql.os.set_syscall('msgrcv', self.msgrcv)

    # ------------------------------------------------------ queue bookkeeping
    def _record(self, msqid: int, key: int) -> None:
        # O_APPEND: safe to call concurrently from forked emulator processes
        with open(self._registry, 'a') as f:
            f.write(f'{msqid} {key & 0xFFFFFFFF:#x} {os.getpid()}\n')

    def _cleanup_registry(self) -> None:
        if not self._registry.exists():
            return
        removed = 0
        for line in self._registry.read_text().splitlines():
            try:
                msqid = int(line.split()[0])
            except (ValueError, IndexError):
                continue
            if _libc.msgctl(msqid, IPC_RMID, None) == 0:
                removed += 1
        self._registry.write_text('')
        if removed:
            _log.info('removed %d host queue(s) recorded in %s',
                      removed, self._registry.name)

    def _atexit(self) -> None:
        # forked children inherit this handler: only the original process cleans up
        if os.getpid() == self._owner_pid:
            self._cleanup_registry()

    # --------------------------------------------------------------- syscalls
    def msgget(self, ql, key, msgflg):
        key32 = _s32(key)
        mode = msgflg & 0o777

        if not self.force_create:
            msqid = _libc.msgget(key32, msgflg)
            if msqid < 0:
                return -_errno()
            return msqid

        # Try to create first (CREAT|EXCL) so we know whether WE made it; only
        # queues we created are recorded for removal at exit.
        msqid = _libc.msgget(key32, IPC_CREAT | IPC_EXCL | mode)
        if msqid >= 0:
            self._record(msqid, key32)
            _log.info('msgget key=%#x flags=%#o -> CREATED queue msqid=%d%s',
                      key32 & 0xFFFFFFFF, msgflg, msqid,
                      '' if msgflg & IPC_CREAT else
                      '  (guest passed no IPC_CREAT: created on the fly)')
            if key32 == -1:
                _log.warning('key is -1: ftok() failed in the guest, every such '
                             'caller will share this one queue')
            return msqid

        if _errno() != errno.EEXIST:
            e = _errno()
            _log.warning('msgget key=%#x failed: %s',
                         key32 & 0xFFFFFFFF, os.strerror(e))
            return -e

        # already there: just open it
        msqid = _libc.msgget(key32, mode)
        if msqid < 0:
            return -_errno()
        _log.debug('msgget key=%#x -> existing queue msqid=%d',
                   key32 & 0xFFFFFFFF, msqid)
        return msqid

    def msgsnd(self, ql, msqid, msgp, msgsz, msgflg):
        psz = ql.arch.pointersize
        try:
            mtype = ql.mem.read_ptr(msgp)                       # guest long
            payload = bytes(ql.mem.read(msgp + psz, msgsz))
        except Exception:
            return -errno.EFAULT

        buf = ctypes.create_string_buffer(_HOST_LONG + msgsz)
        struct.pack_into(_HOST_FMT, buf, 0, mtype)
        buf[_HOST_LONG:_HOST_LONG + msgsz] = payload

        flags = msgflg | IPC_NOWAIT if self.drop_oldest_when_full else msgflg
        for attempt in range(64):
            if _libc.msgsnd(msqid, buf, msgsz, flags) == 0:
                break
            e = _errno()
            if e == errno.EAGAIN and self.drop_oldest_when_full and not (msgflg & IPC_NOWAIT):
                # queue full and nobody is consuming: discard the oldest message
                tmp = ctypes.create_string_buffer(_HOST_LONG + 8192)
                _libc.msgrcv(msqid, tmp, 8192, 0, IPC_NOWAIT | MSG_NOERROR)
                _log.debug('queue %d full, dropped oldest message', msqid)
                continue
            _log.warning('msgsnd msqid=%s failed: %s', msqid, os.strerror(e))
            return -e
        else:
            return -errno.EAGAIN

        shown = payload[:self.max_logged_payload]
        _log.info('msgsnd msqid=%s mtype=%d size=%d payload=%r%s', msqid, mtype, msgsz,
                  shown, ' ...' if len(payload) > len(shown) else '')
        return 0

    def msgrcv(self, ql, msqid, msgp, msgsz, msgtyp, msgflg):
        psz = ql.arch.pointersize
        # long: <0 means "lowest type <= -msgtyp"
        msgtyp = _sguest(msgtyp, psz)
        buf = ctypes.create_string_buffer(_HOST_LONG + msgsz)
        deadline = None if self.rcv_timeout is None else time.monotonic() + \
            self.rcv_timeout

        while True:
            # Always poll with IPC_NOWAIT and sleep in Python: keeps Ctrl-C working
            # and avoids freezing the whole emulator inside a kernel wait.
            n = _libc.msgrcv(msqid, buf, msgsz, msgtyp, msgflg | IPC_NOWAIT)
            if n >= 0:
                break
            e = _errno()
            if e == errno.ENOMSG and not (msgflg & IPC_NOWAIT):
                if deadline is not None and time.monotonic() >= deadline:
                    _log.warning(
                        'msgrcv msqid=%s timed out after %ss', msqid, self.rcv_timeout)
                    return -errno.EINTR
                time.sleep(0.01)
                continue
            return -e

        mtype = struct.unpack_from(_HOST_FMT, buf, 0)[0]
        data = buf.raw[_HOST_LONG:_HOST_LONG + n]
        try:
            ql.mem.write_ptr(msgp, mtype)
            ql.mem.write(msgp + psz, data)
        except Exception:
            return -errno.EFAULT
        _log.info('msgrcv msqid=%s mtype=%d size=%d payload=%r', msqid, mtype, n,
                  data[:self.max_logged_payload])
        return n
