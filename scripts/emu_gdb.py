
from ipc_shim import IpcShim
from emu_logging import setup_logging, hook_logger
from gdb_debugging_ext import GdbManager
from qiling.const import QL_VERBOSE, QL_INTERCEPT, QL_ARCH
from qiling import Qiling
from qiling.os.posix.syscall.socket import get_opened_socket
import qiling.os.posix.syscall.sched as sched
import errno
import multiprocessing
import os
import socket
import threading
import time
import sys
sys.path.append("..")


ROOTFS = os.environ.get('ROOTFS', r'./firmware/tendaac15/rootfs')

_nvram_manager = multiprocessing.Manager()
NVRAM_STORE = _nvram_manager.dict({
    'lan.webiplansslen': b'192.168.170.169',
})


def nvram_listener():
    server_address = fr'{ROOTFS}/var/cfm_socket'

    if os.path.exists(server_address):
        os.unlink(server_address)

    # Create UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(server_address)
    sock.listen(1)

    with open('cfm_socket.log', 'wb') as ofile:
        while True:
            data = bytearray()
            connection, _ = sock.accept()

            try:
                while True:
                    chunk = connection.recv(1024)
                    if not chunk:
                        break
                    data += chunk

                    matched = False
                    for key_str, val_bytes in list(NVRAM_STORE.items()):
                        if key_str.encode('utf-8') in data:
                            connection.send(val_bytes)
                            matched = True
                            break

                    if not matched:
                        break

                    ofile.write(data)
                    data.clear()
            finally:
                connection.close()


# Global dictionary to track active network buffers across thread execution
active_buffers = {}


# One logger per hook. All of them end up in small_log (+ complete_log).
log_exec = hook_logger('execve')
log_file = hook_logger('file')
log_net = hook_logger('net')
log_sock = hook_logger('socket')
log_ipc = hook_logger('ipc')
log_stdio = hook_logger('guest_stdio')
log_clone = hook_logger('clone')


def _signed(ql, value):
    """Syscall return values arrive as Python ints that may be negative or may
    be the unsigned register image of a negative errno; normalise to signed."""
    bits = ql.arch.bits
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >= (1 << (bits - 1)) else value


def _o_creat(ql):
    # O_CREAT is 0x40 on ARM/x86 but 0x100 on MIPS. (On ARM, 0x100 is
    # O_NOCTTY, so testing both flags gives false "FILE CREATED" events.)
    return 0x100 if ql.arch.type == QL_ARCH.MIPS else 0x40


def _hook_failed(name):
    # Hooks must never raise into the emulator, but they must not fail
    # silently either: record the traceback at DEBUG (complete_log only).
    hook_logger(name).debug('hook raised', exc_info=True)


def hook_execve(ql, path_addr, argv_addr, envp_addr, *args):
    try:
        path = ql.mem.string(path_addr)

        # Read argv[] (read_ptr honours pointer size and endianness)
        ptr_size = ql.arch.pointersize
        args_list = []
        for i in range(16):  # bound the loop on corrupted memory
            ptr = ql.mem.read_ptr(argv_addr + i * ptr_size)
            if ptr == 0:  # NULL terminates argv
                break
            args_list.append(ql.mem.string(ptr))

        args_joined = " ".join(args_list)
        log_exec.info(
            "PROCESS STARTED | emu_pid=%s host_pid=%s host_ppid=%s | "
            "Binary: %s | Args: %s",
            ql.os.pid, os.getpid(), os.getppid(), path, args_joined)

        if gdb_mgr is not None:
            gdb_mgr.check_exec_trigger(ql, path, args_joined)

    except Exception:
        _hook_failed('execve')


def auto_create_virtual_file(path):
    # Escludiamo le librerie per non interferire con la ricerca dei percorsi del dynamic linker
    if path.endswith('.so') or '.so.' in path:
        return

    # Intercettiamo i tentativi di accesso ai percorsi volatili tipici dei firmware
    volatile_dirs = ['/var/', '/tmp/', '/etc/', '/dev/', '/proc/', '/sys/']
    if any(path.startswith(d) for d in volatile_dirs):
        real_path = os.path.join(ROOTFS, path.lstrip('/'))
        if not os.path.exists(real_path):
            try:
                os.makedirs(os.path.dirname(real_path), exist_ok=True)
                # Crea un file vuoto sulla macchina host
                open(real_path, 'a').close()
                log_file.info("VIRTUAL FILE AUTO-CREATED | Path: %s", path)
            except Exception:
                pass


def hook_open_enter(ql, path_addr, flags, mode, *args):
    try:
        path = ql.mem.string(path_addr)
        auto_create_virtual_file(path)

        if flags & _o_creat(ql):
            log_file.info("FILE CREATED | Path: %s | Flags: %s",
                          path, hex(flags))
    except Exception:
        _hook_failed('file')


def hook_openat_enter(ql, dirfd, path_addr, flags, mode, *args):
    try:
        path = ql.mem.string(path_addr)
        if path.startswith('/'):  # absolute paths via openat
            auto_create_virtual_file(path)

        if flags & _o_creat(ql):
            log_file.info("FILE CREATED (openat) | Path: %s | Flags: %s",
                          path, hex(flags))
    except Exception:
        _hook_failed('file')


def _get_tid(ql):
    try:
        return ql.os.thread_management.cur_thread.id
    except AttributeError:
        return getattr(ql.os, 'pid', 0)


def hook_net_enter(ql, fd, buf, count, *args):
    # Track the buffer address by thread ID to safely access it on syscall exit
    tid = _get_tid(ql)
    active_buffers[tid] = (fd, buf)


def hook_net_exit(ql, *args):
    tid = _get_tid(ql)
    if tid not in active_buffers:
        return
    fd, buf_addr = active_buffers.pop(tid)
    ret = _signed(ql, args[-1])

    if ret <= 0 or fd <= 2:  # errors/EOF and stdin/stdout/stderr
        return
    try:
        data = ql.mem.read(buf_addr, ret)
        decoded_data = data.decode('utf-8', errors='ignore').strip()

        # Only log things that look like HTTP, to skip random file reads
        if any(k in decoded_data for k in ['GET ', 'POST ', 'HTTP/', 'SOAPACTION']):
            log_net.info("NETWORK REQUEST (HTTP) | fd: %s | %s bytes:\n%s",
                         fd, ret, decoded_data)
            if gdb_mgr is not None:
                gdb_mgr.check_http_trigger(ql, decoded_data)
    except Exception:
        _hook_failed('net')


def my_shutdown(ql, sockfd, how):
    sock = get_opened_socket(ql.os, sockfd)

    # Preserve Qiling's invalid-descriptor / non-socket result.
    if isinstance(sock, int):
        return sock

    try:
        sock.shutdown(how)
        return 0

    except OSError as exc:
        error_number = exc.errno or errno.EIO

        log_sock.warning("shutdown fd=%s how=%s errno=%s error=%s",
                         sockfd, how, error_number, exc)

        return -error_number


def high_fidelity_clone(ql, *args):
    tm = ql.os.thread_management
    was_none = False
    _orig_clone = sched.ql_syscall_clone

    # Se Qiling non ha inizializzato il main thread, creiamo un mock temporaneo
    if getattr(tm, 'cur_thread', None) is None:
        was_none = True

        class TempThread:
            # Restituisce il PID reale del processo come TID iniziale per la risoluzione pthreads
            id = getattr(ql.os, 'pid', 1000)
        tm.cur_thread = TempThread()

    try:
        # Esegue la logica nativa di Qiling per il multithreading (flag parsing, TLS mapping)
        return _orig_clone(ql, *args)
    finally:
        # Ripristina l'ambiente originale in modo che lo scheduler non inciampi nel mock
        # durante il context switching o l'uscita
        if was_none:
            tm.cur_thread = None


def _stat_enter(ql, path_addr, *args):
    try:
        _stat_paths[_get_tid(ql)] = ql.mem.string(path_addr)
    except Exception:
        _hook_failed('ipc')


def _stat_exit(ql, *args):
    path = _stat_paths.pop(_get_tid(ql), None)
    ret = _signed(ql, args[-1])
    if path is not None and ret < 0:
        log_ipc.debug("stat FAILED | path=%s ret=%s", path, ret)


_stat_paths = {}


def _msgget_exit(ql, key, msgflg, *args):
    ret = _signed(ql, args[-1])
    log_ipc.info("msgget | key=%#x flags=%#o ret=%s%s", key & 0xffffffff,
                 msgflg, ret,
                 "  <-- key is -1: preceding ftok()/stat() failed"
                 if (key & 0xffffffff) == 0xffffffff else "")


def _msgsnd_enter(ql, msqid, msgp, msgsz, msgflg, *args):
    log_ipc.info("msgsnd | msqid=%s size=%s flags=%#x", msqid, msgsz, msgflg)
    if gdb_mgr is not None and gdb_mgr.break_ipc:
        try:
            psz = ql.arch.pointersize
            mtype = ql.mem.read_ptr(msgp)
            payload = bytes(ql.mem.read(msgp + psz, max(0, msgsz)))
            gdb_mgr.check_ipc_trigger(ql, msqid, mtype, payload)
        except Exception:
            pass


def _msgrcv_enter(ql, msqid, msgp, msgsz, msgtyp, msgflg, *args):
    log_ipc.info("msgrcv | msqid=%s maxsize=%s type=%s flags=%#x",
                 msqid, msgsz, msgtyp, msgflg)


def hook_write_enter(ql, fd, buf, count, *args):
    if fd in (1, 2) and 0 < count <= 4096:
        try:
            text = bytes(ql.mem.read(buf, count)).decode(
                'utf-8', errors='replace')
            log_stdio.info("%s: %s", 'stdout' if fd == 1 else 'stderr',
                           text.rstrip('\n'))
        except Exception:
            _hook_failed('guest_stdio')


def my_sandbox(path, rootfs):
    for vdir in ['dev', 'proc', 'sys', 'tmp', 'var/run']:
        os.makedirs(os.path.join(rootfs, vdir), exist_ok=True)
    verbose = {'off': QL_VERBOSE.OFF, 'default': QL_VERBOSE.DEFAULT,
               'debug': QL_VERBOSE.DEBUG, 'disasm': QL_VERBOSE.DISASM}.get(
        os.environ.get('EMU_QL_VERBOSE', 'default').lower(), QL_VERBOSE.DEFAULT)

    ql = Qiling(
        path,
        rootfs,
        profile='./linux.ql',
        verbose=verbose
    )
    logs.attach_qiling(ql)  # Qiling's own records -> complete_log
    ql.add_fs_mapper(r'/dev/urandom', r'/dev/urandom')

    _orig_is_mapped = ql.mem.is_mapped

    def safe_is_mapped(addr, size, *args, **kwargs):
        if size <= 0:
            return True
        return _orig_is_mapped(addr, size, *args, **kwargs)
    ql.mem.is_mapped = safe_is_mapped

    if gdb_mgr is not None:
        gdb_mgr.install(ql)

    ql.os.set_syscall('execve', hook_execve, QL_INTERCEPT.ENTER)

    # 1. Track File Creations
    ql.os.set_syscall('open', hook_open_enter, QL_INTERCEPT.ENTER)
    ql.os.set_syscall('openat', hook_openat_enter, QL_INTERCEPT.ENTER)

    # 2. Track Request Contents
    ql.os.set_syscall('recv', hook_net_enter, QL_INTERCEPT.ENTER)
    ql.os.set_syscall('recv', hook_net_exit, QL_INTERCEPT.EXIT)
    ql.os.set_syscall('recvfrom', hook_net_enter, QL_INTERCEPT.ENTER)
    ql.os.set_syscall('recvfrom', hook_net_exit, QL_INTERCEPT.EXIT)
    ql.os.set_syscall('read', hook_net_enter, QL_INTERCEPT.ENTER)
    ql.os.set_syscall('read', hook_net_exit, QL_INTERCEPT.EXIT)
    ql.os.set_syscall("shutdown", my_shutdown)

    # 3. SysV IPC / guest output
    for name in ('stat', 'stat64', 'lstat', 'lstat64'):
        ql.os.set_syscall(name, _stat_enter, QL_INTERCEPT.ENTER)
        ql.os.set_syscall(name, _stat_exit, QL_INTERCEPT.EXIT)
    if ipc is not None:
        ipc.install(ql)
        # Still allow GDB IPC trigger on msgsnd entry alongside IpcShim
        ql.os.set_syscall('msgsnd', _msgsnd_enter, QL_INTERCEPT.ENTER)
    else:
        ql.os.set_syscall('msgget', _msgget_exit, QL_INTERCEPT.EXIT)
        ql.os.set_syscall('msgsnd', _msgsnd_enter, QL_INTERCEPT.ENTER)
        ql.os.set_syscall('msgrcv', _msgrcv_enter, QL_INTERCEPT.ENTER)
    ql.os.set_syscall('write', hook_write_enter, QL_INTERCEPT.ENTER)

    ql.os.set_syscall('clone', high_fidelity_clone)

    core_pattern_path = fr'{ROOTFS}/proc/sys/kernel/core_pattern'
    if os.path.exists(core_pattern_path):
        os.unlink(core_pattern_path)

    ql.run()


logs = None     # set in __main__; forked emulator processes inherit it
ipc = None      # IpcShim or None; set in __main__
gdb_mgr = None  # GdbManager or None; set in __main__

if __name__ == '__main__':
    logs = setup_logging()  # before any hook can fire, before Qiling()
    if os.environ.get('EMU_IPC', 'host').lower() != 'off':
        ipc = IpcShim(registry_dir=str(logs.complete_path.parent))
    if os.environ.get('EMU_GDB', 'on').lower() != 'off':
        gdb_mgr = GdbManager(
            rootfs=ROOTFS,
            log_dir=str(logs.complete_path.parent),
            nvram_store=NVRAM_STORE,
            ipc_shim=ipc
        )
    nvram_listener_thread = threading.Thread(
        target=nvram_listener, daemon=True)
    nvram_listener_thread.start()

    time.sleep(3)
    my_sandbox([fr'{ROOTFS}/bin/httpd'], ROOTFS)
