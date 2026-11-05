from __future__ import annotations

import os
import struct
from collections import deque
from pathlib import Path
from typing import Callable, Deque, Dict, Optional, Tuple
from elftools.elf.elffile import ELFFile
from emu_logging import hook_logger

_log = hook_logger('gdb')


def _get_elf_text_offset(elf_path: str) -> int:
    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if sec.name == '.text':
                    return int(sec['sh_addr'])
    except Exception:
        _log.debug('failed to read .text offset from %s',
                   elf_path, exc_info=True)
    return 0


class GdbManager:
    def __init__(self,
                 rootfs: str,
                 log_dir: str = 'logs',
                 nvram_store: Optional[Dict[str, bytes]] = None,
                 ipc_shim=None):
        self.rootfs = rootfs
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.nvram_store = nvram_store if nvram_store is not None else {}
        self.ipc_shim = ipc_shim

        self.base_port = int(os.environ.get('EMU_GDB_PORT', '9999'))
        self.break_uri = os.environ.get('EMU_GDB_ON_URI', '')
        self.break_exec = os.environ.get('EMU_GDB_ON_EXEC', '')
        self.break_ipc = os.environ.get('EMU_GDB_ON_IPC', '')
        self.trap_crash = os.environ.get(
            'EMU_GDB_ON_CRASH', '1').lower() not in ('0', 'off', 'false')
        self.enable_trace = os.environ.get(
            'EMU_GDB_TRACE', '1').lower() not in ('0', 'off', 'false')
        self.trace_depth = int(os.environ.get('EMU_GDB_TRACE_DEPTH', '128'))

        # Ring buffer of (block_addr, lr_val, sp_val)
        self.trace_ring: Deque[Tuple[int, int, int]
                               ] = deque(maxlen=self.trace_depth)
        self.snapshots: Dict[str, object] = {}
        self._initial_pid = os.getpid()
        self._active_sessions = set()

    def install(self, ql) -> None:
        if self.enable_trace:
            ql.hook_block(self._hook_block)

        if self.trap_crash:
            ql.hook_mem_invalid(self._hook_mem_invalid)

        # Allow immediate startup breakpoint if EMU_GDB_AT_ENTRY=1
        if os.environ.get('EMU_GDB_AT_ENTRY', '0') == '1':
            ql.hook_address(
                lambda q: self.spawn(
                    q, 'Entry point reached (EMU_GDB_AT_ENTRY=1)'),
                ql.loader.elf_entry
            )

    def _get_port(self) -> int:
        """Return base_port for the main process, or a deterministic offset port for forked children."""
        pid = os.getpid()
        if pid == self._initial_pid:
            return self.base_port
        return 10000 + (pid % 5000)

    def _hook_block(self, ql, address: int, size: int) -> None:
        try:
            lr = getattr(ql.arch.regs, 'lr', 0)
            sp = getattr(ql.arch.regs, 'arch_sp', 0)
            self.trace_ring.append((address, lr, sp))
        except Exception:
            pass

    def _hook_mem_invalid(self, ql, access: int, address: int, size: int, value: int) -> bool:
        access_names = {
            16: 'UC_MEM_READ_UNMAPPED',
            17: 'UC_MEM_WRITE_UNMAPPED',
            18: 'UC_MEM_FETCH_UNMAPPED',
            19: 'UC_MEM_WRITE_PROT',
            20: 'UC_MEM_READ_PROT',
            21: 'UC_MEM_FETCH_PROT',
        }
        acc_str = access_names.get(access, f'ACCESS_{access}')
        reason = f'JIT Crash Trap: {acc_str} at {
            address:#x} (size={size}, val={value:#x})'
        _log.error(reason)
        self.dump_trace(ql)
        self.spawn(ql, reason)
        return False

    def check_http_trigger(self, ql, http_text: str) -> None:
        if self.break_uri and self.break_uri in http_text:
            first_line = http_text.splitlines()[0] if http_text else ''
            self.spawn(ql, f'HTTP match "{self.break_uri}" ({first_line})')

    def check_exec_trigger(self, ql, path: str, args_str: str) -> None:
        if self.break_exec and (self.break_exec in path or self.break_exec in args_str):
            self.spawn(ql, f'execve match "{
                       self.break_exec}" -> {path} {args_str}')

    def check_ipc_trigger(self, ql, msqid: int, mtype: int, payload: bytes) -> None:
        if not self.break_ipc:
            return
        if self.break_ipc.encode('utf-8', 'ignore') in payload or self.break_ipc == str(mtype):
            self.spawn(ql, f'IPC msgsnd match "{
                       self.break_ipc}" (msqid={msqid}, mtype={mtype})')

    def _resolve_image_symbol(self, ql, addr: int) -> str:
        for img in getattr(ql.loader, 'images', []):
            if img.base <= addr < img.end:
                name = os.path.basename(img.path)
                return f'{name}+{addr - img.base:#x}'
        return 'unmapped'

    def dump_trace(self, ql) -> str:
        """Format and log the recent basic-block execution ring buffer."""
        if not self.trace_ring:
            return 'Flight recorder is empty (set EMU_GDB_TRACE=1).'
        lines = [f'=== Flight Recorder (last {len(self.trace_ring)} basic blocks, pid={
            os.getpid()}) ===']
        for idx, (pc, lr, sp) in enumerate(self.trace_ring):
            pc_sym = self._resolve_image_symbol(ql, pc)
            lr_sym = self._resolve_image_symbol(ql, lr)
            lines.append(
                f'  [{idx - len(self.trace_ring)
                                :4d}] PC={pc:#010x} ({pc_sym:<24}) | '
                f'LR={lr:#010x} ({lr_sym:<24}) | SP={sp:#010x}'
            )
        out = '\n'.join(lines)
        _log.info('\n%s', out)
        return out

    def generate_gdb_script(self, ql, port: int) -> Path:
        pid = os.getpid()
        script_path = self.log_dir / f'attach_{pid}.gdb'
        main_bin = ql.path

        lines = [
            f'# Auto-generated by emu_gdb.py for host PID {pid}',
            'set pagination off',
            'set confirm off',
            'set architecture arm',
            'set remotetimeout 100',
            f'set solib-absolute-prefix {self.rootfs}',
            f'file {main_bin}',
        ]

        seen = set()
        for img in getattr(ql.loader, 'images', []):
            if img.path in seen or not os.path.exists(img.path):
                continue
            seen.add(img.path)
            if os.path.abspath(img.path) == os.path.abspath(main_bin):
                continue
            if '.so' in os.path.basename(img.path):
                text_off = _get_elf_text_offset(img.path)
                text_addr = img.base + text_off
                lines.append(f'add-symbol-file "{img.path}" {text_addr:#x}')

        lines.extend([
            f'target remote 127.0.0.1:{port}',
            'echo \\n[emu_gdb] Connected! Custom commands: monitor help\\n',
            'info registers',
            'x/5i $pc',
        ])

        script_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return script_path

    def _handle_monitor(self, ql, cmd_raw: str) -> str:
        parts = cmd_raw.strip().split()
        if not parts:
            return self._monitor_help()

        sub = parts[0].lower()
        if sub == 'help':
            return self._monitor_help()

        if sub == 'vmmap':
            info = ql.mem.get_formatted_mapinfo()
            return '\n'.join(info) + '\n'

        if sub == 'trace':
            count = int(parts[1]) if len(
                parts) > 1 and parts[1].isdigit() else 32
            items = list(self.trace_ring)[-count:]
            if not items:
                return 'No trace entries recorded.\n'
            lines = [f'Last {len(items)} basic blocks:']
            for idx, (pc, lr, sp) in enumerate(items):
                lines.append(
                    f'  [{
                        idx - len(items):3d}] PC={pc:#010x} ({self._resolve_image_symbol(ql, pc)}) '
                    f'LR={lr:#010x} ({self._resolve_image_symbol(ql, lr)}) SP={
                        sp:#010x}'
                )
            return '\n'.join(lines) + '\n'

        if sub == 'where':
            if len(parts) < 2:
                return 'Usage: monitor where <hex_addr>\n'
            try:
                addr = int(parts[1], 0)
            except ValueError:
                return f'Invalid address: {parts[1]}\n'
            return f'{addr:#x} -> {self._resolve_image_symbol(ql, addr)}\n'

        if sub == 'ipc':
            if self.ipc_shim is None or not self.ipc_shim._registry.exists():
                return 'No host IPC registry active.\n'
            content = self.ipc_shim._registry.read_text().strip()
            return f'Active Host IPC Queues (msqid key creator_pid):\n{content or "(empty)"}\n'

        if sub == 'nvram':
            if len(parts) == 1 or parts[1] == 'list':
                if not self.nvram_store:
                    return 'NVRAM store is empty.\n'
                return '\n'.join(f'  {k} = {v!r}' for k, v in self.nvram_store.items()) + '\n'
            if parts[1] == 'set' and len(parts) >= 4:
                key = parts[2]
                val = ' '.join(parts[3:]).encode('utf-8')
                self.nvram_store[key] = val
                return f'Set NVRAM[{key!r}] = {val!r}\n'
            return 'Usage: monitor nvram list | monitor nvram set <key> <val>\n'

        if sub == 'snapshot':
            if len(parts) < 2 or parts[1] not in ('save', 'restore', 'list'):
                return 'Usage: monitor snapshot save [name] | restore [name] | list\n'
            action = parts[1]
            name = parts[2] if len(parts) > 2 else 'default'
            if action == 'list':
                return 'Saved snapshots: ' + (', '.join(self.snapshots.keys()) or '(none)') + '\n'
            if action == 'save':
                try:
                    self.snapshots[name] = ql.save(
                        reg=True, mem=True, cpu_context=True)
                    return f'Snapshot "{name}" saved in memory.\n'
                except Exception as exc:
                    return f'Snapshot save failed: {exc}\n'
            if action == 'restore':
                if name not in self.snapshots:
                    return f'Snapshot "{name}" not found.\n'
                try:
                    ql.restore(self.snapshots[name])
                    return f'Snapshot "{name}" restored! Run `flushregs` in GDB to refresh registers.\n'
                except Exception as exc:
                    return f'Snapshot restore failed: {exc}\n'

        return f'Unknown monitor command: {sub!r}. Try `monitor help`.\n'

    @staticmethod
    def _monitor_help() -> str:
        return (
            'Available emu_gdb monitor commands:\n'
            '  monitor help                       Show this help message\n'
            '  monitor vmmap                      Display Qiling memory mappings & permissions\n'
            '  monitor trace [N]                  Show last N executed basic blocks & $lr (default 32)\n'
            '  monitor where <addr>               Resolve an address to <image>+<offset>\n'
            '  monitor ipc                        List active SysV IPC queues created by IpcShim\n'
            '  monitor nvram list                 Show all dynamic NVRAM key/value overrides\n'
            '  monitor nvram set <key> <val>      Override an NVRAM key in cfm_socket listener\n'
            '  monitor snapshot save|restore [id] Save or restore CPU + RAM state in memory\n'
        )

    def spawn(self, ql, reason: str, port: Optional[int] = None) -> None:
        """Pause emulation and open a QlGdb remote stub at the current PC."""
        from qiling.debugger.gdb.gdb import QlGdb

        bind_port = port or self._get_port()
        if bind_port in self._active_sessions:
            return
        self._active_sessions.add(bind_port)

        pc = ql.arch.regs.arch_pc
        pc_sym = self._resolve_image_symbol(ql, pc)
        script_path = self.generate_gdb_script(ql, bind_port)

        banner = (
            f'\n{"=" * 76}\n'
            f'[GDB] PAUSED EMULATION | Host PID: {
                os.getpid()} | Port: {bind_port}\n'
            f'[GDB] Reason : {reason}\n'
            f'[GDB] PC     : {pc:#x} ({pc_sym})\n'
            f'[GDB] Attach : gdb-multiarch -q -x {script_path}\n'
            f'{"=" * 76}'
        )
        _log.info(banner)

        gdb = QlGdb(ql, ip='127.0.0.1', port=bind_port)

        # Hook GDB `monitor` (qRcmd) packets so custom commands work inside gdb-multiarch
        orig_rcmd: Optional[Callable] = getattr(gdb, 'handle_qRcmd', None)

        def _custom_qRcmd(payload: str):
            try:
                cmd_str = bytes.fromhex(payload).decode(
                    'utf-8', errors='replace')
                reply_text = self._handle_monitor(ql, cmd_str)
                gdb.send(reply_text.encode('utf-8').hex().encode('ascii'))
            except Exception as exc:
                err = f'Monitor error: {exc}\n'
                gdb.send(err.encode('utf-8').hex().encode('ascii'))
                if orig_rcmd is not None:
                    return orig_rcmd(payload)

        gdb.handle_qRcmd = _custom_qRcmd
        try:
            gdb.run()
        finally:
            self._active_sessions.discard(bind_port)
