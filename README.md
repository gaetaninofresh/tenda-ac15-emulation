# Tenda AC15 httpd Emulation (Qiling)

Emulation environment for the `httpd` daemon of the Tenda AC15 AC1900 router
firmware (v15.03.05.19), built on top of [Qiling](https://qiling.io/), with
the goal of enabling live vulnerability analysis via GDB. 
## Project layout

- **`gdb_emu.py`** — entry point. Sets up the Qiling sandbox,
  the NVRAM socket listener (`nvram_listener`), the POSIX syscall hooks, and
  wires everything to `GdbManager`.
- **`gdb_debugging_ext.py`** — `GdbManager`: event-triggered GDB debugging,
  memory-fault trapping, basic-block tracing, automatic generation of
  `attach_<pid>.gdb` scripts (with `.text` offset resolution for shared
  libraries), and custom `monitor` commands over `qRcmd` packets.
- **`ipc_shim.py`** — replaces Qiling's internal System V message queues with
  real host-kernel queues via `ctypes`, so IPC actually works across forked
  processes.
- **`emu_logging.py`** — dual logging infrastructure (`complete_log` /
  `small_log`) with real host-PID tracking across `fork()`.

## What this solves

Running the stock firmware under Qiling out of the box rised a range of issues. This project patches around them:

- **`AssertionError` on `write(fd, buf, 0)`** — Qiling's `is_mapped()`
  asserts `size > 0`. Patched with a `safe_is_mapped` wrapper that
  short-circuits zero-length buffers.
- **`AttributeError` on `clone` / network hooks** — `thread_management.cur_thread`
  can be `None` on ARM/single-threaded startup. `high_fidelity_clone` installs
  a temporary mock thread around the real `ql_syscall_clone` call instead of
  forcing a `vfork` redirect (which broke native multithreading).
- **`OSError: [Errno 107] ENOTCONN` on `shutdown()`** — replaced with
  `my_shutdown`, which catches the error and returns the proper negative
  errno to the guest instead of crashing the emulator.
- **IPC hangs (`PostMsg msg create error`)** — `ftok()`/`msgget()` fail
  because no real daemon ever creates the message queues, and Qiling's
  built-in queues live in a per-process Python dict that doesn't survive
  `fork()`. `ipc_shim.py` backs `msgget`/`msgsnd`/`msgrcv` with real host
  SysV queues (shared across forked processes), auto-creates missing queues,
  drops the oldest message instead of blocking senders forever, and polls
  non-blockingly on receive.
- **Missing volatile files/dirs (`/var`, `/tmp`, `/etc`, `/dev`, `/proc`,
  `/sys`)** — Auto-created on `open`/`openat` and at sandbox
  startup; `core_pattern` is removed to avoid interference.
- **Per-process log correlation** — `ql.os.pid` is a static emulated value
  shared by every forked child, so logs instead stamp the real host PID via
  a custom `_PidFormatter`, and guest `stdout`/`stderr` are captured through
  a `write` hook instead of leaking straight to the host terminal.
- **Qiling's native GDB server is effectively unusable for this target** — no
  shared-library symbol support, slow boot-under-GDB, and port collisions on
  `fork()`. `GdbManager` runs the emulator at full speed and only spins up a
  fork-aware `QlGdb` session on demand, triggered by HTTP request content,
  `execve` arguments, IPC payloads, or on crash/entry-point.

See the accompanying project report (`Progetto_SSR2.pdf`) for the full
technical writeup (in italian).

## Usage

1. Unpack the AC15 firmware rootfs (`US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip`
   from Tenda's site) into e.g. `firmware/tendaac15/rootfs`.
2. Inside `squashfs-root`, replace `webroot` with `webroot_ro`
   (`rm -rf webroot && mv webroot_ro webroot`) as the router does on startup.
3. In `qiling/profiles/linux.ql`, set `ifrname_override` to your host's
   network interface (e.g. `eth0`, `lo`).
4. Run:

```bash
PYTHONPATH=/path/to/qiling ROOTFS=/path/to/tenda_rootfs \
    python3 gdb_emu.py
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ROOTFS` | `./firmware/tendaac15/rootfs` | Path to the extracted firmware rootfs |
| `EMU_LOG_DIR` | `logs` | Output directory for logs and GDB scripts |
| `EMU_QL_VERBOSE` | `default` | Qiling verbosity: `off`/`default`/`debug`/`disasm` |
| `EMU_IPC` | `host` | Set `off` to disable `ipc_shim.py` and fall back to passive logging |
| `EMU_GDB` | `on` | Set `off` to disable the GDB subsystem entirely |
| `EMU_GDB_PORT` | `9999` | Base GDB port (forked children get a deterministic offset port) |
| `EMU_GDB_AT_ENTRY` | `0` | Set `1` to pause at the ELF entry point |
| `EMU_GDB_ON_URI` | — | Pause when a matching substring appears in an HTTP request |
| `EMU_GDB_ON_EXEC` | — | Pause when `execve` path/args contain this substring |
| `EMU_GDB_ON_IPC` | — | Pause when an IPC `msgsnd` payload/mtype matches |
| `EMU_GDB_ON_CRASH` | `1` | Spawn a GDB session on invalid/protected memory access |
| `EMU_GDB_TRACE` | `1` | Enable the basic-block ring-buffer trace |
| `EMU_GDB_TRACE_DEPTH` | `128` | Size of the trace ring buffer |

Once a GDB session is triggered, attach with:

```bash
gdb-multiarch -q -x logs/attach_<pid>.gdb
```

Custom `monitor` commands are available inside GDB (`monitor help`,
`monitor vmmap`, `monitor trace [N]`, `monitor where <addr>`, `monitor ipc`,
`monitor nvram list|set`, `monitor snapshot save|restore|list`).

## Known limitations

- **No receiving daemons / incomplete IPC semantics** — `httpd`/`cfm` can
  successfully post IPC messages, but since backend daemons like `netctrl`
  and `time_check` aren't emulated, nothing consumes or acts on them.
- **No real multithreading** — Qiling schedules guest threads round-robin
  rather than executing them concurrently, which rules out conclusive
  analysis of race-condition-based vulnerabilities. This is a structural
  limitation of Qiling itself.
