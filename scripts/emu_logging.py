#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

HOOK_LOGGER_NAME = "emu.hook"

_FILE_FMT = ("%(asctime)s.%(msecs)03d pid=%(hostpid)d "
             "[%(name)s] %(levelname)-7s %(message)s")
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


class _PidFormatter(logging.Formatter):
    """Stamps the *host* pid on every record.
    """

    def format(self, record: logging.LogRecord) -> str:
        record.hostpid = os.getpid()
        return super().format(record)


def hook_logger(name: str) -> logging.Logger:
    """Return the logger for one hook, e.g. hook_logger('execve').
    """
    return logging.getLogger(f"{HOOK_LOGGER_NAME}.{name}")


# Avoid "no handlers could be found" noise if hooks log before setup.
logging.getLogger(HOOK_LOGGER_NAME).addHandler(logging.NullHandler())


@dataclass
class EmuLogs:
    complete_path: Path
    small_path: Path
    _complete_handler: logging.Handler
    _small_handler: logging.Handler
    _attached: List[str] = field(default_factory=list)

    def attach_qiling(self, ql) -> None:
        """Send everything `ql` logs to complete_log. Call right after Qiling()."""
        lg = ql.log
        if lg.name in self._attached:
            return
        lg.addHandler(self._complete_handler)
        self._attached.append(lg.name)

    def close(self) -> None:
        for h in (self._complete_handler, self._small_handler):
            try:
                h.flush()
                h.close()
            except Exception:
                pass


def setup_logging(log_dir: Optional[str] = None,
                  console: bool = True,
                  small_level: int = logging.INFO,
                  complete_level: int = logging.DEBUG) -> EmuLogs:
    out = Path(log_dir or os.environ.get("EMU_LOG_DIR", "logs"))
    out.mkdir(parents=True, exist_ok=True)

    stamp = time.strftime("%Y%m%d_%H%M%S")
    complete_path = out / f"complete_log_{stamp}.log"
    small_path = out / f"small_log_{stamp}.log"

    fmt = _PidFormatter(_FILE_FMT, _DATE_FMT)

    complete_h = logging.FileHandler(complete_path, mode="w", encoding="utf-8",
                                     errors="backslashreplace")
    complete_h.setLevel(complete_level)
    complete_h.setFormatter(fmt)

    small_h = logging.FileHandler(small_path, mode="w", encoding="utf-8",
                                  errors="backslashreplace")
    small_h.setLevel(small_level)
    small_h.setFormatter(fmt)

    hooks = logging.getLogger(HOOK_LOGGER_NAME)
    hooks.setLevel(logging.DEBUG)
    hooks.propagate = False
    for h in list(hooks.handlers):
        hooks.removeHandler(h)
    hooks.addHandler(complete_h)
    hooks.addHandler(small_h)

    if console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("%(message)s"))
        hooks.addHandler(ch)

    print(f"[logging] complete_log -> {complete_path}\n"
          f"[logging] small_log    -> {small_path}")
    return EmuLogs(complete_path, small_path, complete_h, small_h)
