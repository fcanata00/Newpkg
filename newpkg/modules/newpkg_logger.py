#!/usr/bin/env python3
# newpkg_logger.py
"""
newpkg_logger.py — unified structured logger for newpkg

Features (revised):
 - Reads settings from config: output.json, output.color, output.quiet, logging.debug
 - Structured JSON and color console output
 - Safe file logging via RotatingFileHandler (5 MB, 3 backups)
 - Integrates with newpkg_db (records phases, hooks, perf_timer metrics)
 - Provides decorator @perf_timer for timing critical functions
 - Thread-safe, context-aware, human-readable or JSON modes
 - Automatic suppression of console output when quiet=True
"""

from __future__ import annotations

import functools
import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Dict, Optional

# color support
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    _HAS_COLOR = True
except Exception:
    _HAS_COLOR = False

# project integration
try:
    from newpkg_config import init_config
except Exception:
    init_config = None

try:
    from newpkg_db import NewpkgDB
except Exception:
    NewpkgDB = None


# ----------------- utility helpers -----------------
def _shorten(s: str, width: int = 120) -> str:
    """Truncate long text safely for console readability."""
    if len(s) <= width:
        return s
    return s[:width - 3] + "..."


def _color_for_level(level: str) -> str:
    """Return color code for given log level."""
    if not _HAS_COLOR:
        return ""
    return {
        "DEBUG": Fore.CYAN,
        "INFO": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.MAGENTA,
    }.get(level.upper(), "")


def _reset_color() -> str:
    return Style.RESET_ALL if _HAS_COLOR else ""


# ----------------- main logger -----------------
class NewpkgLogger:
    def __init__(self, cfg: Any = None, db: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)

        # config-based settings
        self.json_mode = bool(self._cfg_get("output.json", False))
        self.color_mode = bool(self._cfg_get("output.color", True))
        self.quiet_mode = bool(self._cfg_get("output.quiet", False))
        self.debug_mode = bool(self._cfg_get("logging.debug", False))
        self.log_path = self._cfg_get("logging.file", "/var/log/newpkg.log")

        self.logger = logging.getLogger("newpkg")
        self.logger.setLevel(logging.DEBUG if self.debug_mode else logging.INFO)

        # setup handlers
        self.logger.handlers.clear()
        self._setup_handlers()

        # runtime context for structured logs
        self._context: Dict[str, Any] = {}
        self._extra: Dict[str, Any] = {}

    # ------------- configuration helpers -------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return os.environ.get(key.upper().replace(".", "_"), default)

    def _setup_handlers(self):
        """Configure console + rotating file handlers based on config."""
        # file handler
        try:
            log_dir = os.path.dirname(self.log_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            fh = RotatingFileHandler(self.log_path, maxBytes=5 * 1024 * 1024, backupCount=3, delay=True)
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            self.logger.addHandler(fh)
        except Exception:
            pass

        # console handler (disabled if quiet)
        if not self.quiet_mode:
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(ch)

    # ------------- structured logging core -------------
    def _emit(self, level: str, event: str, msg: str = "", **meta):
        timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        record = {
            "logger": "newpkg",
            "time": timestamp,
            "level": level.upper(),
            "event": event,
            "message": msg,
            **self._context,
            **self._extra,
            "meta": meta,
        }

        if self.json_mode:
            self.logger.log(getattr(logging, level.upper(), logging.INFO), json.dumps(record))
        else:
            color_prefix = _color_for_level(level) if self.color_mode else ""
            reset = _reset_color() if self.color_mode else ""
            context_str = self.context_str()
            msg_line = f"{color_prefix}[{level}] {event}{reset}: {_shorten(msg)}"
            if context_str:
                msg_line += f" {context_str}"
            self.logger.log(getattr(logging, level.upper(), logging.INFO), msg_line)

        # also record DB phase when applicable
        if self.db and hasattr(self.db, "record_phase"):
            try:
                self.db.record_phase(
                    package=meta.get("package") or self._context.get("package", "global"),
                    phase=event,
                    status=level.lower(),
                    meta=meta or {},
                )
            except Exception:
                pass

    # ------------- public logging API -------------
    def debug(self, event: str, msg: str = "", **meta): self._emit("DEBUG", event, msg, **meta)
    def info(self, event: str, msg: str = "", **meta): self._emit("INFO", event, msg, **meta)
    def warning(self, event: str, msg: str = "", **meta): self._emit("WARNING", event, msg, **meta)
    def error(self, event: str, msg: str = "", **meta): self._emit("ERROR", event, msg, **meta)
    def critical(self, event: str, msg: str = "", **meta): self._emit("CRITICAL", event, msg, **meta)

    # ------------- context management -------------
    def set_context(self, **ctx):
        """Set persistent context for all subsequent logs."""
        self._context.update(ctx)

    def clear_context(self):
        self._context.clear()

    def context_str(self) -> str:
        if not self._context:
            return ""
        return "[" + " ".join(f"{k}={v}" for k, v in self._context.items()) + "]"

    # ------------- decorators -------------
    def perf_timer(self, event: Optional[str] = None) -> Callable:
        """
        Decorator to measure performance of a function.
        Logs duration in seconds; records in DB if available.
        """
        def wrapper(fn: Callable):
            @functools.wraps(fn)
            def inner(*args, **kwargs):
                name = event or fn.__name__
                start = time.perf_counter()
                self.info(f"{name}.start", f"Starting {fn.__name__}")
                try:
                    result = fn(*args, **kwargs)
                    duration = time.perf_counter() - start
                    self.info(f"{name}.done", f"{fn.__name__} completed in {duration:.3f}s", duration=duration)
                    # register in DB as perf metric
                    if self.db and hasattr(self.db, "record_phase"):
                        try:
                            self.db.record_phase(
                                package=self._context.get("package", "global"),
                                phase=f"perf:{fn.__name__}",
                                status="ok",
                                meta={"duration": duration},
                            )
                        except Exception:
                            pass
                    return result
                except Exception as e:
                    duration = time.perf_counter() - start
                    tb = traceback.format_exc(limit=5)
                    self.error(f"{name}.fail", f"{fn.__name__} failed after {duration:.3f}s: {e}", traceback=tb)
                    if self.db and hasattr(self.db, "record_phase"):
                        try:
                            self.db.record_phase(
                                package=self._context.get("package", "global"),
                                phase=f"perf:{fn.__name__}",
                                status="error",
                                meta={"error": str(e), "trace": tb},
                            )
                        except Exception:
                            pass
                    raise
            return inner
        return wrapper

    # ------------- hook / phase recorders -------------
    def record_hook(self, name: str, phase: str, status: str = "ok", **meta):
        """Record hook execution status into DB."""
        self.info(f"hook.{name}", f"Hook {name} ({phase}) status={status}")
        if self.db and hasattr(self.db, "record_phase"):
            try:
                self.db.record_phase(package="global", phase=f"hook:{name}", status=status, meta=meta)
            except Exception:
                pass

    # ------------- class constructors -------------
    @classmethod
    def from_config(cls, cfg: Any = None, db: Any = None) -> "NewpkgLogger":
        return cls(cfg=cfg or (init_config() if init_config else None), db=db)

    @classmethod
    def as_handler(cls, cfg: Any = None, db: Any = None) -> logging.Logger:
        """Return configured python logger instance."""
        inst = cls.from_config(cfg, db)
        return inst.logger


# ----------------- example main -----------------
if __name__ == "__main__":
    cfg = init_config() if init_config else None
    log = NewpkgLogger(cfg)
    log.set_context(package="demo", phase="init")

    log.info("startup", "Logger initialized and ready.")
    @log.perf_timer("test")
    def demo_task():
        time.sleep(0.3)
        return "ok"

    demo_task()
    log.record_hook("configure", "pre", status="ok")
    log.error("demo.fail", "Simulated error for test.")
