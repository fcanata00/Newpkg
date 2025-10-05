#!/usr/bin/env python3
# newpkg_logger.py
"""
Improved and finalized version of newpkg_logger.py

Fixes and improvements applied:
1. Lazy imports for newpkg_api, newpkg_db, newpkg_config to avoid circular imports
2. Prevent duplicate handlers (handlers cleared before re-adding)
3. Fallback log directory ~/.local/share/newpkg/logs if /var/log/newpkg fails
4. Safe progress() with always-stop (try/finally)
5. Safe fallback if 'rich' not installed
6. close() method to release handlers and flush logs
7. Full backward compatibility (perf_timer, log_event, get_logger)
"""

from __future__ import annotations

import os
import sys
import json
import gzip
import time
import atexit
import logging
import threading
from contextlib import contextmanager
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Safe rich import fallback
# ---------------------------------------------------------------------------
RICH = False
_console = None
try:
    from rich.console import Console
    from rich.progress import Progress
    _console = Console()
    RICH = True
except Exception:
    RICH = False
    _console = None

# ---------------------------------------------------------------------------
# Fallback logger for the module
# ---------------------------------------------------------------------------
_module_logger = logging.getLogger("newpkg.logger")
if not _module_logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.logger: %(message)s"))
    _module_logger.addHandler(h)
_module_logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Simple fallback logger
# ---------------------------------------------------------------------------
class SimpleLogger:
    def info(self, *args, **kwargs):
        try:
            _module_logger.info(" ".join(map(str, args)))
        except Exception:
            pass
    def warning(self, *args, **kwargs):
        try:
            _module_logger.warning(" ".join(map(str, args)))
        except Exception:
            pass
    def error(self, *args, **kwargs):
        try:
            _module_logger.error(" ".join(map(str, args)))
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Main Logger class
# ---------------------------------------------------------------------------
class NewpkgLogger:
    _instance_lock = threading.RLock()
    _logger_map: Dict[str, "NewpkgLogger"] = {}

    def __init__(self, name: str = "newpkg", cfg: Any = None, json_mode: bool = False):
        self.name = name
        self.cfg = cfg
        self.json_mode = json_mode
        self._pylogger = logging.getLogger(name)
        self._pylogger.setLevel(logging.INFO)
        self._handlers_initialized = False
        self._lock = threading.RLock()
        self._log_dir = self._resolve_log_dir()
        self._ensure_handlers()
        atexit.register(self.close)
        try:
            from newpkg_api import get_api  # type: ignore
            api = get_api()
            api.logger = self
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Directory resolution with fallback
    # -----------------------------------------------------------------------
    def _resolve_log_dir(self) -> Path:
        log_dir = Path("/var/log/newpkg")
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            home_fallback = Path.home() / ".local/share/newpkg/logs"
            home_fallback.mkdir(parents=True, exist_ok=True)
            log_dir = home_fallback
        return log_dir

    # -----------------------------------------------------------------------
    # Ensure handlers
    # -----------------------------------------------------------------------
    def _ensure_handlers(self):
        with self._lock:
            # Prevent duplicate handlers
            for h in list(self._pylogger.handlers):
                try:
                    h.close()
                except Exception:
                    pass
            self._pylogger.handlers.clear()
            try:
                file_path = self._log_dir / f"{self.name}.log"
                handler = RotatingFileHandler(file_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
                fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
                handler.setFormatter(fmt)
                self._pylogger.addHandler(handler)
                self._handlers_initialized = True
            except Exception as e:
                _module_logger.error(f"logger.file_init_fail: {e}", exc_info=True)
                self._handlers_initialized = False

    # -----------------------------------------------------------------------
    # Core emit method
    # -----------------------------------------------------------------------
    def _emit(self, level: str, msg: str, meta: Optional[Dict[str, Any]] = None):
        try:
            timestamp = datetime.utcnow().isoformat() + "Z"
            if self.json_mode:
                data = {"ts": timestamp, "level": level, "msg": msg, "meta": meta or {}}
                self._pylogger.log(getattr(logging, level.upper(), logging.INFO), json.dumps(data, ensure_ascii=False))
            else:
                formatted = f"[{level.upper()}] {msg}"
                self._pylogger.log(getattr(logging, level.upper(), logging.INFO), formatted)
            if _console:
                try:
                    _console.print(f"[{level.upper()}] {msg}")
                except Exception:
                    pass
        except Exception as e:
            _module_logger.error(f"logger.emit_fail: {e}", exc_info=True)

    # -----------------------------------------------------------------------
    # Public API methods
    # -----------------------------------------------------------------------
    def info(self, msg: str, meta: Optional[Dict[str, Any]] = None):
        self._emit("info", msg, meta)

    def warning(self, msg: str, meta: Optional[Dict[str, Any]] = None):
        self._emit("warning", msg, meta)

    def error(self, msg: str, meta: Optional[Dict[str, Any]] = None):
        self._emit("error", msg, meta)

    def event(self, name: str, data: Optional[Dict[str, Any]] = None):
        self._emit("info", f"event:{name}", data or {})

    # -----------------------------------------------------------------------
    # Timer and progress utilities
    # -----------------------------------------------------------------------
    @contextmanager
    def perf_timer(self, name: str, meta: Optional[Dict[str, Any]] = None):
        start = time.time()
        try:
            yield
        finally:
            elapsed = round(time.time() - start, 4)
            self._emit("info", f"{name} took {elapsed}s", meta)

    @contextmanager
    def progress(self, description: str = "Working...", total: int = 100):
        if not RICH:
            yield lambda step=1: None
            return
        progress = Progress()
        task = progress.add_task(description, total=total)
        progress.start()
        try:
            yield lambda step=1: progress.advance(task, step)
        finally:
            try:
                progress.stop()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Resource cleanup
    # -----------------------------------------------------------------------
    def close(self):
        with self._lock:
            for h in list(self._pylogger.handlers):
                try:
                    h.close()
                except Exception:
                    pass
            self._pylogger.handlers.clear()


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------
_default_logger: Optional[NewpkgLogger] = None
_logger_lock = threading.RLock()

def get_logger(cfg: Any = None, json_mode: bool = False) -> NewpkgLogger:
    global _default_logger
    with _logger_lock:
        if _default_logger is None:
            _default_logger = NewpkgLogger("newpkg", cfg, json_mode)
        return _default_logger

# Convenience wrappers
def log_event(name: str, data: Optional[Dict[str, Any]] = None):
    try:
        get_logger().event(name, data)
    except Exception:
        pass

@contextmanager
def perf_timer(name: str, meta: Optional[Dict[str, Any]] = None):
    logger = get_logger()
    with logger.perf_timer(name, meta):
        yield
