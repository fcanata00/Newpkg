#!/usr/bin/env python3
# newpkg_logger.py
"""
Revised newpkg_logger.py

Features:
 - get_logger(cfg=None, name="newpkg") returns a Logger object (single instance per name)
 - lazy initialization of handlers (file / console)
 - rotating file handler with optional gzip compression of old files
 - integration with newpkg_api (registers logger as api.logger)
 - perf_timer() context manager to measure operations and optionally record in DB (db.record_phase)
 - progress() context manager wrapper using rich when available, fallback simple
 - logger.event() convenience for structured events (sanitizes sensitive keys)
 - redaction of sensitive keys in metadata
 - supports text/color by default; JSON output if cfg says so or logger.json_mode True
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

# Optional imports
try:
    from newpkg_config import init_config, get_config  # type: ignore
except Exception:
    init_config = None
    get_config = None

try:
    from newpkg_api import get_api  # type: ignore
except Exception:
    get_api = None

try:
    from newpkg_db import get_db  # type: ignore
except Exception:
    get_db = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

# rich for nice console and progress
try:
    from rich.console import Console
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn
    from rich.traceback import install as rich_traceback_install
    RICH = True
    _console = Console()
    try:
        rich_traceback_install()
    except Exception:
        pass
except Exception:
    RICH = False
    _console = None

# defaults
DEFAULT_LOG_DIR = "/var/log/newpkg"
DEFAULT_LOG_FILE = "newpkg.log"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 5
DEFAULT_COMPRESS = True

# sensitive keys to redact
DEFAULT_SENSITIVE = {"password", "passwd", "secret", "token", "api_key", "apikey", "ssh_key", "private_key"}

# simple thread lock for singleton map
_logger_map: Dict[str, "NewpkgLogger"] = {}
_logger_map_lock = threading.RLock()


def _now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact(obj: Any, sensitive: set) -> Any:
    """
    Walk structure and redact keys that contain sensitive names.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = k.lower()
            if any(sk in kl for sk in sensitive):
                out[k] = "<REDACTED>"
            else:
                out[k] = _redact(v, sensitive)
        return out
    if isinstance(obj, list):
        return [_redact(x, sensitive) for x in obj]
    return obj


class _GzipRotatingFileHandler(RotatingFileHandler):
    """
    RotatingFileHandler that optionally compresses old logs with gzip.
    """

    def __init__(self, filename, mode="a", maxBytes=0, backupCount=0, compress: bool = True, encoding=None, delay=False):
        super().__init__(filename, mode=mode, maxBytes=maxBytes, backupCount=backupCount, encoding=encoding, delay=delay)
        self.compress = compress

    def doRollover(self):
        super().doRollover()
        if not self.compress:
            return
        # compress the oldest non-compressed backup files: filename.{n}
        try:
            base = self.baseFilename
            for i in range(self.backupCount, 0, -1):
                sname = f"{base}.{i}"
                if os.path.exists(sname) and not sname.endswith(".gz"):
                    try:
                        with open(sname, "rb") as f_in:
                            data = f_in.read()
                        with gzip.open(sname + ".gz", "wb") as f_out:
                            f_out.write(data)
                        os.remove(sname)
                    except Exception:
                        # ignore compression errors
                        continue
        except Exception:
            pass


class NewpkgLogger:
    """
    High-level logger wrapper exposing structured methods and integration hooks.
    """

    def __init__(self, cfg: Optional[Any] = None, name: str = "newpkg"):
        self.cfg = cfg or (get_config() if get_config else None)
        self.name = name
        self._pylogger: logging.Logger = logging.getLogger(f"newpkg.{name}")
        self._pylogger.setLevel(logging.INFO)
        self._handlers_initialized = False
        self._lock = threading.RLock()
        self.json_mode = False
        self.compress_backups = DEFAULT_COMPRESS
        self.log_dir = DEFAULT_LOG_DIR
        self.log_file = DEFAULT_LOG_FILE
        self.max_bytes = DEFAULT_MAX_BYTES
        self.backup_count = DEFAULT_BACKUP_COUNT
        self.sensitive = set(DEFAULT_SENSITIVE)
        self.db = get_db() if get_db else None
        self.hooks = get_hooks_manager(self.cfg) if get_hooks_manager else None
        self.api = get_api() if get_api else None
        # if API present, register this logger
        try:
            if self.api:
                self.api.logger = self
        except Exception:
            pass
        # load config-driven overrides lazily
        self._apply_cfg_defaults()

    def _apply_cfg_defaults(self):
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                # JSON mode
                if self.cfg.get("logging.json"):
                    self.json_mode = True
                # compression
                self.compress_backups = bool(self.cfg.get("logging.compress_backups", self.compress_backups))
                # log dir and file
                self.log_dir = str(self.cfg.get("logging.dir") or DEFAULT_LOG_DIR)
                self.log_file = str(self.cfg.get("logging.file") or DEFAULT_LOG_FILE)
                self.max_bytes = int(self.cfg.get("logging.max_bytes") or self.max_bytes)
                self.backup_count = int(self.cfg.get("logging.backup_count") or self.backup_count)
                # sensitive keys extension
                more = self.cfg.get("logging.sensitive_keys") or []
                if isinstance(more, (list, tuple)):
                    for k in more:
                        self.sensitive.add(k.lower())
        except Exception:
            pass

    def _ensure_handlers(self):
        with self._lock:
            if self._handlers_initialized:
                return
            # console handler
            ch = logging.StreamHandler()
            fmt_text = "[%(levelname)s] %(message)s"
            if RICH and _console and not self.json_mode:
                # let rich render via console; basic formatting in message
                formatter = logging.Formatter("%(message)s")
            elif self.json_mode:
                formatter = logging.Formatter("%(message)s")
            else:
                formatter = logging.Formatter(fmt_text)
            ch.setFormatter(formatter)
            ch.setLevel(logging.INFO)
            self._pylogger.addHandler(ch)

            # file handler (rotating)
            try:
                log_dir = Path(self.log_dir)
                log_dir.mkdir(parents=True, exist_ok=True)
                log_path = str(log_dir / self.log_file)
                fh = _GzipRotatingFileHandler(log_path, maxBytes=self.max_bytes, backupCount=self.backup_count, compress=self.compress_backups)
                fh.setLevel(logging.DEBUG)
                # JSON formatter for file when json_mode True
                if self.json_mode:
                    fh.setFormatter(logging.Formatter("%(message)s"))
                else:
                    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
                self._pylogger.addHandler(fh)
            except Exception:
                pass

            self._handlers_initialized = True

    # ---------------- basic log methods ----------------
    def _emit(self, level: str, key: str, message: str, meta: Optional[Dict[str, Any]] = None):
        self._ensure_handlers()
        meta = meta or {}
        # sanitize meta
        safe_meta = _redact(meta, self.sensitive)
        payload = {
            "ts": _now_iso(),
            "logger": self.name,
            "level": level,
            "key": key,
            "message": message,
            "meta": safe_meta,
        }
        # if json mode or writing to file prefer JSON string
        try:
            if self.json_mode:
                text = json.dumps(payload, ensure_ascii=False)
                self._pylogger.log(getattr(logging, level.upper(), logging.INFO), text)
            else:
                # human-friendly
                if RICH and _console:
                    # color mapping (basic)
                    if level.lower() == "error":
                        _console.print(f"[bold red]{message}[/bold red]  {safe_meta}")
                    elif level.lower() == "warning":
                        _console.print(f"[yellow]{message}[/yellow]  {safe_meta}")
                    else:
                        _console.print(f"[green]{message}[/green]  {safe_meta}")
                    # also write to python logger for file persistence
                    self._pylogger.log(getattr(logging, level.upper(), logging.INFO), f"{message} | {safe_meta}")
                else:
                    text = f"{message} | {safe_meta}"
                    self._pylogger.log(getattr(logging, level.upper(), logging.INFO), text)
        except Exception:
            # fallback
            try:
                self._pylogger.log(getattr(logging, level.upper(), logging.INFO), f"{message} | {safe_meta}")
            except Exception:
                pass
        # optionally log to DB as a phase/event
        try:
            if self.db:
                # store a lightweight record in phases table
                try:
                    self.db.record_phase(None, key, level, meta=safe_meta)
                except Exception:
                    pass
        except Exception:
            pass

    def info(self, key: str, message: str, meta: Optional[Dict[str, Any]] = None):
        self._emit("info", key, message, meta)

    def warning(self, key: str, message: str, meta: Optional[Dict[str, Any]] = None):
        self._emit("warning", key, message, meta)

    def error(self, key: str, message: str, meta: Optional[Dict[str, Any]] = None):
        self._emit("error", key, message, meta)

    def event(self, event_name: str, **meta):
        """
        Convenience method to log a structured event.
        """
        # sanitize meta
        safe_meta = _redact(meta, self.sensitive)
        self._emit("info", event_name, f"event:{event_name}", safe_meta)

    # ---------------- perf timer ----------------
    @contextmanager
    def perf_timer(self, name: str, meta: Optional[Dict[str, Any]] = None):
        """
        Context manager to measure block duration and record it.
        Usage:
            with logger.perf_timer("build.gcc"):
                ...
        On exit it logs an info event and calls DB.record_phase if available.
        """
        start = time.time()
        try:
            yield
            ok = True
        except Exception as e:
            ok = False
            raise
        finally:
            dur = time.time() - start
            info_meta = (meta or {}).copy()
            info_meta.update({"duration_s": round(dur, 3)})
            self.event(f"perf.{name}", **info_meta)
            # record in DB if available
            try:
                if self.db:
                    self.db.record_phase(None, f"perf.{name}", "ok" if ok else "fail", meta=info_meta)
            except Exception:
                pass

    # ---------------- progress context ----------------
    @contextmanager
    def progress(self, description: str, total: Optional[int] = None):
        """
        Return a progress context. If rich is available, returns rich.Progress; otherwise returns a dummy object with add_task/update.
        Example:
            with logger.progress("Downloading", total=100) as p:
                task = p.add_task("dl", total=100)
                p.update(task, advance=10)
        """
        if RICH and _console:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=_console,
            )
            try:
                progress.start()
                task = progress.add_task(description, total=total or 0)
                yield progress
                progress.stop()
            except Exception:
                try:
                    progress.stop()
                except Exception:
                    pass
                yield progress
        else:
            # dummy simple context
            class Dummy:
                def add_task(self, *args, **kwargs):
                    return 0
                def update(self, *args, **kwargs):
                    return None
            d = Dummy()
            yield d

    # ---------------- utility: set level and json mode at runtime ----------------
    def set_level(self, level: str):
        try:
            lv = getattr(logging, level.upper(), logging.INFO)
            self._pylogger.setLevel(lv)
        except Exception:
            pass

    def set_json(self, val: bool):
        self.json_mode = bool(val)
        # reinitialize handlers to pick new format next time
        self._handlers_initialized = False

    # ---------------- convenience factory ----------------
def get_logger(cfg: Optional[Any] = None, name: str = "newpkg") -> NewpkgLogger:
    """
    Return a named NewpkgLogger singleton per-process.
    """
    global _logger_map
    key = f"{name}"
    with _logger_map_lock:
        if key in _logger_map:
            return _logger_map[key]
        ln = NewpkgLogger(cfg=cfg, name=name)
        _logger_map[key] = ln
        return ln


# ---------------- simple test/CLI ----------------
if __name__ == "__main__":
    cfg = get_config() if get_config else None
    lg = get_logger(cfg)
    lg.info("startup", "logger initialized")
    with lg.progress("demo", total=100) as p:
        task = p.add_task("work", total=100)
        for i in range(10):
            time.sleep(0.05)
            p.update(task, advance=10)
    with lg.perf_timer("example.task"):
        time.sleep(0.2)
    lg.event("demo.finished", count=10)
