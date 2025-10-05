#!/usr/bin/env python3
"""
newpkg_logger.py

Structured logger for Newpkg with:
 - human-readable colored text output by default
 - optional JSON output if config requests it (logging.format = "json")
 - integration with newpkg_db (record_phase / record_hook)
 - context manager for hierarchical context
 - perf_timer decorator
 - from_config() helper to create logger from ConfigStore
 - as_handler() to return a logging.Handler
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional, Tuple

# optional color support
try:
    import colorama

    colorama.init()
    _HAS_COLOR = True
except Exception:
    _HAS_COLOR = False

# ANSI fallback colors (if colorama not present, terminals usually support ANSI)
ANSI = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
}


def _color(text: str, color: str) -> str:
    if not _HAS_COLOR:
        # still attempt ANSI; many terminals support it
        code = ANSI.get(color, "")
        reset = ANSI["reset"] if code else ""
        return f"{code}{text}{reset}"
    # colorama present: use same ANSI sequences (colorama handles them)
    code = ANSI.get(color, "")
    reset = ANSI["reset"]
    return f"{code}{text}{reset}"


class NewpkgLogger:
    """
    Lightweight logger wrapper.

    Usage:
        logger = NewpkgLogger.from_config(cfg, db)
        logger.info("starting build", pkg="gcc")
        with logger.context("build", pkg="gcc"):
            ...
        @logger.perf_timer("build")
        def build_pkg(...):
            ...
    """

    def __init__(
        self,
        name: str = "newpkg",
        cfg: Any = None,
        db: Any = None,
        log_dir: Optional[str] = None,
        log_file: Optional[str] = None,
        level: str = "INFO",
    ):
        self.name = name
        self.cfg = cfg
        self.db = db
        self._context: list[str] = []
        self._extra: Dict[str, Any] = {}
        self._perf_timers: Dict[str, float] = {}

        # resolve logging configuration from cfg if provided
        log_dir_conf = None
        log_file_conf = None
        level_conf = None
        fmt_conf = None
        try:
            if cfg:
                try:
                    # prefer get_path helper if available
                    if hasattr(cfg, "get_path"):
                        p = cfg.get_path("logging.log_dir")
                        if p:
                            log_dir_conf = str(p)
                    else:
                        log_dir_conf = cfg.get("logging.log_dir")
                except Exception:
                    log_dir_conf = None
                try:
                    log_file_conf = cfg.get("logging.log_file")
                except Exception:
                    log_file_conf = None
                try:
                    level_conf = cfg.get("logging.level")
                except Exception:
                    level_conf = None
                try:
                    fmt_conf = cfg.get("logging.format")
                except Exception:
                    fmt_conf = None
        except Exception:
            pass

        self.log_dir = log_dir or log_dir_conf or "./logs"
        self.log_file = log_file or log_file_conf or "newpkg.log"
        self.level = level_conf or level
        self.format = (fmt_conf or "text").lower()  # 'text' or 'json'

        # ensure dir exists
        try:
            os.makedirs(self.log_dir, exist_ok=True)
        except Exception:
            pass

        # underlying stdlib logger
        self._logger = logging.getLogger(self.name)
        self._logger.setLevel(getattr(logging, self.level.upper(), logging.INFO))
        # avoid duplicate handlers if multiple instantiations
        if not self._logger.handlers:
            fh = RotatingFileHandler(
                os.path.join(self.log_dir, self.log_file), maxBytes=10 * 1024 * 1024, backupCount=5
            )
            fh.setLevel(getattr(logging, self.level.upper(), logging.INFO))
            # file always JSON for easy parsing
            fh.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(fh)

        # console handler (human readable by default)
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(getattr(logging, self.level.upper(), logging.INFO))
        if self.format == "json":
            ch.setFormatter(logging.Formatter("%(message)s"))
        else:
            ch.setFormatter(logging.Formatter("%(message)s"))
        # attach only one console handler
        if not any(isinstance(h, logging.StreamHandler) for h in self._logger.handlers):
            self._logger.addHandler(ch)

        # simple startup log
        self.info("logger.started", message=f"Logger started (level={self.level}, dir={self.log_dir})")

    # ---------------- convenience constructors ----------------
    @classmethod
    def from_config(cls, cfg: Any = None, db: Any = None, name: str = "newpkg") -> "NewpkgLogger":
        log_dir = None
        log_file = None
        level = "INFO"
        try:
            if cfg:
                log_dir = cfg.get("logging.log_dir") if hasattr(cfg, "get") else None
                log_file = cfg.get("logging.log_file") if hasattr(cfg, "get") else None
                level = cfg.get("logging.level") or level
        except Exception:
            pass
        return cls(name=name, cfg=cfg, db=db, log_dir=log_dir, log_file=log_file, level=level)

    def as_handler(self) -> logging.Handler:
        """
        Return a stdlib logging.Handler that forwards records through this logger.
        Useful to attach to other modules.
        """
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(self._logger.level)
        handler.setFormatter(logging.Formatter("%(message)s"))
        return handler

    # ---------------- context management ----------------
    @contextmanager
    def context(self, ctx: str, **metadata):
        """
        Push a context string and optional metadata for the duration of a 'with' block.
        """
        self._context.append(ctx)
        saved_extra = dict(self._extra)
        try:
            # merge metadata
            self._extra.update(metadata)
            yield
        finally:
            # restore
            self._extra = saved_extra
            if self._context:
                self._context.pop()

    def context_str(self) -> str:
        return "/".join(self._context) if self._context else ""

    # ---------------- core logging helpers ----------------
    def _emit(self, level: str, event: str, message: Optional[str] = None, **meta):
        now = datetime.utcnow().isoformat() + "Z"
        full_meta = dict(self._extra)
        full_meta.update(meta or {})
        record = {
            "timestamp": now,
            "level": level,
            "event": event,
            "message": message or "",
            "context": self.context_str(),
            "meta": full_meta,
        }

        # write to file as JSON (file handler expects plain message)
        try:
            # send JSON to file handler via standard logger (the file handler records %(message)s)
            file_msg = json.dumps(record, ensure_ascii=False)
            for h in self._logger.handlers:
                if isinstance(h, RotatingFileHandler):
                    h.emit(logging.LogRecord(self.name, logging.INFO, "", 0, file_msg, None, None))
        except Exception:
            # fallback to raw logging
            try:
                self._logger.info(json.dumps(record))
            except Exception:
                pass

        # console: text or JSON
        if self.format == "json":
            console_msg = json.dumps(record, ensure_ascii=False)
            print(console_msg, file=sys.stderr)
        else:
            # human readable with colors
            lvl_color = "green" if level == "INFO" else "yellow" if level == "WARNING" else "red"
            ctx = f"[{self.context_str()}] " if self.context_str() else ""
            meta_str = " ".join(f"{k}={v}" for k, v in (full_meta or {}).items())
            human = f"{_color(now, 'cyan')} {_color(level, lvl_color)} {_color(event, 'blue')} {ctx}{message or ''}"
            if meta_str:
                human = f"{human} {_color(meta_str, 'magenta')}"
            print(human, file=sys.stderr)

        # DB integration: try to record phase/hook as appropriate (best-effort)
        try:
            if self.db:
                # if event starts with "hook:" treat as hook, else as phase
                if event.startswith("hook:"):
                    hook_name = event.split("hook:", 1)[1] or "unknown"
                    try:
                        if hasattr(self.db, "record_hook"):
                            self.db.record_hook(full_meta.get("pkg") or full_meta.get("package") or "unknown", hook_name, level)
                        else:
                            # fallback to add_log
                            self.db.add_log(full_meta.get("pkg") or full_meta.get("package") or "unknown", f"hook:{hook_name}", level)
                    except Exception:
                        pass
                else:
                    # treat as phase
                    try:
                        if hasattr(self.db, "record_phase"):
                            self.db.record_phase(full_meta.get("pkg") or full_meta.get("package") or "unknown", event, level, log_path=full_meta.get("log_path"))
                        else:
                            self.db.add_log(full_meta.get("pkg") or full_meta.get("package") or "unknown", event, level, full_meta.get("log_path"))
                    except Exception:
                        pass
        except Exception:
            # never let logging error break the program
            pass

    # Public convenience methods
    def info(self, event: str, message: Optional[str] = None, **meta):
        self._emit("INFO", event, message, **meta)

    def warning(self, event: str, message: Optional[str] = None, **meta):
        self._emit("WARNING", event, message, **meta)

    def error(self, event: str, message: Optional[str] = None, **meta):
        self._emit("ERROR", event, message, **meta)

    def debug(self, event: str, message: Optional[str] = None, **meta):
        # respect configured level
        if self._logger.level <= logging.DEBUG:
            self._emit("DEBUG", event, message, **meta)

    # ---------------- perf timer decorator ----------------
    def perf_timer(self, name: str = "perf"):
        """
        Decorator to measure execution time of a function and emit a log event with duration.
        """

        def deco(func):
            def wrapper(*args, **kwargs):
                start = time.time()
                try:
                    res = func(*args, **kwargs)
                    ok = True
                    return res
                except Exception as e:
                    ok = False
                    raise
                finally:
                    end = time.time()
                    dur = end - start
                    self._emit("INFO", f"{name}.elapsed", f"duration={dur:.3f}s", duration=dur, ok=ok, func=getattr(func, "__name__", str(func)))
            return wrapper

        return deco

    # ---------------- helper to set extra metadata (like current package) ----------------
    def set_extra(self, **kw):
        self._extra.update(kw)

    def clear_extra(self):
        self._extra = {}

    # ---------------- small convenience to create a stdlib logger wrapper ---------------
    def get_stdlib_logger(self) -> logging.Logger:
        return self._logger


# If this module is run directly, show a small demo
if __name__ == "__main__":
    # quick demo
    cfg = None
    try:
        from newpkg_config import init_config

        cfg = init_config()
    except Exception:
        cfg = None

    try:
        from newpkg_db import NewpkgDB

        db = NewpkgDB(cfg)
        db.init_db()
    except Exception:
        db = None

    logger = NewpkgLogger.from_config(cfg, db)
    logger.info("demo.start", "Starting demo", pkg="demo")
    with logger.context("demo", pkg="demo"):
        logger.info("demo.step", "Doing step 1")
        @logger.perf_timer("demo.work")
        def work(n):
            s = 0
            for i in range(n):
                s += i
            return s
        work(100000)
        logger.info("demo.end", "Demo finished")
