#!/usr/bin/env python3
# newpkg_logger.py
"""
NewpkgLogger — enhanced logger for newpkg ecosystem

Features:
 - Colorized terminal output (rich if available) with theme support (dark/light/plain)
 - JSON structured output option
 - Respects config: quiet, json, use_rich, logging.max_bytes, logging.backups, logging.log_to_db
 - RotatingFileHandler for persistent logs
 - Separate error trace log file (newpkg-errors.log)
 - perf_timer decorator that records timings and optionally writes aggregated metrics to DB
 - progress() helper using rich.Progress when available, graceful fallback otherwise
 - Attachable to CLI to integrate progress and phases
 - Safe DB integration (if newpkg_db is available), failures are logged as warnings to file
"""

from __future__ import annotations

import functools
import json
import os
import sys
import threading
import time
import traceback
from datetime import datetime
from logging import Handler, LogRecord
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# Optional dependencies
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    RICH_AVAILABLE = True
    _console = Console()
except Exception:
    RICH_AVAILABLE = False
    _console = None

# Optional config/db modules (import lazily in from_config)
try:
    from newpkg_config import init_config, get_config  # type: ignore
except Exception:
    init_config = None
    get_config = None

try:
    from newpkg_db import NewpkgDB  # type: ignore
except Exception:
    NewpkgDB = None

# fallback stdlib logging for internal fallback
import logging
_base_logger = logging.getLogger("newpkg_logger_internal")
if not _base_logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg_logger_internal: %(message)s"))
    _base_logger.addHandler(h)
_base_logger.setLevel(logging.INFO)


# ----------------- defaults -----------------
DEFAULT_THEME = "dark"  # dark | light | plain
DEFAULT_LOG_DIR = "/var/log/newpkg"
DEFAULT_LOG_FILE = "newpkg.log"
DEFAULT_ERROR_FILE = "newpkg-errors.log"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_BACKUPS = 3


# ----------------- helpers -----------------
def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        try:
            return json.dumps(str(obj))
        except Exception:
            return '"<unserializable>"'


# ----------------- main logger class -----------------
class NewpkgLogger:
    """
    NewpkgLogger manages console/file/json logging and optional DB integration.
    Use NewpkgLogger.from_config(cfg, db=None) to build from a config object.
    """

    def __init__(
        self,
        *,
        module: str = "newpkg",
        profile: Optional[str] = None,
        log_dir: Optional[str] = None,
        json_out: bool = False,
        quiet: bool = False,
        use_rich: bool = True,
        theme: str = DEFAULT_THEME,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backups: int = DEFAULT_BACKUPS,
        log_to_db: bool = True,
        error_log_path: Optional[str] = None,
        db: Any = None,
    ):
        self.module = module
        self.profile = profile or os.environ.get("NEWPKG_PROFILE")
        self.json_out = json_out
        self.quiet = quiet
        self.use_rich = use_rich and RICH_AVAILABLE
        self.theme = theme if theme in ("dark", "light", "plain") else DEFAULT_THEME
        self.log_to_db = bool(log_to_db)
        self._db = db  # expected to be NewpkgDB instance or compatible
        self._lock = threading.RLock()

        # log directory & file paths
        base_dir = Path(log_dir or os.environ.get("NEWPKG_LOG_DIR", DEFAULT_LOG_DIR)).expanduser()
        base_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = base_dir / DEFAULT_LOG_FILE
        self.error_log_path = Path(error_log_path or base_dir / DEFAULT_ERROR_FILE)

        # internal python logger for file handling
        self._pylogger = logging.getLogger(f"newpkg.{self.module}")
        self._pylogger.setLevel(logging.DEBUG)

        # configure handlers only once (idempotent)
        if not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in self._pylogger.handlers):
            self._configure_file_handler(max_bytes, backups)

        # keep an in-memory metrics aggregator: {func_name: {"count":N, "total":secs}}
        self._metrics: Dict[str, Dict[str, Any]] = {}

    # ----------------- constructor helper -----------------
    @classmethod
    def from_config(cls, cfg: Any = None, db: Any = None, module: str = "newpkg") -> "NewpkgLogger":
        """
        Build NewpkgLogger from `cfg` (Config instance) and optional DB (NewpkgDB)
        """
        cfg = cfg or (init_config() if init_config else None)
        # read values with safe fallback
        json_out = bool(cfg.get("output.json", False)) if cfg else False
        quiet = bool(cfg.get("output.quiet", False)) if cfg else False
        use_rich = bool(cfg.get("output.use_rich", True)) if cfg else True
        theme = cfg.get("output.theme", DEFAULT_THEME) if cfg else DEFAULT_THEME
        log_dir = cfg.get("logging.dir", cfg.get("cli.report_dir", DEFAULT_LOG_DIR)) if cfg else DEFAULT_LOG_DIR
        max_bytes = int(cfg.get("logging.max_bytes", DEFAULT_MAX_BYTES)) if cfg else DEFAULT_MAX_BYTES
        backups = int(cfg.get("logging.backups", DEFAULT_BACKUPS)) if cfg else DEFAULT_BACKUPS
        log_to_db = bool(cfg.get("logging.log_to_db", True)) if cfg else True
        error_log = cfg.get("logging.error_log", None) if cfg else None
        profile = cfg.get("profile.active", None) if cfg else None

        # choose db instance if not provided and NewpkgDB available
        if db is None and NewpkgDB and cfg:
            try:
                db = NewpkgDB(cfg)
            except Exception:
                db = None

        return cls(
            module=module,
            profile=profile,
            log_dir=log_dir,
            json_out=json_out,
            quiet=quiet,
            use_rich=use_rich,
            theme=theme,
            max_bytes=max_bytes,
            backups=backups,
            log_to_db=log_to_db,
            error_log_path=error_log,
            db=db,
        )

    # ----------------- internal file handler -----------------
    def _configure_file_handler(self, max_bytes: int, backups: int) -> None:
        from logging.handlers import RotatingFileHandler

        try:
            handler = RotatingFileHandler(str(self.log_path), maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
            formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
            handler.setFormatter(formatter)
            self._pylogger.addHandler(handler)
            # error log handler
            err_handler = RotatingFileHandler(str(self.error_log_path), maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
            err_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s\n%(exc_text)s")
            err_handler.setFormatter(err_formatter)
            self._pylogger.addHandler(err_handler)
        except Exception as e:
            _base_logger.warning(f"Failed to configure file handlers: {e}")

    # ----------------- emit helpers -----------------
    def _format_text(self, level: str, event: str, message: str, meta: Optional[Dict[str, Any]] = None) -> str:
        meta = meta or {}
        tag = f"[{level.upper()}]"
        if self.use_rich and _console:
            # colored formatting for rich
            if level.lower() == "info":
                return f"[green]{tag}[/green] [{self.module}] {message} {json.dumps(meta) if meta else ''}"
            if level.lower() == "warning":
                return f"[yellow]{tag}[/yellow] [{self.module}] {message} {json.dumps(meta) if meta else ''}"
            if level.lower() in ("error", "critical"):
                return f"[bold red]{tag}[/bold red] [{self.module}] {message} {json.dumps(meta) if meta else ''}"
            return f"[cyan]{tag}[/cyan] [{self.module}] {message} {json.dumps(meta) if meta else ''}"
        # fallback plain text
        return f"{_now_iso()} {tag} [{self.module}] {message} {json.dumps(meta) if meta else ''}"

    def _format_json(self, level: str, event: str, message: str, meta: Optional[Dict[str, Any]] = None) -> str:
        payload = {
            "ts": _now_iso(),
            "level": level.upper(),
            "module": self.module,
            "profile": self.profile,
            "event": event,
            "msg": message,
            "meta": meta or {},
        }
        return json.dumps(payload, ensure_ascii=False)

    def _write_to_file(self, text: str, level: str, exc_text: Optional[str] = None) -> None:
        try:
            # rely on python logger handlers for rotation
            self._pylogger.info(text if level.lower() != "error" else f"[ERROR] {text}")
            if exc_text:
                # append traceback to error log explicitly
                try:
                    with open(self.error_log_path, "a", encoding="utf-8") as fh:
                        fh.write(f"{_now_iso()} TRACE {self.module}:\n{exc_text}\n\n")
                except Exception:
                    pass
        except Exception as e:
            _base_logger.warning(f"Failed to write log to file: {e}")

    def _emit(self, level: str, event: str, message: str = "", **meta) -> None:
        """
        Core emit: writes to stdout (text or json), to file, and optionally to DB.
        """
        with self._lock:
            try:
                # prepare formatted outputs
                if self.json_out:
                    out = self._format_json(level, event, message, meta)
                else:
                    out = self._format_text(level, event, message, meta)

                # console output (unless quiet)
                if not self.quiet:
                    try:
                        if self.json_out:
                            # print JSON to stdout
                            print(out)
                        else:
                            if self.use_rich and _console:
                                _console.log(out)
                            else:
                                print(out, file=sys.stderr if level.lower() in ("error", "critical") else sys.stdout)
                    except Exception:
                        # console output must not break flow
                        pass

                # always write structured entry into the primary log file via python logger
                exc_text = meta.get("traceback") or None
                self._write_to_file(out, level, exc_text)

                # if configured, attempt to record in DB (safe)
                if self.log_to_db and self._db:
                    try:
                        # for critical events, also write into phases/events
                        if level.lower() in ("error", "critical"):
                            self._db.record_event(event=event, ts=int(time.time()), meta={"level": level, "msg": message, "meta": meta})
                        else:
                            # non-critical: short record
                            self._db.record_event(event=event, ts=int(time.time()), meta={"level": level, "meta": meta})
                    except Exception as e:
                        # don't let DB failures hide logging: write a warning to file
                        warn_msg = f"DB log failed: {e}"
                        try:
                            self._pylogger.warning(warn_msg)
                        except Exception:
                            _base_logger.warning(warn_msg)
            except Exception as e:
                # absolute fallback
                _base_logger.exception(f"_emit failed: {e}")

    # ------------- public API: logging convenience -------------
    def info(self, event: str, message: str = "", **meta) -> None:
        self._emit("info", event, message, **meta)

    def warning(self, event: str, message: str = "", **meta) -> None:
        self._emit("warning", event, message, **meta)

    def error(self, event: str, message: str = "", exc: Optional[Exception] = None, **meta) -> None:
        if exc is not None:
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            meta["traceback"] = tb
        self._emit("error", event, message, **meta)

    def critical(self, event: str, message: str = "", exc: Optional[Exception] = None, **meta) -> None:
        if exc is not None:
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            meta["traceback"] = tb
        self._emit("critical", event, message, **meta)

    def debug(self, event: str, message: str = "", **meta) -> None:
        # debug may be verbose; only log to file when quiet & debug disabled
        self._emit("debug", event, message, **meta)

    # ---------------- perf timer decorator ----------------
    def perf_timer(self, name: Optional[str] = None):
        """
        Decorator to time functions and store metrics in memory and optionally in DB.
        Usage:
            @logger.perf_timer("core.build")
            def build(...): ...
        """
        def deco(fn: Callable):
            fname = name or f"{fn.__module__}.{fn.__name__}"

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                start = time.time()
                exc = None
                try:
                    result = fn(*args, **kwargs)
                except Exception as e:
                    exc = e
                    raise
                finally:
                    duration = time.time() - start
                    # aggregate metrics
                    with self._lock:
                        m = self._metrics.get(fname) or {"count": 0, "total": 0.0}
                        m["count"] += 1
                        m["total"] += duration
                        self._metrics[fname] = m
                    # emit a perf event
                    try:
                        self._emit("info", f"perf.{fname}", f"{fname} took {duration:.3f}s", duration=duration, function=fname)
                    except Exception:
                        pass
                    # optionally persist to DB metrics (store last-run or aggregate)
                    if self.log_to_db and self._db:
                        try:
                            # record into meta.events or phases for tracking
                            self._db.record_event(event=f"perf.{fname}", ts=int(time.time()), meta={"duration": duration, "function": fname})
                        except Exception as e:
                            try:
                                self._pylogger.warning(f"Failed to write perf to DB: {e}")
                            except Exception:
                                _base_logger.warning(f"Failed to write perf to DB: {e}")
                return result
            return wrapper
        return deco

    # ---------------- progress helper ----------------
    def progress(self, description: str, total: Optional[int] = None):
        """
        Return a context manager to update a progress bar.
        Use as:
            with logger.progress("Construindo gcc", total=100) as p:
                for i in range(100):
                    p.update(i)
        The returned object implements update(value, advance=True) and stop() for the fallback.
        """
        if self.use_rich and RICH_AVAILABLE and _console:
            # rich version
            p = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn())
            task_id = None

            class RichCtx:
                def __enter__(self_inner):
                    p.start()
                    nonlocal task_id
                    task_id = p.add_task(description, total=total)
                    return p

                def __exit__(self_inner, exc_type, exc, tb):
                    try:
                        p.stop()
                    except Exception:
                        pass
            return RichCtx()
        else:
            # fallback simple textual progress
            class Fallback:
                def __enter__(self_inner):
                    if not self.quiet:
                        print(f">>> {description} ...")
                    return self_inner

                def update(self_inner, value: int = 0, advance: bool = True):
                    if not self.quiet:
                        print(f"... {description}: {value}")

                def __exit__(self_inner, exc_type, exc, tb):
                    if not self.quiet:
                        print(f">>> {description} done")
            return Fallback()

    # ---------------- attach to CLI / integrate progress ----------------
    def attach_to_cli(self, cli_instance: Any):
        """
        Attach logger helpers to a CLI instance (optional).
        CLI may then call logger.progress(...) and logger.perf_timer on demand.
        """
        try:
            setattr(cli_instance, "logger", self)
        except Exception:
            pass

    # ---------------- metrics / introspection ----------------
    def get_metrics(self) -> Dict[str, Dict[str, Any]]:
        """
        Return a shallow copy of aggregated metrics.
        """
        with self._lock:
            return {k: dict(v) for k, v in self._metrics.items()}

    def flush_metrics_to_db(self):
        """
        Persist aggregated metrics to DB meta (if available).
        This stores an object under meta key "performance_summary".
        """
        if not self._db:
            return False
        with self._lock:
            try:
                summary = {k: {"count": v["count"], "total": v["total"], "avg": (v["total"] / v["count"] if v["count"] else 0.0)} for k, v in self._metrics.items()}
                # store as event
                self._db.record_event(event="performance.summary", ts=int(time.time()), meta=summary)
                return True
            except Exception as e:
                try:
                    self._pylogger.warning(f"Failed to flush metrics: {e}")
                except Exception:
                    _base_logger.warning(f"Failed to flush metrics: {e}")
                return False

    # ---------------- convenience ----------------
    def set_db(self, db_instance: Any):
        with self._lock:
            self._db = db_instance

    def set_quiet(self, v: bool):
        with self._lock:
            self.quiet = bool(v)

    def set_json_out(self, v: bool):
        with self._lock:
            self.json_out = bool(v)
            if self.json_out:
                # disable rich console prints
                self.use_rich = False

    def set_module(self, module: str):
        with self._lock:
            self.module = module

    def flush(self):
        """
        Try to flush any file handlers immediately.
        """
        try:
            for h in self._pylogger.handlers:
                try:
                    h.flush()
                except Exception:
                    pass
        except Exception:
            pass


# ---------------- module-level convenience factory ----------------
_global_logger: Optional[NewpkgLogger] = None
_global_lock = threading.RLock()


def get_logger(cfg: Any = None, db: Any = None, module: str = "newpkg") -> NewpkgLogger:
    """
    Return a reusable global logger instance created from config.
    """
    global _global_logger
    with _global_lock:
        if _global_logger is None:
            _global_logger = NewpkgLogger.from_config(cfg, db=db, module=module)
        return _global_logger


# ---------------- simple CLI test ----------------
if __name__ == "__main__":
    cfg = init_config() if init_config else None
    lg = NewpkgLogger.from_config(cfg)
    lg.info("test.start", "Logger initialized", env=os.environ.get("USER"))
    @lg.perf_timer("example.sleep")
    def sleepy(n=0.1):
        time.sleep(n)
        return "ok"
    sleepy(0.05)
    with lg.progress("Example progress", total=10) as p:
        # if using rich, p is a Progress instance; otherwise fallback
        try:
            for i in range(10):
                time.sleep(0.01)
                if hasattr(p, "advance"):
                    p.advance(0)
                else:
                    try:
                        p.update(i)
                    except Exception:
                        pass
        except Exception:
            pass
    lg.flush_metrics_to_db()
    lg.info("test.done", "Done")
