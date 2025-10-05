"""
newpkg_logger.py

Logger central para newpkg.
- Logs estruturados em JSON para arquivo e opcionalmente para DB (newpkg_db.NewpkgDB)
- Saída para console com opção colorida (colorama) ou texto limpo
- Decorator @perf_timer para medir e logar duração de funções
- Context manager para contextos hierárquicos (start_context/end_context ou using `with logger.context('name'):`)

Dependências opcionais:
- colorama (opcional, para saída colorida no console)

Uso:
    logger = NewpkgLogger(cfg, db=db)
    logger.log_event('package_build', level='INFO', metadata={'package': 'xorg'})

    @logger.perf_timer('build_phase')
    def build():
        ...

    with logger.context('build', 'xorg'):
        ...

"""
from __future__ import annotations

import logging
import logging.handlers
import json
import time
import os
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Optional, List, Callable
from functools import wraps

# optional color support
try:
    from colorama import Fore, Style, init as _color_init
    _color_init(autoreset=True)
    COLORAMA_AVAILABLE = True
except Exception:
    COLORAMA_AVAILABLE = False


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
        }
        # attach any structured data passed in record
        extra = getattr(record, "extra_data", None)
        if extra and isinstance(extra, dict):
            payload.update(extra)
        # attach stack/context if present
        ctx = getattr(record, "context", None)
        if ctx:
            payload["context"] = ctx
        return json.dumps(payload, ensure_ascii=False)


class PlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.utcfromtimestamp(record.created).isoformat() + "Z"
        level = record.levelname
        msg = record.getMessage()
        ctx = getattr(record, "context", None)
        if ctx:
            ctxs = ":".join(ctx)
            return f"{timestamp} [{level}] ({ctxs}) {msg}"
        return f"{timestamp} [{level}] {msg}"


class NewpkgLogger:
    def __init__(self, cfg: Any = None, db: Any = None):
        """Inicializa o logger.

        cfg: objeto compatível com ConfigStore, com get(key) -> value
        db: optional NewpkgDB instance
        """
        self.cfg = cfg
        self.db = db
        # context stack: list of strings
        self._context: List[str] = []

        # configuration defaults
        log_dir = "./logs"
        log_file = "newpkg.log"
        level = "INFO"
        log_to_db = False
        log_format = "json"
        rotate = True
        max_bytes = 10 * 1024 * 1024
        backup_count = 5

        # read from cfg if available
        try:
            if self.cfg is not None:
                log_dir = self.cfg.get("logging.log_dir") or self.cfg.get("logging.log_dir") or log_dir
                log_file = self.cfg.get("logging.log_file") or self.cfg.get("logging.log_file") or log_file
                level = self.cfg.get("logging.level") or level
                log_to_db = _to_bool(self.cfg.get("logging.log_to_db") or self.cfg.get("logging.LOG_TO_DB") or log_to_db)
                log_format = self.cfg.get("logging.format") or log_format
                rotate = _to_bool(self.cfg.get("logging.rotate") or rotate)
                max_bytes = int(self.cfg.get("logging.max_bytes") or max_bytes)
                backup_count = int(self.cfg.get("logging.backup_count") or backup_count)
        except Exception:
            # ignore misconfig
            pass

        self.log_to_db = bool(log_to_db)
        # ensure dir
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception:
            # fallback to cwd
            log_dir = "."

        # setup logger
        self.logger = logging.getLogger("newpkg")
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        # remove existing handlers with same name to avoid duplicates
        for h in list(self.logger.handlers):
            self.logger.removeHandler(h)

        # file handler
        file_path = os.path.join(log_dir, log_file)
        if rotate:
            fh = logging.handlers.RotatingFileHandler(file_path, maxBytes=max_bytes, backupCount=backup_count)
        else:
            fh = logging.FileHandler(file_path)

        if log_format == "json":
            fh.setFormatter(JSONFormatter())
        else:
            fh.setFormatter(PlainFormatter())
        self.logger.addHandler(fh)

        # console handler
        ch = logging.StreamHandler()
        ch.setLevel(getattr(logging, level.upper(), logging.INFO))
        # console uses plain formatter but can be colorized
        ch.setFormatter(PlainFormatter())
        self.logger.addHandler(ch)

    # ----------------- context management -----------------
    @contextmanager
    def context(self, *names: str):
        """Context manager to push/pop context names.

        Usage: with logger.context('build', 'xorg'):
                   logger.log_event(...)
        """
        for n in names:
            self._context.append(str(n))
        try:
            yield
        finally:
            for _ in names:
                if self._context:
                    self._context.pop()

    def start_context(self, *names: str) -> None:
        for n in names:
            self._context.append(str(n))

    def end_context(self, count: int = 1) -> None:
        for _ in range(count):
            if self._context:
                self._context.pop()

    def get_context(self) -> List[str]:
        return list(self._context)

    # ----------------- core logging -----------------
    def log_event(self, event: str, level: str = "INFO", message: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Log an structured event.

        event: event name
        level: logging level string
        metadata: arbitrary dict attached to the event
        """
        levelno = getattr(logging, level.upper(), logging.INFO)
        extra = {"event": event}
        if metadata:
            extra.update({"metadata": metadata})
        # craft record with extra_data and context
        self.logger.log(levelno, message or event, extra={"extra_data": extra, "context": self.get_context()})

        # optionally persist to DB (if available)
        if self.log_to_db and self.db is not None:
            try:
                # map simple events to db.add_log where appropriate
                if metadata and isinstance(metadata, dict) and metadata.get("package"):
                    pkg = metadata.get("package")
                else:
                    pkg = None
                if pkg:
                    phase = metadata.get("phase") or event
                    status = metadata.get("status") or ("ok" if levelno < logging.ERROR else "fail")
                    # attempt to write into build_logs table
                    try:
                        self.db.add_log(pkg, phase, status, log_path=None)
                    except Exception:
                        # do not crash the logger if db write fails
                        pass
            except Exception:
                pass

    # ----------------- decorator -----------------
    def perf_timer(self, event_name: Optional[str] = None):
        """Decorator to measure duration and log result.

        Usage:
            @logger.perf_timer('build_pkg')
            def build(...):
                ...
        """
        def deco(fn: Callable):
            name = event_name or fn.__name__

            @wraps(fn)
            def wrapper(*args, **kwargs):
                start = time.time()
                try:
                    res = fn(*args, **kwargs)
                    duration = time.time() - start
                    # try to infer package from kwargs/args
                    meta = {}
                    if "package" in kwargs:
                        meta["package"] = kwargs.get("package")
                    elif len(args) > 0 and isinstance(args[0], str):
                        meta["package"] = args[0]
                    meta.update({"duration": duration})
                    self.log_event(name, level="INFO", message=f"{name} completed", metadata=meta)
                    return res
                except Exception as e:
                    duration = time.time() - start
                    meta = {"duration": duration, "error": str(e)}
                    self.log_event(name, level="ERROR", message=f"{name} failed: {e}", metadata=meta)
                    raise

            return wrapper

        return deco

    # ----------------- helpers -----------------
    def set_level(self, level: str) -> None:
        lvl = getattr(logging, level.upper(), None)
        if lvl is None:
            raise ValueError("Invalid level")
        self.logger.setLevel(lvl)
        for h in self.logger.handlers:
            h.setLevel(lvl)

    def flush(self) -> None:
        for h in self.logger.handlers:
            try:
                h.flush()
            except Exception:
                pass

    def close(self) -> None:
        for h in list(self.logger.handlers):
            try:
                h.close()
            except Exception:
                pass
            try:
                self.logger.removeHandler(h)
            except Exception:
                pass


# ----------------- convenience functions -----------------

def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    s = str(v).lower()
    return s in ("1", "true", "yes", "on")


# ----------------- small demo when executed -----------------
if __name__ == "__main__":
    # quick demo
    from argparse import ArgumentParser

    ap = ArgumentParser()
    ap.add_argument("--file", help="log file", default=None)
    args = ap.parse_args()
    logger = NewpkgLogger()
    with logger.context("demo", "test"):
        logger.log_event("demo_event", level="INFO", message="This is a test", metadata={"package": "demo"})

    @logger.perf_timer("demo_task")
    def work(x):
        time.sleep(0.1)
        return x * 2

    work(2)
    print("Done demo")
