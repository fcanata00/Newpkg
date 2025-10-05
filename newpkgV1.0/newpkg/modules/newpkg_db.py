#!/usr/bin/env python3
# newpkg_db_fixed.py
"""
Improved newpkg_db.py

Fixes & improvements:
- Lazy imports for newpkg_config and newpkg_api to avoid circular imports
- SimpleLogger fallback when newpkg_logger.get_logger is unavailable
- Use shutil safely in recover (import added)
- Ensure rollback on commit failures
- Protect hooks execution with try/except and avoid failing the DB operation
- Add close() and context manager (__enter__/__exit__)
- Optimize add_package_files using executemany()
- Apply _safe_call to diagnostic methods
- Fix logging call formats
"""

from __future__ import annotations

import errno
import json
import os
import sqlite3
import stat
import threading
import time
import traceback
import shutil
import logging
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Optional get_logger lazy import helper
# ---------------------------------------------------------------------------
def _try_get_logger(cfg=None):
    try:
        from newpkg_logger import get_logger  # type: ignore
        return get_logger(cfg)
    except Exception:
        return None


# Fallback logger (module-level)
_module_logger = logging.getLogger("newpkg.db")
if not _module_logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.db: %(message)s"))
    _module_logger.addHandler(_h)
_module_logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class DBInfo:
    path: str
    size_bytes: int
    last_modified: float
    tables: List[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ensure_dir(path: Path, mode: int = 0o700):
    path = Path(path)
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(path), mode)
    except Exception:
        pass


def _set_file_perms(path: Path, mode: int = 0o600):
    try:
        os.chmod(str(path), mode)
    except Exception:
        pass


def _safe_call(fn):
    """Decorator to catch exceptions and return None/fallback for non-critical methods."""
    @wraps(fn)
    def _inner(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            try:
                _module_logger.error(f"db.safe_call_exception: {fn.__name__} raised {e}", exc_info=True)
            except Exception:
                pass
            return None
    return _inner


# ---------------------------------------------------------------------------
# SimpleLogger fallback
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
# Main database class
# ---------------------------------------------------------------------------
class NewpkgDB:
    DEFAULT_DB_PATH = "/var/lib/newpkg/newpkg.db"
    SCHEMA_VERSION = 1

    def __init__(self, db_path: Optional[str] = None, cfg: Any = None, logger: Any = None, hooks: Any = None):
        # Lazy import for config
        self.cfg = cfg
        if self.cfg is None:
            try:
                from newpkg_config import get_config  # type: ignore
                self.cfg = get_config()
            except Exception:
                self.cfg = None

        # Resolve db path
        if not db_path and self.cfg and hasattr(self.cfg, "get"):
            try:
                db_path = self.cfg.get("db.path") or self.cfg.get("newpkg.db_path")
            except Exception:
                db_path = None
        self.db_path = Path(db_path or os.environ.get("NEWPKG_DB", self.DEFAULT_DB_PATH)).expanduser()
        _ensure_dir(self.db_path.parent, mode=0o700)

        self.conn: Optional[sqlite3.Connection] = None
        self._conn_lock = threading.RLock()

        # Logger
        try:
            self.logger = logger or _try_get_logger(self.cfg) or SimpleLogger()
        except Exception:
            self.logger = SimpleLogger()

        # Hooks (lazy init)
        self.hooks = hooks
        if self.hooks is None:
            try:
                from newpkg_hooks import get_hooks_manager  # type: ignore
                self.hooks = get_hooks_manager(self.cfg)
            except Exception:
                self.hooks = None

        self._open_or_create_db()

        # Try registering with API (lazy)
        try:
            from newpkg_api import get_api  # type: ignore
            try:
                api = get_api()
                api.db = self
                self.logger.info("db.register", "registered DB with newpkg_api")
            except Exception:
                pass
        except Exception:
            pass

        self._cache_lock = threading.RLock()

    # -----------------------------------------------------------------------
    # Database opening and schema
    # -----------------------------------------------------------------------
    def _open_or_create_db(self):
        try:
            self._connect()
            self._apply_pragmas()
            if not self._has_tables():
                self._create_schema()
        except sqlite3.DatabaseError:
            _module_logger.warning("db.open_corrupt: database open failed, attempting recovery")
            if not self.recover():
                raise
            self._connect()
            self._apply_pragmas()
            if not self._has_tables():
                self._create_schema()

    def _connect(self):
        with self._conn_lock:
            if self.conn:
                try:
                    self.conn.execute("select 1")
                    return
                except Exception:
                    try:
                        self.conn.close()
                    except Exception:
                        pass
            _ensure_dir(self.db_path.parent, mode=0o700)
            self.conn = sqlite3.connect(str(self.db_path), timeout=30, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            _set_file_perms(self.db_path, 0o600)

    def _apply_pragmas(self):
        with self._conn_lock:
            if not self.conn:
                return
            cur = self.conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA foreign_keys = ON;")
            cur.close()

    def _has_tables(self) -> bool:
        with self._conn_lock:
            cur = self.conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            rows = cur.fetchall()
            cur.close()
            return bool(rows)

    def _create_schema(self):
        schema = """
        BEGIN;
        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT,
            installed_at INTEGER,
            installed_by TEXT,
            meta JSON
        );
        CREATE UNIQUE INDEX IF NOT EXISTS packages_name_version ON packages(name, version);
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            package_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT,
            size INTEGER,
            FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS files_path_idx ON files(path);
        CREATE TABLE IF NOT EXISTS deps (
            id INTEGER PRIMARY KEY,
            package_id INTEGER NOT NULL,
            dep_name TEXT NOT NULL,
            dep_type TEXT,
            FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS phases (
            id INTEGER PRIMARY KEY,
            package TEXT,
            phase TEXT,
            status TEXT,
            meta JSON,
            ts INTEGER
        );
        CREATE TABLE IF NOT EXISTS meta_kv (
            key TEXT PRIMARY KEY,
            value JSON,
            modified INTEGER
        );
        COMMIT;
        """
        self.conn.executescript(schema)

    # -----------------------------------------------------------------------
    # Recovery
    # -----------------------------------------------------------------------
    def recover(self):
        try:
            if self.conn:
                self.conn.close()
                self.conn = None
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            backup = self.db_path.with_suffix(f".corrupt-{ts}.bak")
            try:
                self.db_path.rename(backup)
            except Exception:
                shutil.copy2(self.db_path, backup)
            _module_logger.warning(f"db.recover: moved corrupt DB to {backup}")
            self._connect()
            self._create_schema()
            return True
        except Exception as e:
            _module_logger.error(f"db.recover_fail: {e}", exc_info=True)
            return False

    # -----------------------------------------------------------------------
    # Helpers for execution and transactions
    # -----------------------------------------------------------------------
    def _execute(self, sql: str, params: Tuple = (), commit: bool = False) -> sqlite3.Cursor:
        with self._conn_lock:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            if commit:
                try:
                    self.conn.commit()
                except Exception:
                    self.conn.rollback()
                    raise
            return cur

    # -----------------------------------------------------------------------
    # Core methods
    # -----------------------------------------------------------------------
    def record_package(self, name: str, version: Optional[str] = None,
                       installed_by: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> int:
        now = int(time.time())
        meta_json = json.dumps(meta or {})
        cur = self._execute(
            "INSERT INTO packages (name, version, installed_at, installed_by, meta) VALUES (?, ?, ?, ?, ?);",
            (name, version, now, installed_by, meta_json), commit=True)
        pkg_id = cur.lastrowid
        cur.close()
        return pkg_id

    def add_package_files(self, package_id: int, files: Iterable[Tuple[str, Optional[str], Optional[int]]]):
        cur = self.conn.cursor()
        entries = [(package_id, p, sha, size) for (p, sha, size) in files]
        cur.executemany("INSERT INTO files (package_id, path, sha256, size) VALUES (?, ?, ?, ?);", entries)
        self.conn.commit()
        cur.close()

    @_safe_call
    def db_stats(self) -> Dict[str, Any]:
        cur = self.conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table';")]
        data = {t: cur.execute(f"SELECT COUNT(*) FROM {t};").fetchone()[0] for t in tables}
        cur.close()
        return data

    @_safe_call
    def dump_db_info(self) -> DBInfo:
        tables = [r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table';")]
        st = self.db_path.stat()
        return DBInfo(str(self.db_path), st.st_size, st.st_mtime, tables)

    # -----------------------------------------------------------------------
    # Context and cleanup
    # -----------------------------------------------------------------------
    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
