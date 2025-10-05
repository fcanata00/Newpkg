#!/usr/bin/env python3
# newpkg_db.py
"""
Revised newpkg_db.py

Features:
 - SQLite DB with WAL, foreign keys
 - Automatic recovery on corruption (backup + recreate)
 - Secure file permissions for DB and dir
 - pre_commit / post_commit hook integration
 - Integration with newpkg_api (register as api.db when available)
 - LRU cache for read-heavy getters with intelligent invalidation on writes
 - Convenience API: get_or_create_package, db_stats, dump_db_info
 - Defensive code: degrades gracefully when optional modules are absent
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
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Optional integrations (best-effort)
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
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

# fallback logger
import logging
_logger = logging.getLogger("newpkg.db")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.db: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# ---------------- dataclasses ----------------
@dataclass
class DBInfo:
    path: str
    size_bytes: int
    last_modified: float
    tables: List[str]


# ---------------- helpers ----------------
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
                _logger.error("db.safe_call_exception", f"{fn.__name__} raised {e}", exc_info=True)
            except Exception:
                pass
            return None
    return _inner


# ---------------- main class ----------------
class NewpkgDB:
    DEFAULT_DB_PATH = "/var/lib/newpkg/newpkg.db"
    SCHEMA_VERSION = 1

    def __init__(self, db_path: Optional[str] = None, cfg: Any = None, logger: Any = None, hooks: Any = None):
        self.cfg = cfg or (get_config() if get_config else None)
        # allow config override db path
        if not db_path and self.cfg and hasattr(self.cfg, "get"):
            try:
                db_path = self.cfg.get("db.path") or self.cfg.get("newpkg.db_path")
            except Exception:
                db_path = None
        self.db_path = Path(db_path or os.environ.get("NEWPKG_DB", self.DEFAULT_DB_PATH)).expanduser()
        # ensure dir exists and secure perms
        _ensure_dir(self.db_path.parent, mode=0o700)
        self.conn: Optional[sqlite3.Connection] = None
        self._conn_lock = threading.RLock()
        self.logger = logger or (get_logger(self.cfg) if get_logger else None)
        self.hooks = hooks or (get_hooks_manager(self.cfg) if get_hooks_manager else None)
        self._init_on_create = True
        self._open_or_create_db()
        # register with API if available
        try:
            api = get_api() if get_api else None
            if api:
                api.db = self
                if self.logger:
                    self.logger.info("db.register", "registered DB with newpkg_api")
        except Exception:
            pass
        # caches invalidated after writes
        self._cache_lock = threading.RLock()

    # ---------------- low-level DB open / schema ----------------
    def _open_or_create_db(self):
        try:
            self._connect()
            self._apply_pragmas()
            # basic migrations / schema install if needed
            if not self._has_tables():
                self._create_schema()
        except sqlite3.DatabaseError:
            _logger.warning("db.open_corrupt", "database open failed, attempting recovery")
            self.recover()
            # try again
            try:
                self._connect()
                self._apply_pragmas()
                if not self._has_tables():
                    self._create_schema()
            except Exception as e:
                _logger.error("db.open_failed", f"unable to open DB after recovery: {e}", exc_info=True)
                raise

    def _connect(self):
        # open sqlite connection with check_same_thread=False for threaded use but protect with locks
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
            # ensure parent dir perms
            try:
                _set_file_perms(self.db_path.parent, 0o700)
            except Exception:
                pass
            self.conn = sqlite3.connect(str(self.db_path), timeout=30, check_same_thread=False)
            # row factory
            self.conn.row_factory = sqlite3.Row

            # secure file perms
            try:
                _set_file_perms(self.db_path, 0o600)
            except Exception:
                pass

    def _apply_pragmas(self):
        with self._conn_lock:
            if not self.conn:
                return
            cur = self.conn.cursor()
            try:
                # enable WAL for concurrency
                cur.execute("PRAGMA journal_mode=WAL;")
            except Exception:
                pass
            try:
                cur.execute("PRAGMA foreign_keys = ON;")
            except Exception:
                pass
            # tune synchronous depending on config
            sync = "FULL"
            try:
                if self.cfg and hasattr(self.cfg, "get"):
                    sync = self.cfg.get("db.synchronous") or sync
            except Exception:
                pass
            try:
                cur.execute(f"PRAGMA synchronous = {sync};")
            except Exception:
                pass
            cur.close()

    def _has_tables(self) -> bool:
        with self._conn_lock:
            cur = self.conn.cursor()
            try:
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
                rows = cur.fetchall()
                return len(rows) > 0
            except Exception:
                return False
            finally:
                cur.close()

    def _create_schema(self):
        """
        Basic schema:
         - packages (id, name, version, installed_at, installed_by, meta JSON)
         - files (id, package_id, path, sha256, size)
         - deps (id, package_id, dep_name, dep_type)
         - phases (id, package, phase, status, meta JSON, ts)
         - meta (key, value)
        """
        with self._conn_lock:
            cur = self.conn.cursor()
            try:
                cur.executescript(
                    """
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
                )
                # VACUUM/ANALYZE optionally
                try:
                    cur.execute("ANALYZE;")
                except Exception:
                    pass
            finally:
                cur.close()

    # ---------------- recovery ----------------
    def recover(self):
        """
        Attempt to recover a corrupt DB: create timestamped backup, move corrupt file aside, recreate schema.
        """
        try:
            if self.conn:
                try:
                    self.conn.close()
                except Exception:
                    pass
                self.conn = None
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            corrupt = self.db_path
            backup = self.db_path.with_suffix(f".corrupt-{ts}.bak")
            try:
                corrupt.rename(backup)
            except Exception:
                try:
                    shutil.copy2(str(corrupt), str(backup))
                except Exception:
                    pass
            _logger.warning("db.recover", f"moved corrupt DB to {backup}")
            # create fresh DB file
            self._connect()
            self._create_schema()
            return True
        except Exception as e:
            _logger.error("db.recover_fail", f"recovery failed: {e}", exc_info=True)
            return False

    # ---------------- transactional helpers ----------------
    def _execute(self, sql: str, params: Tuple = (), commit: bool = False) -> sqlite3.Cursor:
        with self._conn_lock:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            if commit:
                # pre_commit hook
                if self.hooks:
                    try:
                        self.hooks.run("pre_commit", {"sql": sql, "params": params})
                    except Exception:
                        pass
                self.conn.commit()
                # post_commit hook
                if self.hooks:
                    try:
                        self.hooks.run("post_commit", {"sql": sql, "params": params})
                    except Exception:
                        pass
            return cur

    # ---------------- cache invalidation ----------------
    def _invalidate_caches(self):
        with self._cache_lock:
            try:
                self.get_pkg_meta.cache_clear()
            except Exception:
                pass
            try:
                self.get_package_files.cache_clear()
            except Exception:
                pass

    # ---------------- public API methods ----------------
    def record_phase(self, package: Optional[str], phase: str, status: str, meta: Optional[Dict[str, Any]] = None) -> bool:
        """Record lifecycle phases for packages or generic events."""
        meta_json = json.dumps(meta or {})
        ts = int(time.time())
        try:
            self._execute("INSERT INTO phases (package, phase, status, meta, ts) VALUES (?, ?, ?, ?, ?);",
                          (package, phase, status, meta_json, ts), commit=True).close()
            return True
        except Exception as e:
            try:
                _logger.error("db.record_phase_fail", f"{e}", exc_info=True)
            except Exception:
                pass
            return False

    def record_package(self, name: str, version: Optional[str] = None, installed_by: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> int:
        """Insert/Update a package entry and return package_id."""
        now = int(time.time())
        meta_json = json.dumps(meta or {})
        try:
            # try update existing by name+version
            cur = self._execute("SELECT id FROM packages WHERE name = ? AND (version = ? OR (? IS NULL AND version IS NULL));", (name, version, version))
            row = cur.fetchone()
            cur.close()
            if row:
                pkg_id = row["id"]
                self._execute("UPDATE packages SET installed_at = ?, installed_by = ?, meta = ? WHERE id = ?;",
                              (now, installed_by, meta_json, pkg_id), commit=True).close()
            else:
                cur = self._execute("INSERT INTO packages (name, version, installed_at, installed_by, meta) VALUES (?, ?, ?, ?, ?);",
                                    (name, version, now, installed_by, meta_json), commit=True)
                pkg_id = cur.lastrowid
                cur.close()
            # invalidate caches
            self._invalidate_caches()
            return int(pkg_id)
        except Exception as e:
            _logger.error("db.record_package_fail", f"{e}", exc_info=True)
            raise

    def get_or_create_package(self, name: str, version: Optional[str] = None, installed_by: Optional[str] = None, meta: Optional[Dict[str,Any]] = None) -> Tuple[int, bool]:
        """
        Get package id or create it. Returns (package_id, created_flag)
        """
        with self._conn_lock:
            cur = self.conn.cursor()
            try:
                cur.execute("SELECT id FROM packages WHERE name = ? AND (version = ? OR (? IS NULL AND version IS NULL));", (name, version, version))
                row = cur.fetchone()
                if row:
                    return int(row["id"]), False
                now = int(time.time())
                meta_json = json.dumps(meta or {})
                cur.execute("INSERT INTO packages (name, version, installed_at, installed_by, meta) VALUES (?, ?, ?, ?, ?);",
                            (name, version, now, installed_by, meta_json))
                pid = cur.lastrowid
                self.conn.commit()
                self._invalidate_caches()
                return int(pid), True
            finally:
                cur.close()

    @lru_cache(maxsize=4096)
    def get_pkg_meta(self, name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Return package metadata dict or None."""
        try:
            cur = self._execute("SELECT * FROM packages WHERE name = ? AND (version = ? OR (? IS NULL AND version IS NULL)) LIMIT 1;", (name, version, version))
            row = cur.fetchone()
            cur.close()
            if not row:
                return None
            d = dict(row)
            # parse meta JSON
            try:
                d["meta"] = json.loads(d.get("meta") or "{}")
            except Exception:
                d["meta"] = {}
            return d
        except Exception:
            return None

    @lru_cache(maxsize=8192)
    def get_package_files(self, package_name: str) -> List[str]:
        """Return list of file paths installed by package (aggregated across versions)."""
        try:
            cur = self._execute("SELECT f.path FROM files f JOIN packages p ON f.package_id = p.id WHERE p.name = ?;", (package_name,))
            rows = cur.fetchall()
            cur.close()
            return [r["path"] for r in rows]
        except Exception:
            return []

    def add_package_files(self, package_id: int, files: Iterable[Tuple[str, Optional[str], Optional[int]]]):
        """
        Add files for a package. files: iterable of (path, sha256, size)
        """
        try:
            with self._conn_lock:
                cur = self.conn.cursor()
                for (p, sha, size) in files:
                    cur.execute("INSERT INTO files (package_id, path, sha256, size) VALUES (?, ?, ?, ?);", (package_id, p, sha, size))
                self.conn.commit()
            self._invalidate_caches()
        except Exception as e:
            _logger.error("db.add_files_fail", f"{e}", exc_info=True)
            raise

    def purge_package_metadata(self, package_name: str) -> bool:
        """Remove package metadata and optionally files entries (use with care)."""
        try:
            with self._conn_lock:
                cur = self.conn.cursor()
                # find package ids
                cur.execute("SELECT id FROM packages WHERE name = ?;", (package_name,))
                ids = [r["id"] for r in cur.fetchall()]
                if not ids:
                    cur.close()
                    return True
                for pid in ids:
                    cur.execute("DELETE FROM files WHERE package_id = ?;", (pid,))
                    cur.execute("DELETE FROM deps WHERE package_id = ?;", (pid,))
                    cur.execute("DELETE FROM packages WHERE id = ?;", (pid,))
                self.conn.commit()
                cur.close()
            self._invalidate_caches()
            return True
        except Exception as e:
            _logger.error("db.purge_fail", f"{e}", exc_info=True)
            return False

    def list_packages(self, limit: Optional[int] = None, offset: int = 0) -> List[Dict[str, Any]]:
        """List installed packages with optional pagination."""
        try:
            sql = "SELECT id, name, version, installed_at, installed_by, meta FROM packages ORDER BY installed_at DESC"
            if limit:
                sql += f" LIMIT {int(limit)} OFFSET {int(offset)}"
            cur = self._execute(sql, ())
            rows = cur.fetchall()
            cur.close()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["meta"] = json.loads(d.get("meta") or "{}")
                except Exception:
                    d["meta"] = {}
                out.append(d)
            return out
        except Exception:
            return []

    def get_package_versions(self, package_name: str) -> List[Dict[str, Any]]:
        """Return list of versions installed for a package (newest first)."""
        try:
            cur = self._execute("SELECT id, version, installed_at, installed_by, meta FROM packages WHERE name = ? ORDER BY installed_at DESC;", (package_name,))
            rows = cur.fetchall()
            cur.close()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["meta"] = json.loads(d.get("meta") or "{}")
                except Exception:
                    d["meta"] = {}
                out.append(d)
            return out
        except Exception:
            return []

    def record_dependency(self, package_id: int, dep_name: str, dep_type: Optional[str] = None):
        try:
            self._execute("INSERT INTO deps (package_id, dep_name, dep_type) VALUES (?, ?, ?);", (package_id, dep_name, dep_type), commit=True).close()
            return True
        except Exception as e:
            _logger.error("db.record_dep_fail", f"{e}", exc_info=True)
            return False

    # ---------------- diagnostic utilities ----------------
    def db_stats(self) -> Dict[str, Any]:
        """Return statistics: table counts, DB size, last modified."""
        try:
            stats = {}
            cur = self._execute("SELECT name, (SELECT COUNT(*) FROM sqlite_master WHERE type='table') as tblcount FROM sqlite_master WHERE type='table';")
            # easy approach: count rows per table
            cur.close()
            with self._conn_lock:
                cur2 = self.conn.cursor()
                tables = [r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")]
                for t in tables:
                    try:
                        c = cur2.execute(f"SELECT COUNT(*) as cnt FROM {t};").fetchone()
                        stats[t] = int(c[0]) if c else 0
                    except Exception:
                        stats[t] = None
                cur2.close()
            st = self.db_path.stat()
            return {"tables": stats, "size_bytes": st.st_size, "last_modified": st.st_mtime}
        except Exception as e:
            _logger.error("db.stats_fail", f"{e}", exc_info=True)
            return {}

    def dump_db_info(self) -> DBInfo:
        """Return DBInfo dataclass"""
        try:
            tables = [r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")]
            st = self.db_path.stat()
            return DBInfo(path=str(self.db_path), size_bytes=st.st_size, last_modified=st.st_mtime, tables=tables)
        except Exception:
            return DBInfo(path=str(self.db_path), size_bytes=0, last_modified=0.0, tables=[])

    # ---------------- helper to run raw queries (careful) ----------------
    def raw_query(self, sql: str, params: Tuple = ()) -> List[sqlite3.Row]:
        try:
            cur = self._execute(sql, params)
            rows = cur.fetchall()
            cur.close()
            return rows
        except Exception as e:
            _logger.error("db.raw_query_fail", f"{e}", exc_info=True)
            return []

# ---------------- caching wrappers on bound methods ----------------
# lru_cache only works on functions; we provide cached variants that call the instance methods.

def _cached_method(func):
    """Decorator to provide an lru_cache per-instance by using a key that includes id(self)."""
    cache = lru_cache(maxsize=4096)(lambda instance_id, *args, **kwargs: func(*args, **kwargs))
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        return cache(id(self), *args, **kwargs)
    wrapper.cache_clear = cache.cache_clear
    return wrapper

# Monkey-patch lru wrappers onto the class after definition for methods needing caching
# We attach cached versions named get_pkg_meta_cached and get_package_files_cached
def _attach_caches(cls):
    cls.get_pkg_meta_cached = _cached_method(cls.get_pkg_meta)
    cls.get_package_files_cached = _cached_method(cls.get_package_files)
    # expose clear functions
    def clear_caches(self):
        try:
            self.get_pkg_meta_cached.cache_clear()
        except Exception:
            pass
        try:
            self.get_package_files_cached.cache_clear()
        except Exception:
            pass
    cls.clear_caches = clear_caches

_attach_caches(NewpkgDB)

# ---------------- module-level convenience ----------------
_default_db: Optional[NewpkgDB] = None
_db_lock = threading.RLock()

def get_db(db_path: Optional[str] = None, cfg: Any = None, logger: Any = None, hooks: Any = None) -> NewpkgDB:
    global _default_db
    with _db_lock:
        if _default_db is None:
            _default_db = NewpkgDB(db_path=db_path, cfg=cfg, logger=logger, hooks=hooks)
        return _default_db

# ---------------- simple CLI for diagnostics ----------------
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-db", description="inspect newpkg database")
    p.add_argument("--path", help="db path override")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--dump", action="store_true")
    args = p.parse_args()
    db = get_db(db_path=args.path) if args.path else get_db()
    if args.stats:
        pprint.pprint(db.db_stats())
    if args.dump:
        pprint.pprint(db.dump_db_info().__dict__)
