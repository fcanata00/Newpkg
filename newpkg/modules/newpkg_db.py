#!/usr/bin/env python3
# newpkg_db.py
"""
Revised newpkg_db.py

Features implemented:
 - SQLite-based persistence with WAL mode and foreign keys enabled
 - Schema + migrations support (meta.table schema_version)
 - Indexes for files.path, deps.dep, packages.name
 - INSERT OR IGNORE / UPSERT behaviour to avoid duplicates
 - thread-safe via RLock and transaction context manager
 - verify_integrity(parallel=True) using ThreadPoolExecutor
 - backup_db(include_files='recorded'|'all', compress=True/False)
 - functions: list_packages, get_pkg_meta, record_package, record_file, list_files,
              add_dep, get_deps, get_reverse_deps, record_phase, record_event,
              cleanup_orphans, export_packages_json, remove_package, update_package_version
 - DB path selection supports profile: core.db_dir + profile.active
 - Integration points for newpkg_logger/newpkg_config when available
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# Optional integrations
try:
    from newpkg_config import init_config, get_config
except Exception:
    init_config = None
    get_config = None

try:
    from newpkg_logger import NewpkgLogger
except Exception:
    NewpkgLogger = None

# fallback stdlib logger
import logging
_logger = logging.getLogger("newpkg.db")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.db: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


@dataclass
class DBPackage:
    id: int
    name: str
    version: Optional[str]
    meta: Dict[str, Any]


class NewpkgDB:
    DEFAULT_DB_DIR = "/var/lib/newpkg"
    DEFAULT_DB_NAME = "newpkg.db"
    DEFAULT_TIMEOUT = 30.0

    def __init__(self, cfg: Any = None, db_path: Optional[Union[str, Path]] = None, timeout: float = DEFAULT_TIMEOUT):
        """
        Initialize NewpkgDB.

        If db_path is None, compute from config:
          cfg.get("core.db_dir") / (profile.active or "default") / DEFAULT_DB_NAME

        cfg can be result of init_config().
        """
        self.cfg = cfg or (init_config() if init_config else None)

        # logger integration
        self.logger = None
        if NewpkgLogger and self.cfg:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, None)
            except Exception:
                self.logger = None

        # compute DB path
        if db_path:
            self.db_path = Path(db_path)
        else:
            db_dir = None
            try:
                if self.cfg:
                    db_dir = self.cfg.get("core.db_dir", None)
            except Exception:
                db_dir = None
            if not db_dir:
                db_dir = self.DEFAULT_DB_DIR
            # support per-profile DBs
            profile = None
            try:
                if self.cfg:
                    profile = self.cfg.get("profile.active", None)
            except Exception:
                profile = None
            if profile:
                db_dir = str(Path(db_dir) / profile)
            self.db_path = Path(db_dir) / self.DEFAULT_DB_NAME

        # ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.timeout = timeout
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()

        # open/create DB
        self._open()
        # ensure schema
        self._ensure_schema()
        # apply pragma optimizations
        self._apply_pragmas()

    # ----------------- internal helpers -----------------
    def _log(self, level: str, event: str, msg: str = "", **meta) -> None:
        try:
            if self.logger:
                fn = getattr(self.logger, level.lower(), None)
                if fn:
                    fn(event, msg, **meta)
                    return
        except Exception:
            pass
        getattr(_logger, level.lower(), _logger.info)(f"{event}: {msg} - {meta}")

    def _open(self) -> None:
        with self._lock:
            if self._conn:
                return
            self._conn = sqlite3.connect(str(self.db_path), timeout=self.timeout, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._log("info", "db.open", f"Opened DB at {self.db_path}", path=str(self.db_path))

    def _apply_pragmas(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("PRAGMA journal_mode = WAL;")
                cur.execute("PRAGMA synchronous = NORMAL;")
                cur.execute("PRAGMA foreign_keys = ON;")
                cur.execute("PRAGMA temp_store = MEMORY;")
                self._conn.commit()
            except Exception as e:
                self._log("warning", "db.pragma.fail", "Failed to apply pragmas", error=str(e))
            finally:
                cur.close()

    def close(self) -> None:
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
                self._log("info", "db.close", "Closed DB connection")

    # ----------------- schema & migrations -----------------
    def _ensure_schema(self) -> None:
        """
        Ensure tables exist and run lightweight migrations.
        """
        with self.transaction():
            cur = self._conn.cursor()
            # meta table (schema version etc.)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """)
            # packages
            cur.execute("""
            CREATE TABLE IF NOT EXISTS packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                version TEXT,
                meta TEXT,
                installed_by TEXT,
                installed_at INTEGER
            );
            """)
            # files
            cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT,
                size INTEGER,
                UNIQUE(package_id, path),
                FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
            );
            """)
            # dependencies
            cur.execute("""
            CREATE TABLE IF NOT EXISTS deps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER NOT NULL,
                dep TEXT NOT NULL,
                dep_type TEXT DEFAULT 'runtime',
                FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
            );
            """)
            # phases (build/install steps)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS phases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER,
                phase TEXT,
                status TEXT,
                ts INTEGER,
                meta TEXT
            );
            """)
            # create useful indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_deps_dep ON deps(dep);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);")
            # set initial schema version if missing
            cur.execute("SELECT value FROM meta WHERE key = 'schema_version';")
            row = cur.fetchone()
            if not row:
                cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?);", ("1",))
            self._conn.commit()
            cur.close()
        # call migrations (idempotent)
        self.migrate()

    def migrate(self) -> None:
        """
        Apply incremental migrations if necessary. Keeps migrations idempotent.
        """
        with self.transaction():
            cur = self._conn.cursor()
            cur.execute("SELECT value FROM meta WHERE key = 'schema_version';")
            row = cur.fetchone()
            current = int(row[0]) if row else 1
            # example migration path; expand as needed in future
            if current < 2:
                # migration example: add installed_by column if missing (handled already)
                try:
                    cur.execute("ALTER TABLE packages ADD COLUMN installed_by TEXT;")
                except Exception:
                    pass
                cur.execute("UPDATE meta SET value = ? WHERE key = 'schema_version';", ("2",))
                current = 2
            # future migrations would be chained here
            cur.close()

    # ----------------- transaction context manager -----------------
    def transaction(self):
        """
        Usage:
          with db.transaction():
              db.do_xxx()
        """
        self._lock.acquire()
        conn = self._conn
        class Tx:
            def __enter__(tx_self):
                return conn
            def __exit__(tx_self, exc_type, exc, tb):
                try:
                    if exc_type:
                        conn.rollback()
                    else:
                        conn.commit()
                finally:
                    self._lock.release()
                return False
        return Tx()

    # ----------------- package & file operations -----------------
    def list_packages(self) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT id, name, version, meta, installed_by, installed_at FROM packages ORDER BY name;")
            rows = cur.fetchall()
            cur.close()
            out = []
            for r in rows:
                meta = {}
                try:
                    meta = json.loads(r["meta"]) if r["meta"] else {}
                except Exception:
                    meta = {}
                out.append({"id": r["id"], "name": r["name"], "version": r["version"], "meta": meta, "installed_by": r["installed_by"], "installed_at": r["installed_at"]})
            return out

    def get_pkg_meta(self, pkg_name: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT id, name, version, meta FROM packages WHERE name = ?;", (pkg_name,))
            row = cur.fetchone()
            cur.close()
            if not row:
                return None
            try:
                meta = json.loads(row["meta"]) if row["meta"] else {}
            except Exception:
                meta = {}
            return {"id": row["id"], "name": row["name"], "version": row["version"], "meta": meta}

    def record_package(self, name: str, version: Optional[str] = None, meta: Optional[Dict[str, Any]] = None, installed_by: Optional[str] = None) -> int:
        """
        Insert or update package. Returns package_id.
        """
        meta_json = json.dumps(meta or {}, ensure_ascii=False)
        with self.transaction():
            cur = self._conn.cursor()
            cur.execute("INSERT OR IGNORE INTO packages(name, version, meta, installed_by, installed_at) VALUES(?, ?, ?, ?, ?);",
                        (name, version, meta_json, installed_by, int(time.time())))
            cur.execute("UPDATE packages SET version = ?, meta = ?, installed_by = ?, installed_at = ? WHERE name = ?;",
                        (version, meta_json, installed_by, int(time.time()), name))
            cur.execute("SELECT id FROM packages WHERE name = ?;", (name,))
            row = cur.fetchone()
            pid = row["id"]
            cur.close()
        self._log("info", "db.package.record", f"Recorded package {name}", package=name, id=pid)
        return int(pid)

    def update_package_version(self, name: str, version: str) -> bool:
        with self.transaction():
            cur = self._conn.cursor()
            cur.execute("UPDATE packages SET version = ?, installed_at = ? WHERE name = ?;", (version, int(time.time()), name))
            changed = cur.rowcount > 0
            cur.close()
        return changed

    def remove_package(self, name: str) -> bool:
        with self.transaction():
            cur = self._conn.cursor()
            cur.execute("DELETE FROM packages WHERE name = ?;", (name,))
            deleted = cur.rowcount > 0
            cur.close()
        if deleted:
            self._log("info", "db.package.remove", f"Removed package {name}", package=name)
        return deleted

    def record_file(self, package_name: str, file_path: str, sha256sum: Optional[str] = None, size: Optional[int] = None) -> Optional[int]:
        """
        Record a file for a package. Avoid duplication (INSERT OR IGNORE).
        Returns file id or None.
        """
        with self.transaction():
            cur = self._conn.cursor()
            # ensure package exists
            cur.execute("SELECT id FROM packages WHERE name = ?;", (package_name,))
            row = cur.fetchone()
            if not row:
                pid = self.record_package(package_name)
            else:
                pid = row["id"]
            # upsert file record
            cur.execute("INSERT OR IGNORE INTO files(package_id, path, sha256, size) VALUES(?, ?, ?, ?);", (pid, file_path, sha256sum, size))
            # if record existed but new sha/size provided, update it
            cur.execute("UPDATE files SET sha256 = ?, size = ? WHERE package_id = ? AND path = ? AND (sha256 IS NULL OR sha256 != ? OR size IS NULL OR size != ?);",
                        (sha256sum, size, pid, file_path, sha256sum, size))
            cur.execute("SELECT id FROM files WHERE package_id = ? AND path = ?;", (pid, file_path))
            r = cur.fetchone()
            fid = int(r["id"]) if r else None
            cur.close()
        return fid

    def list_files(self, package_name: str) -> List[str]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT f.path FROM files f JOIN packages p ON f.package_id = p.id WHERE p.name = ? ORDER BY f.path;", (package_name,))
            rows = cur.fetchall()
            cur.close()
            return [r["path"] for r in rows]

    def get_all_files(self) -> List[Tuple[str, str]]:
        """
        Returns list of tuples (package_name, file_path)
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT p.name as pkg, f.path as path FROM files f JOIN packages p ON f.package_id = p.id ORDER BY p.name;")
            rows = cur.fetchall()
            cur.close()
            return [(r["pkg"], r["path"]) for r in rows]

    # ----------------- dependency handling -----------------
    def add_dep(self, package_name: str, dep_name: str, dep_type: str = "runtime") -> bool:
        with self.transaction():
            cur = self._conn.cursor()
            cur.execute("SELECT id FROM packages WHERE name = ?;", (package_name,))
            row = cur.fetchone()
            if not row:
                pid = self.record_package(package_name)
            else:
                pid = row["id"]
            # avoid dupes
            cur.execute("INSERT OR IGNORE INTO deps(package_id, dep, dep_type) VALUES(?, ?, ?);", (pid, dep_name, dep_type))
            cur.close()
        return True

    def get_deps(self, package_name: str, dep_type: Optional[str] = None) -> List[str]:
        with self._lock:
            cur = self._conn.cursor()
            if dep_type:
                cur.execute("SELECT dep FROM deps d JOIN packages p ON d.package_id = p.id WHERE p.name = ? AND d.dep_type = ?;", (package_name, dep_type))
            else:
                cur.execute("SELECT dep FROM deps d JOIN packages p ON d.package_id = p.id WHERE p.name = ?;", (package_name,))
            rows = cur.fetchall()
            cur.close()
            return [r["dep"] for r in rows]

    def get_reverse_deps(self, package_name: str) -> List[str]:
        """
        Return list of package names that depend on package_name.
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
            SELECT p2.name as pkg FROM deps d
            JOIN packages p1 ON d.package_id = p1.id
            JOIN packages p2 ON p2.id = d.package_id
            WHERE d.dep = ?;
            """, (package_name,))
            rows = cur.fetchall()
            cur.close()
            # The above query is generic but may need adjustment; fallback simple:
            # Instead, fetch p names where any dep == package_name
            with self._lock:
                cur2 = self._conn.cursor()
                cur2.execute("SELECT p.name FROM packages p JOIN deps d ON p.id = d.package_id WHERE d.dep = ?;", (package_name,))
                rows2 = cur2.fetchall()
                cur2.close()
                return [r["name"] for r in rows2]

    # ----------------- phases & events -----------------
    def record_phase(self, package: Optional[str], phase: str, status: str, meta: Optional[Dict[str, Any]] = None) -> None:
        with self.transaction():
            cur = self._conn.cursor()
            pkg_id = None
            if package:
                cur.execute("SELECT id FROM packages WHERE name = ?;", (package,))
                r = cur.fetchone()
                if r:
                    pkg_id = r["id"]
            meta_json = json.dumps(meta or {}, ensure_ascii=False)
            cur.execute("INSERT INTO phases(package_id, phase, status, ts, meta) VALUES(?, ?, ?, ?, ?);", (pkg_id, phase, status, int(time.time()), meta_json))
            cur.close()
        self._log("info", "db.phase.record", f"Phase recorded: {phase} {status}", package=package, phase=phase, status=status)

    def record_event(self, event: str, ts: Optional[int] = None, meta: Optional[Dict[str, Any]] = None) -> None:
        # store events in meta table as a simple append (keyed by timestamp) or use phases table
        t = int(ts or time.time())
        entry = {"ts": t, "event": event, "meta": meta or {}}
        # store in meta as JSON array under 'events' (simple approach)
        with self.transaction():
            cur = self._conn.cursor()
            cur.execute("SELECT value FROM meta WHERE key = 'events';")
            row = cur.fetchone()
            events = []
            if row and row["value"]:
                try:
                    events = json.loads(row["value"])
                except Exception:
                    events = []
            events.append(entry)
            cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('events', ?);", (json.dumps(events, ensure_ascii=False),))
            cur.close()
        self._log("debug", "db.event.record", f"Event recorded: {event}", event=event)

    # ----------------- integrity verification -----------------
    def _sha256(self, path: Union[str, Path]) -> Optional[str]:
        try:
            h = sha256()
            with open(str(path), "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def verify_integrity(self, packages: Optional[List[str]] = None, parallel: bool = True, workers: Optional[int] = None) -> Dict[str, Any]:
        """
        Verify recorded files' hashes and sizes.
        Returns a dict with keys: 'checked', 'mismatches' (list), 'missing' (list).
        Parallelizable.
        """
        items = []
        if packages:
            for pkg in packages:
                for f in self.list_files(pkg):
                    items.append((pkg, f))
        else:
            items = self.get_all_files()

        mismatches = []
        missing = []
        checked = 0

        def _check(item):
            pkg, fpath = item
            checked_local = 0
            try:
                if not os.path.exists(fpath):
                    return ("missing", pkg, fpath, None, None)
                calc = self._sha256(fpath)
                with self._lock:
                    cur = self._conn.cursor()
                    cur.execute("SELECT sha256, size FROM files f JOIN packages p ON f.package_id = p.id WHERE p.name = ? AND f.path = ?;", (pkg, fpath))
                    r = cur.fetchone()
                    cur.close()
                expected = r["sha256"] if r else None
                size_expected = r["size"] if r else None
                size_actual = os.path.getsize(fpath) if os.path.exists(fpath) else None
                if expected and calc and expected != calc:
                    return ("mismatch", pkg, fpath, expected, calc)
                if size_expected is not None and size_actual is not None and int(size_expected) != int(size_actual):
                    return ("size_mismatch", pkg, fpath, size_expected, size_actual)
                return ("ok", pkg, fpath, expected, calc)
            except Exception as e:
                return ("error", pkg, fpath, None, str(e))

        if parallel:
            max_workers = workers or min(8, (os.cpu_count() or 1) * 2)
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_check, itm): itm for itm in items}
                for fut in as_completed(futures):
                    res = fut.result()
                    checked += 1
                    if res[0] == "ok":
                        continue
                    elif res[0] == "missing":
                        missing.append({"package": res[1], "path": res[2]})
                    elif res[0] in ("mismatch", "size_mismatch"):
                        mismatches.append({"type": res[0], "package": res[1], "path": res[2], "expected": res[3], "actual": res[4]})
                    else:
                        mismatches.append({"type": "error", "package": res[1], "path": res[2], "error": res[4]})
        else:
            for itm in items:
                res = _check(itm)
                checked += 1
                if res[0] == "ok":
                    continue
                elif res[0] == "missing":
                    missing.append({"package": res[1], "path": res[2]})
                else:
                    mismatches.append({"type": res[0], "package": res[1], "path": res[2], "expected": res[3], "actual": res[4]})

        out = {"checked": checked, "missing": missing, "mismatches": mismatches}
        self._log("info", "db.verify.done", f"Integrity verify done: checked={checked}, missing={len(missing)}, mismatches={len(mismatches)}")
        return out

    # ----------------- cleanup / maintenance -----------------
    def cleanup_orphans(self, dry_run: bool = True) -> List[str]:
        """
        Remove packages that have no reverse-deps and are not protected.
        Returns list of removed package names (or would-be removed in dry_run).
        """
        protected = set(self.cfg.get("audit.protected_packages", ["glibc", "linux-firmware", "base"]) if self.cfg else ["glibc", "linux-firmware", "base"])
        removed = []
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT name FROM packages;")
            all_pkgs = [r["name"] for r in cur.fetchall()]
            for pkg in all_pkgs:
                if pkg in protected:
                    continue
                cur.execute("SELECT 1 FROM deps WHERE dep = ? LIMIT 1;", (pkg,))
                rev = cur.fetchone()
                if not rev:
                    # orphan candidate
                    if dry_run:
                        removed.append(pkg)
                    else:
                        cur.execute("DELETE FROM packages WHERE name = ?;", (pkg,))
                        removed.append(pkg)
            cur.close()
        self._log("info", "db.cleanup_orphans", f"Orphans: {len(removed)}", removed=removed, dry_run=dry_run)
        return removed

    # ----------------- backup / export -----------------
    def backup_db(self, out_dir: Optional[Union[str, Path]] = None, include_files: str = "recorded", compress: bool = True) -> Optional[str]:
        """
        Create a backup tar (optionally xz) containing the DB and optionally recorded files.
        include_files: 'recorded' => only files in DB; 'all' => include entire filesystem paths stored (dangerous)
        Returns path to archive or None on failure.
        """
        out_dir = Path(out_dir) if out_dir else Path(self.cfg.get("core.backup_dir", "/var/log/newpkg/backups") if self.cfg else "/var/log/newpkg/backups")
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = int(time.time())
        base_name = f"newpkg-backup-{ts}"
        ext = ".tar.xz" if compress else ".tar"
        out_path = out_dir / (base_name + ext)
        try:
            tmpfd, tmpname = tempfile.mkstemp(dir=str(out_dir), prefix=base_name)
            os.close(tmpfd)
            mode = "w:xz" if compress else "w"
            with tarfile.open(tmpname, mode) as tar:
                # add DB file
                try:
                    tar.add(str(self.db_path), arcname=f"db/{Path(self.db_path).name}")
                except Exception:
                    pass
                if include_files in ("recorded", "all"):
                    files = []
                    if include_files == "recorded":
                        files = self.get_all_files()
                        # files is list of (pkg, path)
                        for pkg, path in files:
                            try:
                                if os.path.exists(path):
                                    tar.add(path, arcname=f"files/{pkg}/{os.path.relpath(path, '/')}")
                            except Exception:
                                continue
                    else:
                        # 'all' - add entire root? very dangerous; instead add common system dirs listed in config
                        sys_paths = self.cfg.get("backup.include_paths", []) if self.cfg else []
                        for p in sys_paths:
                            try:
                                if os.path.exists(p):
                                    tar.add(p, arcname=f"sys/{os.path.basename(p)}")
                            except Exception:
                                continue
                # optionally include config sources
                try:
                    if self.cfg and getattr(self.cfg, "sources", None):
                        for s in (self.cfg.sources or []):
                            try:
                                if os.path.exists(s):
                                    tar.add(s, arcname=f"config/{Path(s).name}")
                            except Exception:
                                continue
                except Exception:
                    pass
            # move tmp to final
            os.replace(tmpname, str(out_path))
            self._log("info", "db.backup.ok", f"Backup written to {out_path}", path=str(out_path))
            return str(out_path)
        except Exception as e:
            self._log("error", "db.backup.fail", f"Backup failed: {e}", error=str(e))
            try:
                if os.path.exists(tmpname):
                    os.unlink(tmpname)
            except Exception:
                pass
            return None

    def export_packages_json(self, out_path: Optional[Union[str, Path]] = None) -> str:
        """
        Dumps package metadata and file lists to JSON. Returns path to JSON file.
        """
        if not out_path:
            out_path = Path(self.cfg.get("cli.report_dir", "/var/log/newpkg/cli")) / f"packages-{int(time.time())}.json"
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        data = []
        for pkg in self.list_packages():
            files = self.list_files(pkg["name"])
            data.append({"name": pkg["name"], "version": pkg["version"], "meta": pkg["meta"], "files": files})
        out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        self._log("info", "db.export.ok", f"Exported packages JSON to {out_path}", path=str(out_path))
        return str(out_path)

    # ----------------- convenience / util -----------------
    def find_package_by_file(self, path: str) -> Optional[str]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT p.name FROM packages p JOIN files f ON f.package_id = p.id WHERE f.path = ? LIMIT 1;", (path,))
            row = cur.fetchone()
            cur.close()
            return row["name"] if row else None

    # ----------------- finalize -----------------
    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

# End of newpkg_db.py
