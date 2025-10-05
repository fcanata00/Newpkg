#!/usr/bin/env python3
# newpkg_db.py
"""
NewpkgDB — sqlite-backed package database for the newpkg ecosystem.

Key features in this revision:
 - Reads DB path from newpkg_config (db.path) and respects general.dry_run
 - Uses sqlite3.connect(..., check_same_thread=False) for thread-friendly access
 - Optional integration with newpkg_logger (structured events)
 - Schema creation with schema_version stored in meta table
 - Context manager transaction() for safe commits/rollbacks
 - record_file includes optional sha256 and size, used by verify_integrity()
 - verify_integrity() checks file existence and sha256 if present
 - backup_db() creates compressed tar.xz backup of DB file and recorded files list
 - export_packages_json() returns exported JSON and ensures DB connection is closed
 - migrate() placeholder to apply schema migrations
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import time
import hashlib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# optional project imports
try:
    from newpkg_config import init_config
except Exception:
    init_config = None

try:
    from newpkg_logger import NewpkgLogger
except Exception:
    NewpkgLogger = None

# module-level logger fallback (standard logging) — used if no NewpkgLogger provided
import logging
_logger = logging.getLogger("newpkg.db")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.db: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


def _sha256_of_path(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class DBRecord:
    name: str
    version: Optional[str] = None
    category: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class NewpkgDB:
    DEFAULT_DB_PATH = "/var/lib/newpkg/newpkg.db"

    def __init__(self, cfg: Any = None, logger: Any = None):
        """
        Initialize NewpkgDB.

        - cfg: optional ConfigStore (init_config())
        - logger: optional NewpkgLogger-compatible instance
        """
        self.cfg = cfg or (init_config() if init_config else None)
        self.logger = None
        if logger:
            self.logger = logger
        else:
            # if project NewpkgLogger exists and cfg provided, try to instantiate
            if NewpkgLogger and self.cfg is not None:
                try:
                    self.logger = NewpkgLogger.from_config(self.cfg, self)
                except Exception:
                    self.logger = None

        self._log = self._make_logger()
        # determine db path; if dry_run requested, use in-memory database
        dry_run = bool(self._cfg_get("general.dry_run", False))
        dbpath = self._cfg_get("db.path", None) or self.DEFAULT_DB_PATH
        if dry_run:
            self._in_memory = True
            self.db_path = ":memory:"
        else:
            self._in_memory = False
            self.db_path = os.path.expanduser(str(dbpath))
            # ensure parent dir exists
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        # connect (allow multithreaded access)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _make_logger(self):
        def _fn(level: str, event: str, message: str = "", **meta):
            try:
                if self.logger:
                    fn = getattr(self.logger, level.lower(), None)
                    if fn:
                        fn(event, message, **meta)
                        return
            except Exception:
                pass
            getattr(_logger, level.lower(), _logger.info)(f"{event}: {message} - {meta}")
        return _fn

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        # fallback to environment variables
        return os.environ.get(key.upper().replace(".", "_"), default)

    # ----------------- schema -----------------
    def _init_db(self):
        cur = self.conn.cursor()
        # PRAGMA to improve concurrency and durability choices
        try:
            cur.execute("PRAGMA journal_mode = WAL;")
            cur.execute("PRAGMA synchronous = NORMAL;")
        except Exception:
            pass

        # Create tables if not exist
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                version TEXT,
                category TEXT,
                metadata TEXT,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            );
            CREATE UNIQUE INDEX IF NOT EXISTS packages_name_idx ON packages(name);
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER,
                path TEXT,
                sha256 TEXT,
                size INTEGER,
                recorded_at INTEGER DEFAULT (strftime('%s','now')),
                FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS deps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER,
                dep TEXT,
                dep_type TEXT,
                FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS phases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package TEXT,
                phase TEXT,
                status TEXT,
                meta TEXT,
                ts INTEGER DEFAULT (strftime('%s','now'))
            );
            """
        )
        # ensure schema_version present
        sv = self.get_meta("schema_version")
        if sv is None:
            self.set_meta("schema_version", "1")
        self._log("info", "db.init", f"DB initialized at {self.db_path}", db_path=self.db_path)

    # ----------------- meta helpers -----------------
    def set_meta(self, key: str, value: str):
        cur = self.conn.cursor()
        cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?);", (key, value))
        self._log("debug", "db.meta.set", f"Set meta {key}", key=key, value=value)

    def get_meta(self, key: str) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT value FROM meta WHERE key = ?;", (key,))
        r = cur.fetchone()
        return r["value"] if r else None

    # ----------------- transactions -----------------
    @contextmanager
    def transaction(self):
        """
        Context manager for transactions:
            with db.transaction():
                db.add_package(...)
        """
        cur = self.conn.cursor()
        try:
            cur.execute("BEGIN;")
            yield
            cur.execute("COMMIT;")
        except Exception as e:
            try:
                cur.execute("ROLLBACK;")
            except Exception:
                pass
            self._log("error", "db.tx.fail", f"Transaction failed: {e}", error=str(e))
            raise

    # ----------------- package APIs -----------------
    def add_package(self, name: str, version: Optional[str] = None, category: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> int:
        """
        Add or update a package entry. Returns package_id.
        """
        meta_json = json.dumps(metadata or {})
        cur = self.conn.cursor()
        cur.execute("INSERT OR REPLACE INTO packages(name, version, category, metadata) VALUES(?, ?, ?, ?);", (name, version, category, meta_json))
        # fetch id
        cur.execute("SELECT id FROM packages WHERE name = ?;", (name,))
        r = cur.fetchone()
        pid = r["id"] if r else None
        self._log("info", "db.pkg.add", f"Added/updated package {name}", package=name, version=version, package_id=pid)
        return pid

    def get_package(self, name: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM packages WHERE name = ?;", (name,))
        r = cur.fetchone()
        if not r:
            return None
        return {
            "id": r["id"],
            "name": r["name"],
            "version": r["version"],
            "category": r["category"],
            "metadata": json.loads(r["metadata"] or "{}"),
            "created_at": r["created_at"],
        }

    def list_packages(self) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT name, version, category, created_at FROM packages ORDER BY name;")
        out = []
        for r in cur.fetchall():
            out.append({"name": r["name"], "version": r["version"], "category": r["category"], "created_at": r["created_at"]})
        return out

    def update_package(self, name: str, **fields) -> bool:
        allowed = {"version", "category", "metadata"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return False
        cur = self.conn.cursor()
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values())
        values.append(name)
        cur.execute(f"UPDATE packages SET {set_clause} WHERE name = ?;", values)
        self._log("info", "db.pkg.update", f"Updated package {name}", package=name, updates=updates)
        return True

    # ----------------- files / deps -----------------
    def record_file(self, package_name: str, file_path: str, sha256: Optional[str] = None):
        """
        Record a file path for a package. If package doesn't exist, create it.
        """
        pid = self.add_package(package_name) or self._package_id(package_name)
        cur = self.conn.cursor()
        try:
            size = os.path.getsize(file_path) if os.path.exists(file_path) else None
        except Exception:
            size = None
        cur.execute("INSERT INTO files(package_id, path, sha256, size) VALUES(?, ?, ?, ?);", (pid, file_path, sha256, size))
        self._log("debug", "db.file.record", f"Recorded file {file_path} for {package_name}", package=package_name, path=file_path, sha256=sha256)

    def list_files(self, package_name: str) -> List[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT f.path FROM files f JOIN packages p ON f.package_id = p.id WHERE p.name = ?;", (package_name,))
        return [r["path"] for r in cur.fetchall()]

    def _package_id(self, package_name: str) -> Optional[int]:
        cur = self.conn.cursor()
        cur.execute("SELECT id FROM packages WHERE name = ?;", (package_name,))
        r = cur.fetchone()
        return r["id"] if r else None

    def add_dep(self, package_name: str, dep: str, dep_type: str = "runtime"):
        pid = self._package_id(package_name) or self.add_package(package_name)
        cur = self.conn.cursor()
        cur.execute("INSERT INTO deps(package_id, dep, dep_type) VALUES(?, ?, ?);", (pid, dep, dep_type))
        self._log("debug", "db.dep.add", f"Added dep {dep} for {package_name}", package=package_name, dep=dep, dep_type=dep_type)

    def get_deps(self, package_name: str) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT d.dep, d.dep_type FROM deps d JOIN packages p ON d.package_id = p.id WHERE p.name = ?;", (package_name,))
        return [{"dep": r["dep"], "type": r["dep_type"]} for r in cur.fetchall()]

    # ----------------- phases / lifecycle -----------------
    def record_phase(self, package: str, phase: str, status: str, meta: Optional[Dict[str, Any]] = None):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO phases(package, phase, status, meta) VALUES(?, ?, ?, ?);", (package, phase, status, json.dumps(meta or {})))
        self._log("info", "db.phase", f"Phase recorded for {package}: {phase}={status}", package=package, phase=phase, status=status)

    def list_phases(self, package: str) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT phase, status, meta, ts FROM phases WHERE package = ? ORDER BY ts;", (package,))
        out = []
        for r in cur.fetchall():
            out.append({"phase": r["phase"], "status": r["status"], "meta": json.loads(r["meta"] or "{}"), "ts": r["ts"]})
        return out

    # ----------------- verification / integrity -----------------
    def verify_integrity(self, package_name: str) -> Dict[str, Any]:
        """
        Verify files recorded for package. If sha256 present, check hash; otherwise check existence.
        Returns dict { ok: bool, details: [ ... ] }
        """
        files = []
        cur = self.conn.cursor()
        cur.execute("SELECT f.path, f.sha256 FROM files f JOIN packages p ON f.package_id = p.id WHERE p.name = ?;", (package_name,))
        ok = True
        details = []
        for r in cur.fetchall():
            path = r["path"]
            expected = r["sha256"]
            if not path or not os.path.exists(path):
                ok = False
                details.append({"path": path, "status": "missing"})
                continue
            if expected:
                try:
                    got = _sha256_of_path(path)
                    if got != expected:
                        ok = False
                        details.append({"path": path, "status": "checksum-mismatch", "expected": expected, "got": got})
                    else:
                        details.append({"path": path, "status": "ok"})
                except Exception as e:
                    ok = False
                    details.append({"path": path, "status": "error", "error": str(e)})
            else:
                details.append({"path": path, "status": "exists"})
        return {"ok": ok, "details": details}

    # ----------------- backup / export -----------------
    def backup_db(self, output_dir: Optional[str] = None, include_files: bool = True) -> str:
        """
        Create a compressed tar.xz backup containing:
         - the sqlite DB file (if persisted)
         - optionally files recorded for packages (best-effort)
        Returns path to archive.
        """
        if self._in_memory:
            raise RuntimeError("Cannot backup in-memory (dry_run) database")
        out_dir = Path(output_dir or tempfile.gettempdir())
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        out = out_dir / f"newpkg-db-backup-{ts}.tar.xz"
        with tarfile.open(out, "w:xz") as tar:
            # add DB file
            try:
                tar.add(self.db_path, arcname=Path(self.db_path).name)
            except Exception as e:
                self._log("warning", "db.backup.db_add_fail", f"Failed adding db file: {e}", error=str(e))
            if include_files:
                # iterate recorded files and add if present
                cur = self.conn.cursor()
                cur.execute("SELECT DISTINCT f.path FROM files f;")
                for r in cur.fetchall():
                    p = r["path"]
                    try:
                        if p and os.path.exists(p):
                            tar.add(p, arcname=os.path.join("files", os.path.relpath(p, "/")))
                    except Exception:
                        continue
        self._log("info", "db.backup.ok", f"Backup written to {out}", path=str(out))
        return str(out)

    def export_packages_json(self, dest: Optional[str] = None) -> str:
        """
        Export packages and files to JSON file; close the connection afterwards.
        Returns path to exported file.
        """
        out = dest or os.path.join(tempfile.gettempdir(), "newpkg_export.json")
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM packages;")
        pkgs = []
        for r in cur.fetchall():
            pid = r["id"]
            cur2 = self.conn.cursor()
            cur2.execute("SELECT path, sha256, size FROM files WHERE package_id = ?;", (pid,))
            files = [{"path": f["path"], "sha256": f["sha256"], "size": f["size"]} for f in cur2.fetchall()]
            pkgs.append({
                "name": r["name"],
                "version": r["version"],
                "category": r["category"],
                "metadata": json.loads(r["metadata"] or "{}"),
                "files": files,
                "created_at": r["created_at"],
            })
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(pkgs, fh, indent=2)
        self._log("info", "db.export", f"Exported packages to {out}", path=out)
        # close DB to ensure resources freed
        try:
            self.close()
        except Exception:
            pass
        return out

    # ----------------- migration placeholder -----------------
    def migrate(self):
        """
        Placeholder to apply schema migrations. Reads meta.schema_version and upgrades to latest (if needed).
        Implement schema changes here as required.
        """
        sv = int(self.get_meta("schema_version") or 1)
        latest = 1  # bump as migrations are added
        if sv < latest:
            self._log("info", "db.migrate", f"Migrating schema {sv} -> {latest}")
            # example migration steps (execute safe DDL here)
            # cur = self.conn.cursor()
            # cur.executescript("ALTER TABLE ...;")
            self.set_meta("schema_version", str(latest))
            self._log("info", "db.migrate.ok", f"Migration complete to {latest}")

    # ----------------- utils -----------------
    def close(self):
        try:
            if self.conn:
                self.conn.close()
                self.conn = None
                self._log("info", "db.close", "Database connection closed")
        except Exception as e:
            self._log("warning", "db.close.fail", f"Close failed: {e}", error=str(e))

# if executed directly, do a small demo (non-invasive)
if __name__ == "__main__":
    cfg = init_config() if init_config else None
    db = NewpkgDB(cfg=cfg)
    db.add_package("example", version="1.0", category="demo", metadata={"desc": "demo pkg"})
    db.record_file("example", "/usr/lib/example/libexample.so", sha256=None)
    print("Packages:", db.list_packages())
    print("Files:", db.list_files("example"))
    print("Verify:", db.verify_integrity("example"))
    # create backup (if not dry-run)
    if not db._in_memory:
        print("Backup:", db.backup_db())
    print("Export:", db.export_packages_json())
