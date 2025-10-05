#!/usr/bin/env python3
"""
newpkg_db.py

SQLite-backed database layer for newpkg.

Features:
 - safe initialization (init_db), migrations placeholder
 - context-managed transactions
 - add_package / update_package_status / mark_installed
 - record_file, get_files, get_all_files
 - add_log, get_logs, record_phase, record_hook
 - get_deps, get_reverse_deps
 - connect_readonly for audit use (SQLite URI mode)
 - verify_integrity (basic placeholder checking registered file existence)
 - backup() helper to create a tar.xz of DB file
 - robust path resolution reading config keys compatible with ConfigStore
"""
from __future__ import annotations

import os
import sqlite3
import json
import shutil
import tarfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

DB_DEFAULT_PATH = '/var/lib/newpkg/newpkg.db'


class NewpkgDBError(Exception):
    pass


class NewpkgDB:
    def __init__(self, cfg: Any = None, db_path: Optional[str] = None):
        """
        cfg: optional ConfigStore instance
        db_path: optional explicit path (overrides cfg)
        """
        self.cfg = cfg
        self._conn: Optional[sqlite3.Connection] = None
        self._db_path = db_path or self._resolve_db_path()
        self._cache_package_id: Dict[str, int] = {}

    # ---------------- path resolution ----------------
    def _resolve_db_path(self) -> str:
        # Order of preference:
        #  - explicit env NEWPKG_DB_PATH
        #  - cfg.get('general.db_path') or cfg.get('db.path')
        #  - DB_DEFAULT_PATH
        env = os.environ.get('NEWPKG_DB_PATH')
        if env:
            return str(Path(env).expanduser())
        if self.cfg:
            try:
                p = self.cfg.get('general.db_path')
                if p:
                    return str(Path(p).expanduser())
            except Exception:
                pass
            try:
                p = self.cfg.get('db.path')
                if p:
                    return str(Path(p).expanduser())
            except Exception:
                pass
            try:
                p = self.cfg.get('DB_PATH')
                if p:
                    return str(Path(p).expanduser())
            except Exception:
                pass
        # fallback
        return DB_DEFAULT_PATH

    # ---------------- connect / close ----------------
    def connect(self) -> sqlite3.Connection:
        if self._conn:
            return self._conn
        dbp = Path(self._db_path)
        dbp.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(dbp), detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        conn.row_factory = sqlite3.Row
        # pragmatic pragmas for WAL journaling
        try:
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA synchronous=NORMAL;')
        except Exception:
            pass
        self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def connect_readonly(self) -> sqlite3.Connection:
        """
        Open the sqlite DB as readonly using URI mode.
        Useful for audits that must not obtain writer locks.
        """
        p = Path(self._db_path).expanduser().resolve()
        uri = f'file:{str(p)}?mode=ro'
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    # ---------------- transactions ----------------
    @contextmanager
    def transaction(self):
        conn = self.connect()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

    # ---------------- initialization / migration ----------------
    def init_db(self, force: bool = False) -> None:
        """
        Create required tables if they do not exist. If force=True, re-create schema (destructive).
        """
        conn = self.connect()
        cur = conn.cursor()
        if force:
            # backup prior to destructive change
            self.backup(suffix='.preinit.tar.xz')
            # drop existing tables (best-effort)
            for t in ('files', 'deps', 'packages', 'build_logs', 'meta'):
                try:
                    cur.execute(f'DROP TABLE IF EXISTS {t};')
                except Exception:
                    pass
            conn.commit()

        # create tables
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            version TEXT,
            origin TEXT,
            status TEXT,
            install_dir TEXT,
            installed_at TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_id INTEGER,
            path TEXT NOT NULL,
            size INTEGER,
            hash TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS deps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_id INTEGER,
            dep_name TEXT,
            dep_type TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS build_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_id INTEGER,
            phase TEXT,
            status TEXT,
            log_path TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """)
        conn.commit()
        cur.close()

    def migrate(self) -> None:
        """
        Placeholder for migrations. Implement needed DDL changes here in future.
        """
        # In production you would inspect schema_version key and apply migrations.
        pass

    # ---------------- backup ----------------
    def backup(self, out_dir: Optional[str] = None, suffix: str = '.tar.xz') -> Optional[str]:
        """
        Create a compressed archive of the DB file.
        Returns path to archive or None if failed.
        """
        try:
            dbp = Path(self._db_path)
            if not dbp.exists():
                return None
            out_dir = out_dir or str(dbp.parent)
            out_dir_p = Path(out_dir)
            out_dir_p.mkdir(parents=True, exist_ok=True)
            ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
            archive_name = f'newpkg_db_backup_{ts}{suffix}'
            outpath = out_dir_p / archive_name
            with tarfile.open(outpath, 'w:xz') as tar:
                tar.add(str(dbp), arcname=dbp.name)
            return str(outpath)
        except Exception:
            return None

    # ---------------- helpers: package id caching ----------------
    def _get_package_id(self, name: str) -> Optional[int]:
        if name in self._cache_package_id:
            return self._cache_package_id[name]
        with self.transaction() as cur:
            cur.execute('SELECT id FROM packages WHERE name = ?;', (name,))
            row = cur.fetchone()
            if row:
                pid = int(row['id'])
                self._cache_package_id[name] = pid
                return pid
        return None

    # ---------------- package CRUD ----------------
    def add_package(self, name: str, version: Optional[str] = None, origin: Optional[str] = None,
                    status: str = 'staged') -> int:
        """
        Adds a package entry or updates existing one.
        Returns package_id.
        """
        pid = self._get_package_id(name)
        now = datetime.utcnow().isoformat() + 'Z'
        if pid:
            with self.transaction() as cur:
                cur.execute('UPDATE packages SET version=?, origin=?, status=? WHERE id=?;', (version, origin, status, pid))
            return pid
        with self.transaction() as cur:
            cur.execute('INSERT INTO packages (name, version, origin, status, created_at) VALUES (?, ?, ?, ?, ?);',
                        (name, version, origin, status, now))
            pid = cur.lastrowid
            self._cache_package_id[name] = pid
            return pid

    def get_package(self, name: str) -> Optional[Dict[str, Any]]:
        pid = self._get_package_id(name)
        if not pid:
            return None
        with self.transaction() as cur:
            cur.execute('SELECT * FROM packages WHERE id = ?;', (pid,))
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def list_packages(self) -> List[Dict[str, Any]]:
        with self.transaction() as cur:
            cur.execute('SELECT * FROM packages ORDER BY name;')
            return [dict(r) for r in cur.fetchall()]

    def update_package_status(self, name: str, status: str, version: Optional[str] = None) -> None:
        pid = self.add_package(name, version=version, origin=None, status=status)
        with self.transaction() as cur:
            cur.execute('UPDATE packages SET status = ? WHERE id = ?;', (status, pid))

    def remove_package(self, name: str) -> None:
        pid = self._get_package_id(name)
        if not pid:
            return
        with self.transaction() as cur:
            cur.execute('DELETE FROM packages WHERE id = ?;', (pid,))
        # evict cache
        self._cache_package_id.pop(name, None)

    def mark_installed(self, name: str, install_dir: Optional[str] = None) -> None:
        """
        Mark package as installed, set install_dir and installed_at timestamp.
        """
        pid = self._get_package_id(name)
        if not pid:
            # create package if missing
            pid = self.add_package(name, version=None, origin=None, status='installed')
        now = datetime.utcnow().isoformat() + 'Z'
        with self.transaction() as cur:
            cur.execute('UPDATE packages SET status = ?, install_dir = ?, installed_at = ? WHERE id = ?;',
                        ('installed', install_dir, now, pid))

    # ---------------- files ----------------
    def record_file(self, package_name: str, path: str, size: Optional[int] = None, hash: Optional[str] = None) -> int:
        pid = self._get_package_id(package_name)
        if not pid:
            pid = self.add_package(package_name, version=None, origin=None, status='installed')
        with self.transaction() as cur:
            cur.execute('INSERT INTO files (package_id, path, size, hash) VALUES (?, ?, ?, ?);', (pid, path, size, hash))
            return cur.lastrowid

    def get_files(self, package_name: str) -> List[Dict[str, Any]]:
        pid = self._get_package_id(package_name)
        if not pid:
            return []
        with self.transaction() as cur:
            cur.execute('SELECT path, size, hash, created_at FROM files WHERE package_id = ?;', (pid,))
            return [dict(r) for r in cur.fetchall()]

    def get_all_files(self) -> List[Dict[str, Any]]:
        """
        Return all files registered in DB together with package name.
        Useful for audit scanning.
        """
        with self.transaction() as cur:
            cur.execute('''
                SELECT f.path as path, f.size as size, f.hash as hash, p.name as package
                FROM files f
                LEFT JOIN packages p ON p.id = f.package_id;
            ''')
            return [dict(r) for r in cur.fetchall()]

    # ---------------- deps ----------------
    def add_dep(self, package_name: str, dep_name: str, dep_type: str = 'runtime') -> int:
        pid = self._get_package_id(package_name) or self.add_package(package_name)
        with self.transaction() as cur:
            cur.execute('INSERT INTO deps (package_id, dep_name, dep_type) VALUES (?, ?, ?);', (pid, dep_name, dep_type))
            return cur.lastrowid

    def get_deps(self, package_name: str) -> List[Dict[str, Any]]:
        pid = self._get_package_id(package_name)
        if not pid:
            return []
        with self.transaction() as cur:
            cur.execute('SELECT dep_name, dep_type FROM deps WHERE package_id = ?;', (pid,))
            return [dict(r) for r in cur.fetchall()]

    def get_reverse_deps(self, package_name: str) -> List[str]:
        """
        Return list of package names that depend on package_name.
        """
        with self.transaction() as cur:
            cur.execute('''
                SELECT p2.name AS depender
                FROM deps d
                JOIN packages p2 ON p2.id = d.package_id
                WHERE d.dep_name = ?
                GROUP BY p2.name;
            ''', (package_name,))
            return [r['depender'] for r in cur.fetchall()]

    # ---------------- logs / phases / hooks ----------------
    def add_log(self, package_name: str, phase: str, status: str, log_path: Optional[str] = None) -> int:
        pid = self._get_package_id(package_name)
        if not pid:
            pid = self.add_package(package_name, None, origin=None, status='unknown')
        with self.transaction() as cur:
            cur.execute('INSERT INTO build_logs (package_id, phase, status, log_path) VALUES (?, ?, ?, ?);',
                        (pid, phase, status, log_path))
            return cur.lastrowid

    def get_logs(self, package_name: str) -> List[Dict[str, Any]]:
        pid = self._get_package_id(package_name)
        if not pid:
            return []
        with self.transaction() as cur:
            cur.execute('SELECT phase, status, log_path, created_at FROM build_logs WHERE package_id = ? ORDER BY created_at DESC;', (pid,))
            return [dict(r) for r in cur.fetchall()]

    def record_phase(self, package_name: str, phase: str, status: str, log_path: Optional[str] = None) -> int:
        """
        Convenience wrapper to add build phase logs (configure/build/install).
        """
        return self.add_log(package_name, phase, status, log_path)

    def record_hook(self, package_name: str, hook_name: str, status: str) -> int:
        """
        Record the execution of a hook as a log entry.
        """
        return self.add_log(package_name, f'hook:{hook_name}', status, log_path=None)

    # ---------------- simple integrity / verification ----------------
    def verify_integrity(self, package_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Very light verification:
          - if package_name provided, check that files exist for that package and report missing.
          - if not provided, check all files and return summary.
        """
        results: Dict[str, Any] = {'checked': 0, 'missing': 0, 'missing_files': []}
        if package_name:
            files = self.get_files(package_name)
        else:
            files = self.get_all_files()
        for f in files:
            results['checked'] += 1
            path = f.get('path')
            if not path:
                continue
            if not Path(path).exists():
                results['missing'] += 1
                results['missing_files'].append({'path': path, 'package': f.get('package')})
        return results

    # ---------------- meta helpers ----------------
    def set_meta(self, key: str, value: Any) -> None:
        with self.transaction() as cur:
            cur.execute('REPLACE INTO meta (key, value) VALUES (?, ?);', (key, json.dumps(value)))

    def get_meta(self, key: str) -> Any:
        with self.transaction() as cur:
            cur.execute('SELECT value FROM meta WHERE key = ?;', (key,))
            row = cur.fetchone()
            if not row:
                return None
            try:
                return json.loads(row['value'])
            except Exception:
                return row['value']

    # ---------------- export / utilities ----------------
    def export_packages_json(self, path: str) -> None:
        data = {'packages': []}
        for p in self.list_packages():
            pkg = dict(p)
            pkg['files'] = self.get_files(pkg['name'])
            pkg['deps'] = self.get_deps(pkg['name'])
            pkg['logs'] = self.get_logs(pkg['name'])
            data['packages'].append(pkg)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data, indent=2), encoding='utf-8')

    # ---------------- cleanup ----------------
    def vacuum(self) -> None:
        conn = self.connect()
        try:
            conn.execute('VACUUM;')
            conn.commit()
        except Exception:
            pass

    # ---------------- destructor ----------------
    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# Basic CLI for quick tests
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(prog='newpkg-db')
    ap.add_argument('--init', action='store_true', help='initialize DB')
    ap.add_argument('--export', help='export packages to JSON')
    ap.add_argument('--verify', action='store_true', help='verify file integrity')
    args = ap.parse_args()

    db = NewpkgDB()
    if args.init:
        db.init_db()
        print('db initialized at', db._db_path)
    if args.export:
        db.export_packages_json(args.export)
        print('exported to', args.export)
    if args.verify:
        res = db.verify_integrity()
        print('verify:', json.dumps(res, indent=2))
