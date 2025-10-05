"""
newpkg_db.py

Banco de dados local para o projeto `newpkg`.
- Usa SQLite3 e disponibiliza uma API de alto nível para gerenciar pacotes, arquivos,
  dependências e logs de build.
- Suporta migrations internas, backup, vacuum e verificação de integridade dos arquivos
  registrados (hash/size/exists).

Design goals:
- Independente de plataforma (Linux-focused paths, mas portable).
- Integração com ConfigStore via parâmetro `cfg` (objeto com `get(key)`).
- Segurança: realiza backup antes de migrations.

Exemplo de uso:
    db = NewpkgDB(cfg)
    db.init_db()
    pkg_id = db.add_package('xorg', '1.0', 1, origin='blfs')
    db.record_file('xorg', '/mnt/lfs/usr/bin/X', size=1024, hash='...')

"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Iterator, Tuple
import hashlib
import json
import shutil
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime


DEFAULT_DB_TEMPLATE = "${LFS}/var/lib/newpkg/db.sqlite"


class NewpkgDBError(Exception):
    pass


@dataclass
class PackageRecord:
    id: int
    name: str
    version: Optional[str]
    release: Optional[int]
    status: str
    origin: Optional[str]
    build_dir: Optional[str]
    install_dir: Optional[str]
    installed_at: Optional[str]
    updated_at: Optional[str]


class NewpkgDB:
    """API de alto-nível para o banco de dados local do newpkg.

    Parâmetros:
        cfg: objeto opcional com método `get(key: str)` que retorna valores expandidos.
        db_path: caminho direto para o banco (override cfg).
    """

    CURRENT_SCHEMA_VERSION = 1

    def __init__(self, cfg: Any = None, db_path: Optional[str] = None, ensure_dirs: bool = True):
        self.cfg = cfg
        self._raw_db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._open_kwargs = {"check_same_thread": False}
        if ensure_dirs:
            self._ensure_db_dir_exists()

    # -------------------- path resolution --------------------
    def _resolve_db_path(self) -> Path:
        if self._raw_db_path:
            p = Path(self._raw_db_path)
        else:
            # try cfg
            if self.cfg is not None:
                try:
                    candidate = self.cfg.get("DB_PATH")
                except Exception:
                    candidate = None
            else:
                candidate = None
            if not candidate:
                # fallback: use DEFAULT template expanding LFS if possible
                lfs = None
                if self.cfg is not None:
                    try:
                        lfs = self.cfg.get("general.LFS") or self.cfg.get("LFS")
                    except Exception:
                        lfs = None
                if not lfs:
                    lfs = "/mnt/lfs"
                candidate = DEFAULT_DB_TEMPLATE.replace("${LFS}", lfs)
            p = Path(candidate)
        return p.expanduser().resolve()

    def _ensure_db_dir_exists(self) -> None:
        p = self._resolve_db_path()
        p.parent.mkdir(parents=True, exist_ok=True)

    # -------------------- connection management --------------------
    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            dbp = str(self._resolve_db_path())
            conn = sqlite3.connect(dbp, **self._open_kwargs)
            conn.row_factory = sqlite3.Row
            # recommended pragmas
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._conn = conn
        return self._conn

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.commit()
            except Exception:
                pass
            try:
                self._conn.close()
            except Exception:
                pass
            finally:
                self._conn = None

    # -------------------- transactions --------------------
    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        conn = self._connect()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # -------------------- initialization / migrations --------------------
    def init_db(self, force: bool = False) -> None:
        """Cria as tabelas base e inicializa o schema metadata.

        Se force=True, recria o banco (faz backup primeiro se existir).
        """
        dbp = self._resolve_db_path()
        if dbp.exists():
            if force:
                self.backup(dbp.with_suffix(dbp.suffix + ".bak"))
                dbp.unlink()
            else:
                # ensure migrations
                self.migrate(self.CURRENT_SCHEMA_VERSION)
                return

        # ensure parent dir
        dbp.parent.mkdir(parents=True, exist_ok=True)

        conn = self._connect()
        with self.transaction() as cur:
            # packages
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS packages (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    version TEXT,
                    release INTEGER,
                    status TEXT,
                    origin TEXT,
                    build_dir TEXT,
                    install_dir TEXT,
                    installed_at TEXT,
                    updated_at TEXT
                );
                """
            )
            # files
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY,
                    package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    size INTEGER,
                    hash TEXT,
                    mode INTEGER,
                    owner TEXT,
                    groupname TEXT
                );
                """
            )
            # deps
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS deps (
                    id INTEGER PRIMARY KEY,
                    package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE,
                    depends_on TEXT NOT NULL,
                    optional INTEGER DEFAULT 0
                );
                """
            )
            # build logs
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS build_logs (
                    id INTEGER PRIMARY KEY,
                    package_id INTEGER,
                    phase TEXT,
                    status TEXT,
                    log_path TEXT,
                    timestamp TEXT
                );
                """
            )
            # meta
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
                """
            )
            # set schema version
            cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", ("schema_version", str(self.CURRENT_SCHEMA_VERSION)))
        # vacuum for fresh DB
        self.vacuum()

    def _get_schema_version(self) -> int:
        with self.transaction() as cur:
            cur.execute("SELECT value FROM meta WHERE key = 'schema_version'")
            r = cur.fetchone()
            if r:
                try:
                    return int(r[0])
                except Exception:
                    return 0
            return 0

    def migrate(self, target_version: int) -> None:
        """Aplica migrações até target_version.

        Implementa uma cadeia de migrações (cada número) que garantem compatibilidade.
        Faz backup automático antes de aplicar mudanças destrutivas.
        """
        current = self._get_schema_version()
        if current == 0:
            # assume DB not initialized
            self.init_db()
            return
        if current >= target_version:
            return
        dbp = self._resolve_db_path()
        # backup before migrations
        self.backup(dbp.with_suffix(dbp.suffix + f".v{current}.bak"))
        # simple migration framework placeholder
        # e.g. if current == 1 and target_version == 2: apply changes
        # Since CURRENT_SCHEMA_VERSION == 1, nothing to do now
        with self.transaction() as cur:
            cur.execute("UPDATE meta SET value=? WHERE key='schema_version'", (str(target_version),))

    # -------------------- package operations --------------------
    def add_package(self, name: str, version: Optional[str] = None, release: Optional[int] = None, origin: Optional[str] = None, status: str = "built", build_dir: Optional[str] = None, install_dir: Optional[str] = None) -> int:
        with self.transaction() as cur:
            now = datetime.utcnow().isoformat()
            cur.execute(
                "INSERT OR REPLACE INTO packages(name, version, release, status, origin, build_dir, install_dir, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (name, version, release, status, origin, build_dir, install_dir, now),
            )
            # fetch id
            cur.execute("SELECT id FROM packages WHERE name = ?", (name,))
            row = cur.fetchone()
            return int(row[0])

    def update_package_status(self, name: str, status: str) -> None:
        with self.transaction() as cur:
            now = datetime.utcnow().isoformat()
            cur.execute("UPDATE packages SET status = ?, updated_at = ? WHERE name = ?", (status, now, name))

    def get_package(self, name: str) -> Optional[PackageRecord]:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM packages WHERE name = ?", (name,))
        row = cur.fetchone()
        if not row:
            return None
        return PackageRecord(
            id=row["id"],
            name=row["name"],
            version=row["version"],
            release=row["release"],
            status=row["status"],
            origin=row["origin"],
            build_dir=row["build_dir"],
            install_dir=row["install_dir"],
            installed_at=row["installed_at"],
            updated_at=row["updated_at"],
        )

    def remove_package(self, name: str) -> None:
        with self.transaction() as cur:
            cur.execute("DELETE FROM packages WHERE name = ?", (name,))

    def list_packages(self, status: Optional[str] = None) -> List[PackageRecord]:
        conn = self._connect()
        cur = conn.cursor()
        if status:
            cur.execute("SELECT * FROM packages WHERE status = ? ORDER BY name", (status,))
        else:
            cur.execute("SELECT * FROM packages ORDER BY name")
        rows = cur.fetchall()
        return [
            PackageRecord(
                id=r["id"],
                name=r["name"],
                version=r["version"],
                release=r["release"],
                status=r["status"],
                origin=r["origin"],
                build_dir=r["build_dir"],
                install_dir=r["install_dir"],
                installed_at=r["installed_at"],
                updated_at=r["updated_at"],
            )
            for r in rows
        ]

    # -------------------- files --------------------
    def record_file(self, pkg_name: str, path: str, size: Optional[int] = None, hash: Optional[str] = None, mode: Optional[int] = None, owner: Optional[str] = None, groupname: Optional[str] = None) -> int:
        with self.transaction() as cur:
            # ensure package exists
            cur.execute("SELECT id FROM packages WHERE name = ?", (pkg_name,))
            row = cur.fetchone()
            if not row:
                raise NewpkgDBError(f"Package '{pkg_name}' not registered")
            pkg_id = int(row[0])
            cur.execute(
                "INSERT INTO files(package_id, path, size, hash, mode, owner, groupname) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (pkg_id, path, size, hash, mode, owner, groupname),
            )
            cur.execute("SELECT last_insert_rowid() as id")
            r = cur.fetchone()
            return int(r[0])

    def get_files(self, pkg_name: str) -> List[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT f.* FROM files f JOIN packages p ON p.id = f.package_id WHERE p.name = ? ORDER BY f.path",
            (pkg_name,),
        )
        rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({k: r[k] for k in r.keys()})
        return out

    # -------------------- dependencies --------------------
    def add_dependency(self, pkg_name: str, dep_name: str, optional: bool = False) -> int:
        with self.transaction() as cur:
            cur.execute("SELECT id FROM packages WHERE name = ?", (pkg_name,))
            row = cur.fetchone()
            if not row:
                raise NewpkgDBError(f"Package '{pkg_name}' not registered")
            pkg_id = int(row[0])
            cur.execute("INSERT INTO deps(package_id, depends_on, optional) VALUES(?, ?, ?)", (pkg_id, dep_name, int(bool(optional))))
            cur.execute("SELECT last_insert_rowid() as id")
            r = cur.fetchone()
            return int(r[0])

    def get_deps(self, pkg_name: str) -> List[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT d.* FROM deps d JOIN packages p ON p.id = d.package_id WHERE p.name = ?",
            (pkg_name,),
        )
        rows = cur.fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]

    def get_reverse_deps(self, pkg_name: str) -> List[str]:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("SELECT id FROM packages WHERE name = ?", (pkg_name,))
        row = cur.fetchone()
        if not row:
            return []
        pkg_id = int(row[0])
        cur.execute("SELECT p.name FROM deps d JOIN packages p ON d.package_id = p.id WHERE d.depends_on = ?", (pkg_name,))
        rows = cur.fetchall()
        return [r[0] for r in rows]

    # -------------------- logs --------------------
    def add_log(self, pkg_name: str, phase: str, status: str, log_path: Optional[str] = None) -> int:
        with self.transaction() as cur:
            cur.execute("SELECT id FROM packages WHERE name = ?", (pkg_name,))
            row = cur.fetchone()
            pkg_id = int(row[0]) if row else None
            now = datetime.utcnow().isoformat()
            cur.execute("INSERT INTO build_logs(package_id, phase, status, log_path, timestamp) VALUES(?, ?, ?, ?, ?)", (pkg_id, phase, status, log_path, now))
            cur.execute("SELECT last_insert_rowid() as id")
            r = cur.fetchone()
            return int(r[0])

    def get_logs(self, pkg_name: str) -> List[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("SELECT id FROM packages WHERE name = ?", (pkg_name,))
        row = cur.fetchone()
        if not row:
            return []
        pkg_id = int(row[0])
        cur.execute("SELECT * FROM build_logs WHERE package_id = ? ORDER BY timestamp", (pkg_id,))
        rows = cur.fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]

    # -------------------- maintenance --------------------
    def vacuum(self) -> None:
        conn = self._connect()
        conn.execute("VACUUM;")

    def backup(self, target_path: Path) -> None:
        """Cria backup do arquivo do DB no caminho target_path (Path).

        Garante flush e cópia atômica quando possível.
        """
        dbp = self._resolve_db_path()
        if not dbp.exists():
            return
        # ensure target dir
        target_path = Path(target_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        self.close()  # ensure file closed
        shutil.copy2(dbp, target_path)

    # -------------------- integrity --------------------
    def verify_integrity(self, pkg_name: Optional[str] = None, hash_algo: str = "sha256") -> List[Dict[str, Any]]:
        """Verifica arquivos registrados: existência, tamanho e hash.

        Retorna lista de problemas encontrados: [{path, exists, size_ok, hash_ok, expected_hash, actual_hash}]
        """
        algo = getattr(hashlib, hash_algo, None)
        if algo is None:
            raise NewpkgDBError(f"Hash algorithm {hash_algo} not available")
        to_check = []
        conn = self._connect()
        cur = conn.cursor()
        if pkg_name:
            cur.execute("SELECT id FROM packages WHERE name = ?", (pkg_name,))
            row = cur.fetchone()
            if not row:
                raise NewpkgDBError(f"Package {pkg_name} not found")
            pkg_id = int(row[0])
            cur.execute("SELECT path, size, hash FROM files WHERE package_id = ?", (pkg_id,))
        else:
            cur.execute("SELECT path, size, hash FROM files")
        rows = cur.fetchall()
        for r in rows:
            p = r[0]
            expected_size = r[1]
            expected_hash = r[2]
            rec = {"path": p, "exists": False, "size_ok": False, "hash_ok": None, "expected_hash": expected_hash, "actual_hash": None}
            if os.path.exists(p):
                rec["exists"] = True
                try:
                    st = os.stat(p)
                    actual_size = st.st_size
                    rec["size_ok"] = (expected_size is None) or (int(expected_size) == actual_size)
                    if expected_hash:
                        # compute hash
                        h = algo()
                        with open(p, "rb") as fh:
                            for chunk in iter(lambda: fh.read(65536), b""):
                                h.update(chunk)
                        rec["actual_hash"] = h.hexdigest()
                        rec["hash_ok"] = (rec["actual_hash"] == expected_hash)
                except Exception as e:
                    rec["error"] = str(e)
            to_check.append(rec)
        return to_check

    # -------------------- export / helper --------------------
    def export_packages_json(self, target: Path) -> None:
        data = {"packages": []}
        for p in self.list_packages():
            files = self.get_files(p.name)
            deps = self.get_deps(p.name)
            logs = self.get_logs(p.name)
            data["packages"].append({"meta": p.__dict__, "files": files, "deps": deps, "logs": logs})
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# -------------------- small demo when executed directly --------------------
if __name__ == "__main__":
    # demo usage (very small)
    import argparse

    ap = argparse.ArgumentParser(prog="newpkg-db-demo")
    ap.add_argument("--db", help="path to sqlite db", default=None)
    ap.add_argument("--init", action="store_true")
    args = ap.parse_args()

    db = NewpkgDB(db_path=args.db)
    if args.init:
        db.init_db(force=False)
        print("DB initialized at:", db._resolve_db_path())
    else:
        print("Use --init to create DB")
