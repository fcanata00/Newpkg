#!/usr/bin/env python3
# newpkg_remove.py
"""
newpkg_remove.py — remoção segura de pacotes para newpkg

Funcionalidades:
 - Gera plano de remoção (por pacote) com base no DB (arquivos instalados)
 - Faz backup (tar.xz + metadata) antes da remoção
 - Remove arquivos de forma segura (opcional dentro de sandbox)
 - Purga dados associados (config, cache) se solicitado
 - Permite rollback/restauração a partir do backup
 - Respeita newpkg_config: general.dry_run, output.quiet, output.json, general.root_dir
 - Usa NewpkgLogger/NewpkgDB/NewpkgHooks/NewpkgSandbox quando disponíveis
 - Gera relatório em /var/log/newpkg/remove/remove-last.json
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# imports opcionais do ecossistema
try:
    from newpkg_config import init_config
except Exception:
    init_config = None

try:
    from newpkg_logger import NewpkgLogger
except Exception:
    NewpkgLogger = None

try:
    from newpkg_db import NewpkgDB
except Exception:
    NewpkgDB = None

try:
    from newpkg_hooks import NewpkgHooks
except Exception:
    NewpkgHooks = None

try:
    from newpkg_sandbox import NewpkgSandbox
except Exception:
    NewpkgSandbox = None

# fallback stdlib logger
import logging
_logger = logging.getLogger("newpkg.remove")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.remove: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


@dataclass
class RemovePlanItem:
    package: str
    files: List[str]


@dataclass
class RemoveResult:
    package: str
    removed_files: List[str]
    skipped_files: List[str]
    rc: int
    duration: float
    backup: Optional[str] = None
    message: Optional[str] = None

    def to_dict(self):
        return asdict(self)


class NewpkgRemove:
    DEFAULT_REPORT_DIR = "/var/log/newpkg/remove"
    DEFAULT_SAFE_PREFIXES = ["/usr", "/usr/local", "/opt", "/var/lib/newpkg", "/etc"]
    DEFAULT_BACKUP_DIR = "/var/lib/newpkg/backups"

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)

        # logger
        if logger:
            self.logger = logger
        else:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, db) if NewpkgLogger and self.cfg else None
            except Exception:
                self.logger = None

        self._log = self._make_logger()

        # db
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)

        # hooks
        if hooks:
            self.hooks = hooks
        else:
            try:
                self.hooks = NewpkgHooks.from_config(self.cfg, self.logger, self.db) if NewpkgHooks and self.cfg else None
            except Exception:
                self.hooks = None

        # sandbox
        if sandbox:
            self.sandbox = sandbox
        else:
            try:
                self.sandbox = NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgSandbox and self.cfg else None
            except Exception:
                self.sandbox = None

        # config flags
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))
        # base root (supports building to /mnt/lfs)
        self.root_dir = os.path.expanduser(str(self._cfg_get("general.root_dir", "/")))
        # safety prefixes (from config or default)
        self.safe_prefixes = list(self._cfg_get("remove.safe_prefixes", self.DEFAULT_SAFE_PREFIXES) or self.DEFAULT_SAFE_PREFIXES)
        # require confirmation to actually remove (default true)
        self.require_confirm = bool(self._cfg_get("remove.require_confirm", True))
        # report and backup dirs
        self.report_dir = Path(self._cfg_get("remove.report_dir", self.DEFAULT_REPORT_DIR))
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.last_report = self.report_dir / "remove-last.json"
        self.backup_dir = Path(self._cfg_get("remove.backup_dir", self.DEFAULT_BACKUP_DIR))
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # perf_timer if available
        self._perf_timer = getattr(self.logger, "perf_timer", None) if self.logger else None

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        env_key = key.upper().replace(".", "_")
        return os.environ.get(env_key, default)

    def _make_logger(self):
        def _fn(level: str, event: str, msg: str = "", **meta):
            try:
                if self.logger:
                    fn = getattr(self.logger, level.lower(), None)
                    if fn:
                        fn(event, msg, **meta)
                        return
            except Exception:
                pass
            getattr(_logger, level.lower(), _logger.info)(f"{event}: {msg} - {meta}")
        return _fn

    # ---------- helpers ----------
    def _abs_path(self, p: str) -> Optional[str]:
        """Resolve path possibly relative to configured root_dir; return absolute path or None if invalid."""
        if not p:
            return None
        # expand env and user
        p_expanded = os.path.expandvars(os.path.expanduser(p))
        if os.path.isabs(p_expanded):
            return os.path.normpath(os.path.join(self.root_dir.lstrip("/"), p_expanded.lstrip("/"))) if self.root_dir != "/" else os.path.normpath(p_expanded)
        else:
            # treat as relative to root_dir
            return os.path.normpath(os.path.join(self.root_dir, p_expanded))

    def _is_path_safe(self, path: str) -> bool:
        """Check if given path starts with at least one safe prefix."""
        try:
            p = Path(path).resolve()
        except Exception:
            return False
        for pref in self.safe_prefixes:
            try:
                pref_abs = Path(pref if os.path.isabs(pref) else os.path.join(self.root_dir, pref)).resolve()
                if str(p).startswith(str(pref_abs)):
                    return True
            except Exception:
                continue
        return False

    def _record_phase(self, package: str, phase: str, status: str, meta: Dict[str, Any]):
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase=phase, status=status, meta=meta)
        except Exception:
            pass

    # ---------- plan ----------
    def plan_removal(self, package: str) -> Dict[str, Any]:
        """
        Build a removal plan for a package from the DB.
        Returns dict with plan (file list) and metadata.
        """
        start = time.time()
        if not self.db:
            msg = "no database available"
            self._log("error", "remove.plan.nodb", msg, package=package)
            return {"ok": False, "error": msg}

        try:
            files = self.db.list_files(package)  # expected list of paths
        except Exception as e:
            self._log("error", "remove.plan.dbfail", f"DB failure listing files: {e}", package=package, error=str(e))
            return {"ok": False, "error": "db_list_files_failed", "exc": str(e)}

        # normalize absolute paths relative to root_dir
        abs_files = []
        unsafe = []
        for f in files:
            ap = self._abs_path(f)
            if not ap:
                unsafe.append(f)
                continue
            if not self._is_path_safe(ap):
                unsafe.append(ap)
                continue
            abs_files.append(ap)

        plan = {"package": package, "files": sorted(abs_files), "unsafe": sorted(unsafe), "count": len(abs_files)}
        elapsed = time.time() - start
        self._log("info", "remove.plan.ok", f"Plan built for {package} files={len(abs_files)} unsafe={len(unsafe)}", package=package, count=len(abs_files))
        self._record_phase(package, "remove.plan", "ok", {"count": len(abs_files), "unsafe": len(unsafe), "time": elapsed})
        return {"ok": True, "plan": plan, "duration": elapsed}

    # ---------- backup ----------
    def backup_package(self, package: str, files: List[str]) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Creates tar.xz backup of the listed files and a metadata json.
        Returns (ok, backup_path, metadata_path)
        """
        start = time.time()
        ts = int(time.time())
        safe_name = package.replace("/", "_")
        backup_name = f"{safe_name}-{ts}.tar.xz"
        meta_name = f"{safe_name}-{ts}.meta.json"
        backup_path = str(self.backup_dir / backup_name)
        meta_path = str(self.backup_dir / meta_name)
        # in dry-run simulate
        if self.dry_run:
            self._log("info", "remove.backup.dryrun", f"DRY-RUN: would backup {len(files)} files for {package}", package=package, count=len(files))
            return True, None, None

        try:
            # create temporary dir to assemble entries (use tar with absolute paths via arcname)
            with tarfile.open(backup_path, "w:xz") as tar:
                for f in files:
                    try:
                        if os.path.exists(f):
                            # arcname to preserve relative subtree - use leading slash removal
                            arcname = os.path.relpath(f, "/") if f.startswith("/") else f
                            tar.add(f, arcname=arcname)
                    except Exception as e:
                        # skip problematic files but record
                        self._log("warning", "remove.backup.skip", f"Skipping file in backup {f}: {e}", file=f, error=str(e))
            # metadata
            meta = {"package": package, "ts": ts, "file_count": len(files), "created_by": "newpkg_remove"}
            Path(meta_path).write_text(json.dumps(meta, indent=2), encoding="utf-8")
            elapsed = time.time() - start
            self._log("info", "remove.backup.ok", f"Backup created {backup_path} ({len(files)} files) in {elapsed:.2f}s", package=package, backup=backup_path)
            self._record_phase(package, "remove.backup", "ok", {"backup": backup_path, "meta": meta_path, "time": elapsed})
            return True, backup_path, meta_path
        except Exception as e:
            self._log("error", "remove.backup.fail", f"Backup failed: {e}", package=package, error=str(e))
            self._record_phase(package, "remove.backup", "error", {"error": str(e)})
            return False, None, None

    # ---------- remove files ----------
    def _remove_path(self, path: str, use_sandbox: bool = True) -> Tuple[int, str, str]:
        """Remove a single path. Returns (rc, stdout, stderr). rc 0 ok."""
        # ensure safety check
        if not self._is_path_safe(path):
            return (2, "", f"path not safe: {path}")
        if self.dry_run:
            self._log("info", "remove.exec.dryrun", f"DRY-RUN would remove {path}", path=path)
            return (0, "", "")
        # prefer sandbox
        if use_sandbox and self.sandbox:
            # use sandbox to run 'rm -rf' safely
            cmd = ["rm", "-rf", path]
            try:
                res = self.sandbox.run_in_sandbox(cmd, cwd="/", captures=True, env=None)
                rc = res.rc
                out = res.stdout or ""
                err = res.stderr or ""
                return (rc, out, err)
            except Exception as e:
                return (255, "", str(e))
        # fallback direct removal
        try:
            if os.path.islink(path) or os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
            else:
                # unknown type, attempt unlink
                try:
                    os.remove(path)
                except Exception:
                    pass
            return (0, "", "")
        except Exception as e:
            return (1, "", str(e))

    def execute_removal(self, package: str, confirm: bool = False, purge: bool = False, use_sandbox: bool = True) -> Dict[str, Any]:
        """
        Execute removal: backup -> delete files -> optionally purge configs/cache.
        confirm: must be True (or require_confirm False) to actually perform removals.
        Returns structured summary.
        """
        start_total = time.time()
        plan_res = self.plan_removal(package)
        if not plan_res.get("ok"):
            return {"ok": False, "error": plan_res.get("error")}

        plan = plan_res["plan"]
        files: List[str] = plan["files"]
        unsafe = plan["unsafe"]

        # don't proceed if unsafe entries exist
        if unsafe:
            msg = f"Unsafe paths present: {unsafe}"
            self._log("error", "remove.execute.unsafe", msg, package=package)
            return {"ok": False, "error": "unsafe_paths", "unsafe": unsafe}

        if self.require_confirm and not confirm:
            self._log("warning", "remove.execute.no_confirm", "Execution requires explicit confirm", package=package)
            return {"ok": False, "error": "no_confirm"}

        # run pre_remove hooks
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("pre_remove", [f"pre_remove:{package}"], json_output=False)
        except Exception:
            pass

        # create backup
        ok_backup, backup_path, meta_path = self.backup_package(package, files)
        if not ok_backup:
            return {"ok": False, "error": "backup_failed"}

        removed = []
        skipped = []
        errors = []

        t0 = time.time()
        for f in files:
            rc, out, err = self._remove_path(f, use_sandbox=use_sandbox)
            if rc == 0:
                removed.append(f)
            else:
                skipped.append(f)
                errors.append({"file": f, "rc": rc, "err": err})
                self._log("error", "remove.exec.filefail", f"Failed removing {f}: {err}", file=f, rc=rc, err=err)

        duration = time.time() - t0

        # optionally purge configs/cache related to package (best-effort)
        purge_result = None
        if purge:
            purge_result = self._purge_package_data(package, use_sandbox=use_sandbox)

        # update DB: mark package as removed (best-effort)
        try:
            if self.db and hasattr(self.db, "mark_removed"):
                try:
                    self.db.mark_removed(package)
                except Exception:
                    pass
        except Exception:
            pass

        # run post_remove hooks
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("post_remove", [f"post_remove:{package}"], json_output=False)
        except Exception:
            pass

        total_duration = time.time() - start_total
        rc_summary = 0 if not errors else 2
        result = {
            "ok": rc_summary == 0,
            "package": package,
            "removed": removed,
            "skipped": skipped,
            "errors": errors,
            "backup": backup_path,
            "backup_meta": meta_path,
            "purge": purge_result,
            "duration": total_duration,
        }

        # save report
        try:
            self.write_report(result)
        except Exception:
            pass

        # record phase
        self._record_phase(package, "remove.exec", "ok" if rc_summary == 0 else "error", {"removed": len(removed), "skipped": len(skipped), "errors": len(errors), "backup": backup_path})

        return result

    # ---------- purge ----------
    def _purge_package_data(self, package: str, use_sandbox: bool = True) -> Dict[str, Any]:
        """
        Purge configuration/cache directories related to the package.
        This is heuristic; check package metadata in DB for known locations.
        """
        purged = []
        failed = []
        # heuristics: /etc/{package}, /var/cache/{package}, /var/lib/{package}, ~/.config/{package}
        candidates = []
        etc_cand = os.path.join(self.root_dir, "etc", package)
        varlib_cand = os.path.join(self.root_dir, "var", "lib", package)
        varcache_cand = os.path.join(self.root_dir, "var", "cache", package)
        home_conf = os.path.expanduser(f"~/.config/{package}")
        candidates.extend([etc_cand, varlib_cand, varcache_cand, home_conf])

        for c in candidates:
            if os.path.exists(c):
                if not self._is_path_safe(c):
                    failed.append({"path": c, "err": "unsafe"})
                    continue
                if self.dry_run:
                    self._log("info", "remove.purge.dryrun", f"DRY-RUN purge {c}", path=c)
                    purged.append(c)
                    continue
                try:
                    if use_sandbox and self.sandbox:
                        r = self.sandbox.run_in_sandbox(["rm", "-rf", c], cwd="/", captures=True)
                        if r.rc == 0:
                            purged.append(c)
                        else:
                            failed.append({"path": c, "err": r.stderr})
                    else:
                        if os.path.isdir(c):
                            shutil.rmtree(c)
                        else:
                            os.remove(c)
                        purged.append(c)
                except Exception as e:
                    failed.append({"path": c, "err": str(e)})
        self._record_phase(package, "remove.purge", "ok" if not failed else "partial", {"purged": len(purged), "failed": len(failed)})
        return {"purged": purged, "failed": failed}

    # ---------- rollback ----------
    def rollback(self, backup_path: str, restore_to: Optional[str] = None, use_sandbox: bool = True) -> Dict[str, Any]:
        """
        Restore a backup tar.xz to the filesystem. restore_to allows alternative root.
        """
        start = time.time()
        if self.dry_run:
            self._log("info", "remove.rollback.dryrun", f"DRY-RUN would restore {backup_path} to {restore_to or self.root_dir}")
            return {"ok": True, "simulated": True}

        if not os.path.exists(backup_path):
            return {"ok": False, "error": "backup_missing", "path": backup_path}

        target_root = restore_to or self.root_dir
        if not self._is_path_safe(target_root):
            return {"ok": False, "error": "target_not_safe", "target": target_root}

        try:
            if use_sandbox and self.sandbox:
                # copy archive into sandbox's accessible area and extract
                # best-effort: run tar -xJf <archive> -C /
                cmd = ["tar", "-xJf", backup_path, "-C", target_root]
                res = self.sandbox.run_in_sandbox(cmd, cwd=target_root, captures=True)
                rc = res.rc
                if rc != 0:
                    return {"ok": False, "error": "sandbox_extract_failed", "stderr": res.stderr}
            else:
                with tarfile.open(backup_path, "r:xz") as tar:
                    tar.extractall(path=target_root)
            dur = time.time() - start
            self._log("info", "remove.rollback.ok", f"Restored {backup_path} to {target_root} in {dur:.2f}s", backup=backup_path, target=target_root)
            return {"ok": True, "backup": backup_path, "target": target_root, "duration": time.time() - start}
        except Exception as e:
            self._log("error", "remove.rollback.fail", f"Rollback failed: {e}", error=str(e))
            return {"ok": False, "error": str(e)}

    # ---------- reporting ----------
    def write_report(self, result: Dict[str, Any]) -> Path:
        """Write last-run report in JSON to report_dir."""
        try:
            rpt = {"ts": int(time.time()), "result": result}
            tmp = self.last_report.with_suffix(".tmp")
            tmp.write_text(json.dumps(rpt, indent=2), encoding="utf-8")
            tmp.replace(self.last_report)
            self._log("info", "remove.report.write", f"Wrote report to {self.last_report}", path=str(self.last_report))
            return self.last_report
        except Exception as e:
            self._log("error", "remove.report.fail", f"Failed writing report: {e}", error=str(e))
            raise

    # ---------- CLI helper ----------
    @staticmethod
    def cli():
        import argparse
        p = argparse.ArgumentParser(prog="newpkg-remove", description="Remover pacotes de forma segura com newpkg")
        p.add_argument("package", help="Nome do pacote a remover (como no DB)")
        p.add_argument("--plan", action="store_true", help="Mostrar plano de remoção")
        p.add_argument("--execute", action="store_true", help="Executar remoção (requer --confirm ou config override)")
        p.add_argument("--confirm", action="store_true", help="Confirmar execução")
        p.add_argument("--purge", action="store_true", help="Purgar configs/caches associados")
        p.add_argument("--dry-run", action="store_true", help="Simular sem mudanças")
        p.add_argument("--no-sandbox", action="store_true", help="Não usar sandbox para remoções")
        p.add_argument("--json", action="store_true", help="Imprimir JSON")
        p.add_argument("--quiet", action="store_true", help="Modo silencioso")
        p.add_argument("--restore", metavar="BACKUP", help="Restaurar backup tar.xz")
        p.add_argument("--restore-to", metavar="DIR", help="Restaurar backup num root alternativo")
        args = p.parse_args()

        cfg = init_config() if init_config else None
        logger = NewpkgLogger.from_config(cfg, NewpkgDB(cfg)) if NewpkgLogger and cfg else None
        db = NewpkgDB(cfg) if NewpkgDB and cfg else None
        hooks = NewpkgHooks.from_config(cfg, logger, db) if NewpkgHooks and cfg else None
        sandbox = NewpkgSandbox(cfg=cfg, logger=logger, db=db) if NewpkgSandbox and cfg else None

        remover = NewpkgRemove(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)

        # override flags from CLI
        if args.dry_run:
            remover.dry_run = True
        if args.quiet:
            remover.quiet = True
        if args.json:
            remover.json_out = True
        if args.no_sandbox:
            use_sandbox = False
        else:
            use_sandbox = True

        if args.restore:
            res = remover.rollback(args.restore, restore_to=args.restore_to, use_sandbox=use_sandbox)
            if remover.json_out or args.json:
                print(json.dumps(res, indent=2))
            else:
                print("Restore:", res)
            raise SystemExit(0 if res.get("ok") else 2)

        if args.plan:
            res = remover.plan_removal(args.package)
            if remover.json_out or args.json:
                print(json.dumps(res, indent=2))
            else:
                plan = res.get("plan", {})
                print(f"Package: {plan.get('package')}")
                print(f"Files: {plan.get('count')}")
                if plan.get("unsafe"):
                    print("Unsafe entries (will block removal):")
                    for u in plan.get("unsafe", []):
                        print("  -", u)
            raise SystemExit(0 if res.get("ok") else 2)

        if args.execute:
            res = remover.execute_removal(args.package, confirm=args.confirm, purge=args.purge, use_sandbox=use_sandbox)
            if remover.json_out or args.json:
                print(json.dumps(res, indent=2))
            else:
                if res.get("ok"):
                    print(f"Removed {len(res.get('removed',[]))} files for {args.package}; backup: {res.get('backup')}")
                else:
                    print("Removal failed:", res.get("error"))
            raise SystemExit(0 if res.get("ok") else 2)

        # default: show plan
        res = remover.plan_removal(args.package)
        if remover.json_out or args.json:
            print(json.dumps(res, indent=2))
        else:
            plan = res.get("plan", {})
            print(f"Package: {plan.get('package')}")
            for f in plan.get("files", []):
                print(" -", f)
        raise SystemExit(0 if res.get("ok") else 2)


if __name__ == "__main__":
    NewpkgRemove.cli()
