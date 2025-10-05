#!/usr/bin/env python3
# newpkg_remove.py
"""
Newpkg remove manager — revised.

Features:
 - Plan + safe backup (tar.xz) before destructive actions
 - Optional sandboxed removals (use_fakeroot support)
 - Hooks before/after major phases with structured context
 - Progress UI via logger.progress() (Rich fallback)
 - Perf timing and DB record_phase integration
 - Audit reporting on start/success/failure
 - Purge intelligence (DB metadata + heuristics)
 - Reports saved/rotated/compressed under report_dir
 - API-friendly functions and CLI runner with abbreviations
"""

from __future__ import annotations

import json
import lzma
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional integrations (best-effort)
try:
    from newpkg_config import init_config  # type: ignore
except Exception:
    init_config = None

try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_db import NewpkgDB  # type: ignore
except Exception:
    NewpkgDB = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

try:
    from newpkg_sandbox import get_sandbox  # type: ignore
except Exception:
    get_sandbox = None

try:
    from newpkg_audit import NewpkgAudit  # type: ignore
except Exception:
    NewpkgAudit = None

# fallback logger
import logging
_logger = logging.getLogger("newpkg.remove")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.remove: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# optional rich for CLI
try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
    _console = Console()
except Exception:
    RICH = False
    _console = None

# ---------------- dataclasses ----------------
@dataclass
class RemovalPlanEntry:
    package: str
    files: List[str]
    size_bytes: int
    action: str  # 'remove' or 'purge' or 'skip'
    reason: Optional[str] = None
    backup: Optional[str] = None


# ---------------- class ----------------
class NewpkgRemove:
    DEFAULT_REPORT_DIR = "/var/log/newpkg/remove"
    DEFAULT_BACKUP_DIR = "/var/cache/newpkg/remove_backups"
    DEFAULT_KEEP_REPORTS = 20
    SAFE_WHITELIST_PREFIXES = ("/usr", "/opt", "/var", "/etc", "/home")  # allow removals within these by heuristic

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None, audit: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        self.logger = logger or (get_logger(self.cfg) if get_logger else None)
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)
        self.hooks = hooks or (get_hooks_manager(self.cfg) if get_hooks_manager else None)
        self.sandbox = sandbox or (get_sandbox(self.cfg) if get_sandbox else None)
        self.audit = audit or (NewpkgAudit(self.cfg) if NewpkgAudit and self.cfg else None)

        # config
        self.report_dir = Path(self._cfg_get("remove.report_dir", self.DEFAULT_REPORT_DIR)).expanduser()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir = Path(self._cfg_get("remove.backup_dir", self.DEFAULT_BACKUP_DIR)).expanduser()
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.keep_reports = int(self._cfg_get("remove.keep_reports", self.DEFAULT_KEEP_REPORTS))
        self.use_sandbox = bool(self._cfg_get("remove.use_sandbox", False))
        self.sandbox_profile = str(self._cfg_get("remove.sandbox_profile", "light"))
        self.require_confirm = bool(self._cfg_get("remove.require_confirm", True))
        self.auto_confirm = bool(self._cfg_get("remove.auto_confirm", False))
        self.dry_run = bool(self._cfg_get("remove.dry_run", False))
        self.parallel = int(self._cfg_get("remove.parallel", max(1, (os.cpu_count() or 2))))
        self.max_backup_mb = int(self._cfg_get("remove.max_backup_mb", 1024))
        self.rotate_compress = bool(self._cfg_get("remove.compress_reports", True))
        self._lock = threading.RLock()

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        envk = key.upper().replace(".", "_")
        return os.environ.get(envk, default)

    # ---------------- helpers ----------------
    def _now_ts(self) -> str:
        return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    def _record_phase(self, name: Optional[str], phase: str, status: str, meta: Optional[Dict[str, Any]] = None) -> None:
        try:
            if self.db:
                self.db.record_phase(name, phase, status, meta=meta or {})
        except Exception:
            pass

    def _audit_report(self, topic: str, entity: str, status: str, meta: Dict[str, Any]) -> None:
        if not self.audit:
            return
        try:
            self.audit.report(topic, entity, status, meta)
        except Exception:
            pass

    def _rotate_reports(self) -> None:
        try:
            files = sorted([p for p in self.report_dir.iterdir() if p.is_file() and p.name.startswith("remove-report-")], key=lambda p: p.stat().st_mtime, reverse=True)
            for p in files[self.keep_reports:]:
                try:
                    p.unlink()
                except Exception:
                    pass
        except Exception:
            pass

    def _save_report(self, report: Dict[str, Any]) -> Path:
        ts = self._now_ts()
        path = self.report_dir / f"remove-report-{ts}.json"
        try:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(path))
            if self.rotate_compress:
                # compress and remove original
                try:
                    comp_path = path.with_suffix(path.suffix + ".xz")
                    with open(path, "rb") as f_in:
                        comp = lzma.compress(f_in.read())
                    with open(comp_path, "wb") as f_out:
                        f_out.write(comp)
                    try:
                        path.unlink()
                        path = comp_path
                    except Exception:
                        pass
                except Exception:
                    pass
            self._rotate_reports()
        except Exception as e:
            if self.logger:
                self.logger.warning("remove.report_save_fail", f"failed saving report: {e}")
        return path

    def _is_safe_path(self, p: str) -> bool:
        # disallow absolute root or system-critical dirs
        if not p:
            return False
        if os.path.abspath(p) in ("/", "/boot", "/proc", "/sys", "/dev"):
            return False
        # enforce whitelist prefixes
        return any(p.startswith(pref) for pref in self.SAFE_WHITELIST_PREFIXES)

    # ---------------- plan ----------------
    def build_plan_for_packages(self, package_names: List[str], include_configs: bool = True) -> List[RemovalPlanEntry]:
        """
        Build plan using DB metadata when available, otherwise fall back to filesystem heuristics.
        Each plan entry contains files to remove and an action.
        """
        start = time.time()
        plan: List[RemovalPlanEntry] = []
        for pkg in package_names:
            files = []
            size = 0
            reason = None
            if self.db and hasattr(self.db, "get_package_files"):
                try:
                    files = list(self.db.get_package_files(pkg) or [])
                    size = sum((Path(f).stat().st_size if Path(f).exists() else 0) for f in files)
                except Exception:
                    files = []
                    size = 0
            else:
                # heuristic: look under /usr, /opt for directories matching package name
                candidates = []
                for base in ("/usr", "/opt", "/var", "/etc"):
                    cand = Path(base) / pkg
                    if cand.exists():
                        candidates.append(str(cand))
                files = candidates
                size = sum((Path(f).stat().st_size if Path(f).exists() else 0) for f in files)
            action = "remove" if files else "skip"
            # optionally include config paths found in db metadata
            if include_configs and self.db and hasattr(self.db, "get_metadata"):
                try:
                    cfg_paths = self.db.get_metadata(pkg, "config_paths") or []
                    for cp in cfg_paths:
                        if cp not in files:
                            files.append(cp)
                except Exception:
                    pass
            plan.append(RemovalPlanEntry(package=pkg, files=files, size_bytes=size, action=action, reason=reason))
        duration = time.time() - start
        self._record_phase(None, "remove.plan", "ok", meta={"count": len(plan), "duration": round(duration, 3)})
        return plan

    # ---------------- backup ----------------
    def create_backup_for_entry(self, entry: RemovalPlanEntry) -> Optional[str]:
        """
        Create tar.xz backup for files in entry; skip if too large.
        Returns backup path or None.
        """
        if not entry.files:
            return None
        size_mb = entry.size_bytes // (1024 * 1024)
        if self.max_backup_mb and size_mb > self.max_backup_mb:
            if self.logger:
                self.logger.warning("remove.backup_skip", f"skip backup for {entry.package} size {size_mb}MB > {self.max_backup_mb}MB")
            return None
        try:
            ts = self._now_ts()
            out_name = f"{entry.package}-{ts}.tar.xz"
            tmp = tempfile.NamedTemporaryFile(delete=False, dir=str(self.backup_dir), prefix=f"{entry.package}-", suffix=".tar.xz")
            tmp.close()
            with tarfile.open(tmp.name, "w:xz") as tf:
                for f in entry.files:
                    try:
                        if os.path.exists(f) or os.path.islink(f):
                            tf.add(f, arcname=os.path.join(entry.package, os.path.relpath(f, "/")))
                    except Exception:
                        continue
            dest = self.backup_dir / out_name
            os.replace(tmp.name, dest)
            if self.logger:
                self.logger.info("remove.backup_ok", f"backup created for {entry.package}", path=str(dest))
            return str(dest)
        except Exception as e:
            if self.logger:
                self.logger.error("remove.backup_fail", f"backup failed for {entry.package}: {e}")
            return None

    # ---------------- remove single entry ----------------
    def _remove_files_entry(self, entry: RemovalPlanEntry, use_sandbox: Optional[bool] = None, fakeroot: bool = False) -> Tuple[bool, str]:
        """
        Remove files for the plan entry. If sandbox available and use_sandbox True, run inside sandbox.
        Returns (ok, message)
        """
        use_sandbox = self.use_sandbox if use_sandbox is None else bool(use_sandbox)
        if self.dry_run:
            return True, "dry-run: no files removed"

        # check safety for each file
        for f in entry.files:
            if not self._is_safe_path(f):
                msg = f"unsafe path refused: {f}"
                if self.logger:
                    self.logger.error("remove.unsafe", msg, path=f)
                return False, msg

        if use_sandbox and self.sandbox:
            # create a script to remove the files and run inside sandbox
            try:
                script = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".sh")
                script.write("#!/bin/sh\nset -e\n")
                for f in entry.files:
                    # rm -rf safe quoting
                    script.write(f"rm -rf -- {shlex_quote(f)}\n")
                script.close()
                os.chmod(script.name, 0o755)
                try:
                    res = self.sandbox.run_in_sandbox([script.name], workdir=None, env=None, binds=None, ro_binds=None, backend=None, use_fakeroot=fakeroot, timeout=int(self._cfg_get("remove.sandbox_timeout", 600)))
                    rc, out, err = res.rc, res.stdout, res.stderr
                    ok = rc == 0
                    msg = (out or "") + (err or "")
                    return ok, msg
                finally:
                    try:
                        os.unlink(script.name)
                    except Exception:
                        pass
            except Exception as e:
                return False, f"sandbox removal exception: {e}"
        else:
            # direct removal on host
            failures = []
            for f in entry.files:
                try:
                    p = Path(f)
                    if p.is_symlink() or p.is_file():
                        p.unlink()
                    elif p.is_dir():
                        shutil.rmtree(str(p))
                    else:
                        # not exists
                        continue
                except Exception as e:
                    failures.append(f"{f}: {e}")
            if failures:
                return False, "; ".join(failures)
            return True, "removed"

    # ---------------- rollback ----------------
    def restore_backup(self, backup_path: str) -> Tuple[bool, str]:
        """
        Restore a backup tar.xz produced by create_backup_for_entry.
        """
        try:
            p = Path(backup_path)
            if not p.exists():
                return False, "backup missing"
            # open and extract safely - extract members under package/<relpath> -> restore to /
            with tarfile.open(str(p), mode="r:xz") as tf:
                members = tf.getmembers()
                for m in members:
                    # strip top-level component
                    parts = m.name.split("/", 1)
                    if len(parts) == 2:
                        m.name = parts[1]
                    else:
                        m.name = parts[-1]
                    # prevent path traversal
                    if m.name.startswith(".."):
                        continue
                    tf.extract(m, path="/")
            return True, "restored"
        except Exception as e:
            return False, str(e)

    # ---------------- high-level remove flow ----------------
    def remove_packages(self, package_names: List[str], confirm: Optional[bool] = None, purge: bool = False, parallel: Optional[int] = None, use_sandbox: Optional[bool] = None, fakeroot: bool = False) -> Dict[str, Any]:
        """
        High-level function:
         - build plan
         - for each entry: backup (if enabled), remove files, optionally purge configs
         - if failure: attempt rollback from backup
        Returns a structured report.
        """
        start_total = time.time()
        parallel = parallel or self.parallel
        use_sandbox = self.use_sandbox if use_sandbox is None else bool(use_sandbox)
        # build plan
        plan = self.build_plan_for_packages(package_names, include_configs=purge)
        # confirmation
        if confirm is None:
            confirm = self.auto_confirm or (not self.require_confirm)
        if not confirm and not self.auto_confirm and not self.dry_run:
            if not self._prompt_confirm(plan):
                return {"ok": False, "reason": "user_cancelled"}

        # audit start
        self._audit_report("remove.run", ",".join(package_names), "start", {"count": len(plan)})

        # progress
        progress_ctx = None
        if self.logger:
            try:
                progress_ctx = self.logger.progress(f"Removing {len(plan)} packages", total=len(plan))
            except Exception:
                progress_ctx = None

        results = []
        failures = []

        def worker(entry: RemovalPlanEntry) -> Dict[str, Any]:
            ent_meta = {"package": entry.package, "size_bytes": entry.size_bytes, "files": len(entry.files)}
            self._record_phase(entry.package, "remove.start", "pending", meta=ent_meta)
            # pre-remove hook
            if self.hooks:
                try:
                    self.hooks.run("pre_remove", {"package": entry.package, "files": entry.files, "meta": ent_meta})
                except Exception:
                    pass
            # backup
            backup = None
            try:
                backup = self.create_backup_for_entry(entry)
                entry.backup = backup
                if backup and self.hooks:
                    try:
                        self.hooks.run("post_backup", {"package": entry.package, "backup": backup})
                    except Exception:
                        pass
            except Exception as e:
                if self.logger:
                    self.logger.warning("remove.backup_exception", f"backup exception for {entry.package}: {e}")

            # perform removal
            ok, msg = self._remove_files_entry(entry, use_sandbox=use_sandbox, fakeroot=fakeroot)
            if ok:
                # optionally purge config metadata via DB
                if purge and self.db and hasattr(self.db, "purge_package_metadata"):
                    try:
                        self.db.purge_package_metadata(entry.package)
                    except Exception:
                        pass
                self._record_phase(entry.package, "remove.done", "ok", meta={"backup": backup})
                self._audit_report("remove.package", entry.package, "ok", {"backup": backup})
                if self.hooks:
                    try:
                        self.hooks.run("post_remove", {"package": entry.package, "ok": True, "backup": backup})
                    except Exception:
                        pass
                return {"package": entry.package, "ok": True, "backup": backup, "message": msg}
            else:
                # attempt rollback if backup exists
                rolled = False
                roll_msg = ""
                if backup:
                    try:
                        r_ok, r_msg = self.restore_backup(backup)
                        rolled = r_ok
                        roll_msg = r_msg
                    except Exception as e:
                        roll_msg = str(e)
                self._record_phase(entry.package, "remove.fail", "fail", meta={"error": msg, "rollback": rolled})
                self._audit_report("remove.package", entry.package, "fail", {"error": msg, "rollback": rolled})
                if self.hooks:
                    try:
                        self.hooks.run("post_remove", {"package": entry.package, "ok": False, "error": msg, "rollback": rolled})
                    except Exception:
                        pass
                return {"package": entry.package, "ok": False, "error": msg, "rollback": rolled, "rollback_msg": roll_msg}

        # execute in parallel
        with ThreadPoolExecutor(max_workers=max(1, parallel)) as ex:
            futures = {ex.submit(worker, e): e for e in plan}
            for fut in as_completed(futures):
                e = futures[fut]
                try:
                    r = fut.result()
                except Exception as exc:
                    r = {"package": e.package, "ok": False, "error": str(exc)}
                results.append(r)
                if not r.get("ok"):
                    failures.append(r)
                # update progress context if present
                try:
                    if progress_ctx:
                        pass
                except Exception:
                    pass

        if progress_ctx:
            try:
                progress_ctx.__exit__(None, None, None)
            except Exception:
                pass

        report = {
            "timestamp": self._now_ts(),
            "requested": package_names,
            "results": results,
            "failed": failures,
            "ok": len(failures) == 0,
            "duration": round(time.time() - start_total, 3)
        }
        path = self._save_report(report)
        self._record_phase(None, "remove.run", "ok" if report["ok"] else "partial", meta={"report": str(path), "failed": len(failures)})
        # audit final
        self._audit_report("remove.run", ",".join(package_names), "ok" if report["ok"] else "partial", {"report": str(path)})
        return report

    # ---------------- CLI / interactive ----------------
    def _prompt_confirm(self, plan: List[RemovalPlanEntry]) -> bool:
        nremove = sum(1 for p in plan if p.action == "remove")
        npurge = sum(1 for p in plan if p.action == "purge")
        if RICH and _console:
            _console.print(f"[bold]Planned actions: remove={nremove}, purge={npurge}[/bold]")
        else:
            print(f"Planned actions: remove={nremove}, purge={npurge}")
        try:
            ans = input("Proceed? [y/N]: ").strip().lower()
            return ans in ("y", "yes")
        except Exception:
            return False

    def run_cli(self, argv: Optional[List[str]] = None) -> int:
        import argparse
        parser = argparse.ArgumentParser(prog="newpkg-remove", description="Remove packages safely with newpkg")
        parser.add_argument("packages", nargs="+", help="package names to remove")
        parser.add_argument("--purge", action="store_true", help="remove configs and metadata")
        parser.add_argument("--yes", "-y", action="store_true", help="auto confirm")
        parser.add_argument("--dry-run", action="store_true", help="do not perform destructive actions")
        parser.add_argument("--parallel", type=int, help="override parallel workers")
        parser.add_argument("--report-dir", help="override report dir")
        parser.add_argument("--no-sandbox", action="store_true", help="do not use sandbox even if available")
        parser.add_argument("--fakeroot", action="store_true", help="use fakeroot inside sandbox")
        args = parser.parse_args(argv or sys.argv[1:])

        if args.report_dir:
            self.report_dir = Path(args.report_dir)
            self.report_dir.mkdir(parents=True, exist_ok=True)
        if args.parallel:
            self.parallel = args.parallel
        if args.yes:
            self.auto_confirm = True
        if args.dry_run:
            self.dry_run = True
        if args.no_sandbox:
            use_sandbox = False
        else:
            use_sandbox = None  # preserve default

        report = self.remove_packages(args.packages, confirm=self.auto_confirm, purge=args.purge, parallel=self.parallel, use_sandbox=use_sandbox, fakeroot=args.fakeroot)
        ok = report.get("ok", False)
        if RICH and _console:
            if ok:
                _console.print(f"[green]Removal completed OK — report saved[/green]")
            else:
                _console.print(f"[yellow]Removal finished with failures — check report[/yellow]")
        else:
            if ok:
                print("Removal completed OK")
            else:
                print("Removal finished with failures")
        return 0 if ok else 2


# ---------------- utility ----------------
def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


# ---------------- module-level convenience ----------------
_default_remove: Optional[NewpkgRemove] = None


def get_remove(cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None, audit: Any = None) -> NewpkgRemove:
    global _default_remove
    if _default_remove is None:
        _default_remove = NewpkgRemove(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox, audit=audit)
    return _default_remove


# ---------------- CLI entrypoint ----------------
if __name__ == "__main__":
    remover = get_remove()
    sys.exit(remover.run_cli())
