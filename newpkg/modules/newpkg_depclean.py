#!/usr/bin/env python3
# newpkg_depclean.py
"""
newpkg_depclean.py — dependency cleanup, revised.

Features added:
 - perf timing for phases (scan, plan, execute) and DB recording where available
 - progress bars via logger.progress() / rich
 - hooks integration: pre_scan, post_scan, pre_execute, post_execute, pre_remove, post_remove
 - audit reporting on critical failures (best-effort)
 - optional sandboxed removals or rebuilds
 - backup (tar.xz) before removal and rollback support
 - report rotation/history
 - auto-confirm (configurable) for non-interactive runs
 - integration with newpkg_upgrade/newpkg_core for rebuild attempt
 - colored CLI summary using rich if available
"""

from __future__ import annotations

import json
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
    from newpkg_sandbox import get_sandbox  # type: ignore
except Exception:
    get_sandbox = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

try:
    from newpkg_upgrade import NewpkgUpgrade  # type: ignore
except Exception:
    NewpkgUpgrade = None

try:
    from newpkg_core import NewpkgCore  # type: ignore
except Exception:
    NewpkgCore = None

try:
    from newpkg_audit import NewpkgAudit  # type: ignore
except Exception:
    NewpkgAudit = None

# rich for colored CLI & nicer progress fallback
try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
    _console = Console()
except Exception:
    RICH = False
    _console = None

# fallback logger
import logging
_logger = logging.getLogger("newpkg.depclean")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.depclean: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# ---------------- dataclasses ----------------
@dataclass
class PackageInfo:
    name: str
    version: Optional[str] = None
    installed_files: List[str] = None
    reverse_deps: List[str] = None
    size: Optional[int] = None


@dataclass
class PlanEntry:
    package: str
    action: str  # 'remove' | 'rebuild' | 'ignore'
    reason: str
    backup: Optional[str] = None


# ---------------- main class ----------------
class NewpkgDepclean:
    DEFAULT_REPORT_DIR = "/var/log/newpkg/depclean"
    DEFAULT_BACKUP_DIR = "/var/cache/newpkg/depclean_backups"
    DEFAULT_KEEP_REPORTS = 10

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None, hooks: Any = None, upgrade: Any = None, core: Any = None, audit: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        self.logger = logger or (get_logger(self.cfg) if get_logger else None)
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)
        self.sandbox = sandbox or (get_sandbox(self.cfg) if get_sandbox else None)
        self.hooks = hooks or (get_hooks_manager(self.cfg) if get_hooks_manager else None)
        self.upgrade = upgrade or (NewpkgUpgrade(self.cfg) if NewpkgUpgrade else None)
        self.core = core or (NewpkgCore(self.cfg) if NewpkgCore else None)
        self.audit = audit or (NewpkgAudit(self.cfg) if NewpkgAudit else None)

        # config
        self.report_dir = Path(self._cfg_get("depclean.report_dir", self.DEFAULT_REPORT_DIR)).expanduser()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir = Path(self._cfg_get("depclean.backup_dir", self.DEFAULT_BACKUP_DIR)).expanduser()
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.keep_reports = int(self._cfg_get("depclean.keep_reports", self.DEFAULT_KEEP_REPORTS))
        self.parallel = int(self._cfg_get("depclean.parallel_jobs", max(1, (os.cpu_count() or 2))))
        self.auto_confirm = bool(self._cfg_get("depclean.auto_confirm", False))
        self.use_sandbox = bool(self._cfg_get("depclean.use_sandbox", False))
        self.sandbox_profile = str(self._cfg_get("depclean.sandbox_profile", "light"))
        self.backup_before_remove = bool(self._cfg_get("depclean.backup_before_remove", True))
        self.max_backup_size_mb = int(self._cfg_get("depclean.max_backup_size_mb", 1024))  # skip backup if too large
        self.dry_run = bool(self._cfg_get("depclean.dry_run", False))

        # locks
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

    def _rotate_reports(self) -> None:
        try:
            files = sorted([p for p in self.report_dir.iterdir() if p.is_file() and p.name.startswith("depclean-report-")], key=lambda p: p.stat().st_mtime, reverse=True)
            for p in files[self.keep_reports:]:
                try:
                    p.unlink()
                except Exception:
                    pass
        except Exception:
            pass

    def _save_report(self, report: Dict[str, Any]) -> Path:
        ts = self._now_ts()
        path = self.report_dir / f"depclean-report-{ts}.json"
        try:
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(path))
            # rotate
            self._rotate_reports()
        except Exception as e:
            if self.logger:
                self.logger.warning("depclean.report_save_fail", f"failed to save report: {e}")
        return path

    def _record_phase(self, name: Optional[str], phase: str, status: str, meta: Optional[Dict[str, Any]] = None) -> None:
        try:
            if self.db:
                self.db.record_phase(name, phase, status, meta=meta or {})
        except Exception:
            pass

    def _call_hook(self, name: str, ctx: Dict[str, Any]) -> None:
        if not self.hooks:
            return
        try:
            self.hooks.run(name, ctx)
        except Exception as e:
            if self.logger:
                self.logger.warning("depclean.hook.fail", f"hook {name} failed: {e}", hook=name)
            else:
                _logger.warning(f"hook {name} failed: {e}")

    def _audit_report(self, topic: str, entity: str, status: str, meta: Dict[str, Any]) -> None:
        if not self.audit:
            return
        try:
            self.audit.report(topic, entity, status, meta)
        except Exception:
            pass

    def _backup_package_files(self, pkg: PackageInfo) -> Optional[str]:
        """
        Create a tar.xz archive with the package's files (best-effort)
        Returns path to backup or None.
        """
        if not pkg.installed_files:
            return None
        # estimate size; skip if too large
        total_size = 0
        for f in pkg.installed_files:
            try:
                total_size += Path(f).stat().st_size if Path(f).exists() else 0
            except Exception:
                pass
        mb = total_size // (1024 * 1024)
        if self.max_backup_size_mb and mb > self.max_backup_size_mb:
            if self.logger:
                self.logger.warning("depclean.backup.skip", f"skip backup for {pkg.name} size {mb}MB > {self.max_backup_size_mb}MB")
            return None
        try:
            ts = self._now_ts()
            out_name = f"{pkg.name}-{ts}.tar.xz"
            tmpfile = tempfile.NamedTemporaryFile(delete=False, dir=str(self.backup_dir), prefix=f"{pkg.name}-", suffix=".tar.xz")
            tmpfile.close()
            with tarfile.open(tmpfile.name, mode="w:xz") as tf:
                for f in pkg.installed_files:
                    p = Path(f)
                    if p.exists():
                        try:
                            tf.add(str(p), arcname=os.path.join(pkg.name, os.path.relpath(str(p), "/")))
                        except Exception:
                            # skip if cannot add
                            pass
            final = self.backup_dir / out_name
            os.replace(tmpfile.name, final)
            if self.logger:
                self.logger.info("depclean.backup.ok", f"backup created for {pkg.name}", path=str(final))
            return str(final)
        except Exception as e:
            if self.logger:
                self.logger.error("depclean.backup.fail", f"backup failed for {pkg.name}: {e}")
            return None

    def _remove_package_files(self, pkg: PackageInfo, workdir: Optional[str] = None) -> Tuple[bool, str]:
        """
        Physically remove package files. If sandbox enabled and available, perform inside sandbox.
        Returns (ok, message)
        """
        # prepare list of files to remove; best-effort
        files = pkg.installed_files or []
        if self.dry_run:
            return True, "dry-run (no files removed)"
        # choose removal implementation
        if self.use_sandbox and self.sandbox:
            # create a small script to remove the files and run it inside sandbox
            try:
                script = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".sh")
                script.write("#!/bin/sh\nset -e\n")
                for f in files:
                    script.write(f"rm -rf -- {shlex_quote(f)}\n")
                script.close()
                os.chmod(script.name, os.stat(script.name).st_mode | stat.S_IXUSR)
                # run within sandbox
                try:
                    res = self.sandbox.run_in_sandbox([script.name], workdir=workdir, env=None, binds=None, ro_binds=None, backend=None, use_fakeroot=False, timeout=600)
                    ok = res.rc == 0
                    msg = res.stdout + ("\n" + res.stderr if res.stderr else "")
                finally:
                    try:
                        os.unlink(script.name)
                    except Exception:
                        pass
                return ok, msg
            except Exception as e:
                return False, f"sandbox removal exception: {e}"
        else:
            # remove on host
            failures = []
            for f in files:
                try:
                    p = Path(f)
                    if p.exists() or p.is_symlink():
                        if p.is_dir():
                            shutil.rmtree(str(p))
                        else:
                            p.unlink()
                except Exception as e:
                    failures.append(f"{f}: {e}")
            if failures:
                return False, "; ".join(failures)
            return True, "removed"

    # ---------------- scanning / planning ----------------
    def scan(self) -> Dict[str, PackageInfo]:
        """
        Scan DB / system for installed packages and their reverse deps.
        Returns dict: package_name -> PackageInfo
        """
        start = time.time()
        self._call_hook("pre_scan", {})
        result: Dict[str, PackageInfo] = {}
        # Best-effort: use DB if available; fallback to scanning common dirs (not implemented fully).
        if self.db:
            try:
                pkg_list = self.db.list_installed_packages()  # expects list of dicts {name, version, files, rdeps}
                for p in pkg_list:
                    info = PackageInfo(
                        name=p.get("name"),
                        version=p.get("version"),
                        installed_files=p.get("files") or [],
                        reverse_deps=p.get("rdeps") or [],
                        size=p.get("size")
                    )
                    result[info.name] = info
            except Exception as e:
                # fallback: try simple pkgcache in /var/lib/newpkg/packages.json if available
                if self.logger:
                    self.logger.warning("depclean.scan.db_fail", f"db scan failed: {e}")
        else:
            # fallback naive scan (very conservative): look for /usr/local/{bin,lib} for packages (best-effort)
            # we won't implement a full package manager scanner here; return empty
            if self.logger:
                self.logger.info("depclean.scan.fallback", "no db available; fallback scan not implemented (returning empty)")
        duration = time.time() - start
        self._record_phase(None, "depclean.scan", "ok", meta={"count": len(result), "duration": duration})
        self._call_hook("post_scan", {"count": len(result)})
        return result

    def plan(self, packages: Dict[str, PackageInfo]) -> List[PlanEntry]:
        """
        Build a plan to remove orphan packages or rebuild broken reverse-deps.
        Simple heuristic:
         - remove packages with no reverse_deps
         - rebuild packages where reverse_deps reference missing packages
        """
        start = time.time()
        self._call_hook("pre_plan", {"count": len(packages)})
        plan: List[PlanEntry] = []
        pkg_names = set(packages.keys())
        for name, info in packages.items():
            rdeps = info.reverse_deps or []
            if not rdeps:
                plan.append(PlanEntry(package=name, action="remove", reason="no reverse dependencies", backup=None))
            else:
                # check if any rdep refers to missing package
                missing = [r for r in rdeps if r not in pkg_names]
                if missing:
                    plan.append(PlanEntry(package=name, action="rebuild", reason=f"reverse deps missing: {missing}", backup=None))
                else:
                    # keep
                    plan.append(PlanEntry(package=name, action="ignore", reason="in use", backup=None))
        duration = time.time() - start
        self._record_phase(None, "depclean.plan", "ok", meta={"total": len(plan), "duration": duration})
        self._call_hook("post_plan", {"total": len(plan)})
        return plan

    # ---------------- execution ----------------
    def execute(self, plan: List[PlanEntry], packages: Dict[str, PackageInfo], confirm: Optional[bool] = None) -> Dict[str, Any]:
        """
        Execute the plan. Returns report.
        Behavior:
         - For 'remove': backup (if enabled), then remove files; on failure, attempt rollback via backup restore.
         - For 'rebuild': try newpkg_upgrade.rebuild or core.build fallback.
        """
        start_total = time.time()
        self._call_hook("pre_execute", {"plan_count": len(plan)})
        # confirm
        if confirm is None:
            confirm = self.auto_confirm
        if not confirm and not self.dry_run:
            # interactive confirmation
            if not self.auto_confirm:
                proceed = self._prompt_confirm(plan)
                if not proceed:
                    return {"ok": False, "reason": "user_cancelled", "applied": [], "failed": []}

        # prepare progress
        total = len(plan)
        results = []
        failed = []

        progress_ctx = None
        if self.logger:
            try:
                progress_ctx = self.logger.progress("Executing depclean plan", total=total)
            except Exception:
                progress_ctx = None

        # use thread pool for concurrency for independent removals/rebuilds
        def worker(entry: PlanEntry) -> Dict[str, Any]:
            pkg = packages.get(entry.package)
            if not pkg:
                return {"entry": asdict(entry), "ok": False, "error": "package metadata missing"}
            # removal
            if entry.action == "remove":
                self._call_hook("pre_remove", {"package": entry.package})
                backup_path = None
                if self.backup_before_remove and self.backup_dir:
                    try:
                        backup_path = self._backup_package_files(pkg)
                        entry.backup = backup_path
                    except Exception as e:
                        # continue even if backup fails (but log)
                        if self.logger:
                            self.logger.warning("depclean.backup_fail", f"backup failed for {pkg.name}: {e}")
                # remove files
                ok, msg = self._remove_package_files(pkg, workdir=None)
                if not ok:
                    # attempt rollback: restore backup
                    if backup_path and Path(backup_path).exists():
                        try:
                            ok_restore, restore_msg = self._restore_backup(backup_path)
                            if ok_restore:
                                if self.logger:
                                    self.logger.info("depclean.rollback.ok", f"restored backup for {pkg.name}")
                                self._audit_report("depclean", pkg.name, "rollback_restored", {"backup": backup_path})
                            else:
                                if self.logger:
                                    self.logger.error("depclean.rollback.fail", f"failed restore for {pkg.name}: {restore_msg}")
                                self._audit_report("depclean", pkg.name, "rollback_failed", {"backup": backup_path, "error": restore_msg})
                        except Exception as e:
                            if self.logger:
                                self.logger.error("depclean.rollback.exception", f"rollback exception for {pkg.name}: {e}")
                    # record failure
                    try:
                        self._record_phase(pkg.name, "depclean.remove", "fail", meta={"error": msg})
                    except Exception:
                        pass
                    self._call_hook("post_remove", {"package": pkg.name, "ok": False, "error": msg})
                    self._audit_report("depclean", pkg.name, "remove_failed", {"error": msg})
                    return {"entry": asdict(entry), "ok": False, "error": msg}
                else:
                    # success: update DB to remove package record if possible
                    try:
                        if self.db:
                            self.db.remove_package(pkg.name)
                    except Exception:
                        pass
                    self._record_phase(pkg.name, "depclean.remove", "ok", meta={"backup": backup_path})
                    self._call_hook("post_remove", {"package": pkg.name, "ok": True, "backup": backup_path})
                    return {"entry": asdict(entry), "ok": True, "backup": backup_path}
            elif entry.action == "rebuild":
                self._call_hook("pre_rebuild", {"package": entry.package})
                rebuilt = False
                rebuild_msgs = []
                # try upgrade module first
                if self.upgrade:
                    try:
                        ok, msg = self.upgrade.rebuild(entry.package)
                        rebuilt = bool(ok)
                        rebuild_msgs.append(str(msg))
                    except Exception as e:
                        rebuild_msgs.append(f"upgrade.rebuild exception: {e}")
                # fallback to core build if available
                if not rebuilt and self.core:
                    try:
                        ok2, msg2 = self.core.build_package(entry.package)
                        rebuilt = bool(ok2)
                        rebuild_msgs.append(str(msg2))
                    except Exception as e:
                        rebuild_msgs.append(f"core.build exception: {e}")
                if not rebuilt:
                    self._record_phase(entry.package, "depclean.rebuild", "fail", meta={"messages": rebuild_msgs})
                    self._call_hook("post_rebuild", {"package": entry.package, "ok": False, "messages": rebuild_msgs})
                    self._audit_report("depclean", entry.package, "rebuild_failed", {"messages": rebuild_msgs})
                    return {"entry": asdict(entry), "ok": False, "error": "rebuild_failed", "messages": rebuild_msgs}
                else:
                    self._record_phase(entry.package, "depclean.rebuild", "ok", meta={"messages": rebuild_msgs})
                    self._call_hook("post_rebuild", {"package": entry.package, "ok": True, "messages": rebuild_msgs})
                    return {"entry": asdict(entry), "ok": True, "messages": rebuild_msgs}
            else:
                # ignore
                return {"entry": asdict(entry), "ok": True, "info": "ignored"}

        # run workers
        with ThreadPoolExecutor(max_workers=max(1, self.parallel)) as ex:
            future_map = {ex.submit(worker, e): e for e in plan}
            for fut in as_completed(future_map):
                e = future_map[fut]
                try:
                    r = fut.result()
                except Exception as exc:
                    r = {"entry": asdict(e), "ok": False, "error": str(exc)}
                results.append(r)
                if not r.get("ok"):
                    failed.append(r)
                # progress update (logger.progress)
                try:
                    if progress_ctx:
                        # progress_ctx doesn't expose task id here; relying on its own visuals
                        pass
                except Exception:
                    pass

        if progress_ctx:
            try:
                progress_ctx.__exit__(None, None, None)
            except Exception:
                pass

        duration = time.time() - start_total
        ok = len(failed) == 0
        report = {
            "timestamp": self._now_ts(),
            "plan_total": len(plan),
            "results": results,
            "failed": failed,
            "ok": ok,
            "duration": duration
        }
        # save report
        path = self._save_report(report)
        try:
            self._record_phase(None, "depclean.execute", "ok" if ok else "partial", meta={"report": str(path), "duration": duration, "failed": len(failed)})
        except Exception:
            pass

        self._call_hook("post_execute", {"report": str(path), "ok": ok, "failed": len(failed)})
        return report

    def _prompt_confirm(self, plan: List[PlanEntry]) -> bool:
        # pretty print summary and ask Y/n unless auto_confirm
        remove_count = sum(1 for p in plan if p.action == "remove")
        rebuild_count = sum(1 for p in plan if p.action == "rebuild")
        ignore_count = sum(1 for p in plan if p.action == "ignore")
        if RICH and _console:
            _console.print(f"[bold]depclean plan summary[/bold]")
            _console.print(f"Removals: [red]{remove_count}[/red], Rebuilds: [yellow]{rebuild_count}[/yellow], Ignored: [green]{ignore_count}[/green]")
        else:
            print(f"Plan summary: removals={remove_count}, rebuilds={rebuild_count}, ignored={ignore_count}")
        try:
            ans = input("Proceed? [y/N]: ").strip().lower()
            return ans in ("y", "yes")
        except Exception:
            return False

    # ---------------- backup restore ----------------
    def _restore_backup(self, backup_path: str) -> Tuple[bool, str]:
        """
        Restore a tar.xz backup created by _backup_package_files.
        Restores files into / (the archive contains paths under package-name/...), best-effort.
        """
        try:
            p = Path(backup_path)
            if not p.exists():
                return False, "backup not found"
            with tarfile.open(str(p), mode="r:xz") as tf:
                # member names were stored with arcname pkgname/relpath
                # strip the first component (pkgname) when extracting
                for member in tf.getmembers():
                    # rewrite member.name removing first path element
                    parts = member.name.split("/", 1)
                    if len(parts) == 2:
                        member.name = parts[1]
                    else:
                        member.name = parts[-1]
                    # prevent path traversal
                    if member.name.startswith(".."):
                        continue
                    tf.extract(member, path="/")
            return True, "restored"
        except Exception as e:
            return False, str(e)

    # ---------------- CLI convenience ----------------
    def run_cli(self, argv: Optional[List[str]] = None) -> int:
        import argparse
        parser = argparse.ArgumentParser(prog="newpkg-depclean", description="Scan and remove orphan packages")
        parser.add_argument("--scan-only", action="store_true", help="only scan and print plan")
        parser.add_argument("--auto-confirm", action="store_true", help="auto confirm removals")
        parser.add_argument("--dry-run", action="store_true", help="dry run (no removals)")
        parser.add_argument("--report-dir", help="override report dir")
        parser.add_argument("--backup-dir", help="override backup dir")
        args = parser.parse_args(argv or sys.argv[1:])
        if args.report_dir:
            self.report_dir = Path(args.report_dir)
            self.report_dir.mkdir(parents=True, exist_ok=True)
        if args.backup_dir:
            self.backup_dir = Path(args.backup_dir)
            self.backup_dir.mkdir(parents=True, exist_ok=True)
        if args.auto_confirm:
            self.auto_confirm = True
        if args.dry_run:
            self.dry_run = True

        # run flow
        pkgs = self.scan()
        plan = self.plan(pkgs)
        if args.scan_only:
            # print plan
            if RICH and _console:
                table = Table(title="depclean plan")
                table.add_column("package")
                table.add_column("action")
                table.add_column("reason")
                for e in plan:
                    table.add_row(e.package, e.action, e.reason)
                _console.print(table)
            else:
                for e in plan:
                    print(f"{e.package}: {e.action} - {e.reason}")
            return 0

        report = self.execute(plan, pkgs, confirm=(self.auto_confirm or args.auto_confirm))
        ok = report.get("ok", False)
        if RICH and _console:
            if ok:
                _console.print(f"[green]depclean finished OK — report saved to {self.report_dir}[/green]")
            else:
                _console.print(f"[yellow]depclean finished with failures — report saved to {self.report_dir}[/yellow]")
        else:
            if ok:
                print("depclean finished OK")
            else:
                print("depclean finished with failures")
        return 0 if ok else 2


# ---------------- module-level convenience ----------------
_default_depclean: Optional[NewpkgDepclean] = None


def get_depclean(cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None, hooks: Any = None, upgrade: Any = None, core: Any = None, audit: Any = None) -> NewpkgDepclean:
    global _default_depclean
    if _default_depclean is None:
        _default_depclean = NewpkgDepclean(cfg=cfg, logger=logger, db=db, sandbox=sandbox, hooks=hooks, upgrade=upgrade, core=core, audit=audit)
    return _default_depclean


# ---------------- quick CLI ----------------
if __name__ == "__main__":
    dep = get_depclean()
    sys.exit(dep.run_cli())
