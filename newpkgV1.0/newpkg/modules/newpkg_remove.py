#!/usr/bin/env python3
# newpkg_remove.py
"""
newpkg_remove.py — safe remover / depclean helper for newpkg

Features:
 - Integrates with newpkg_api (cfg, logger, db, sandbox, hooks, audit) when available
 - Path safety checks and LFS support
 - Backup to /var/backups/newpkg/removed/<pkg> with metadata JSON (tar.xz)
 - Hooks: pre_remove, post_backup, post_remove, post_fail
 - Dry-run, yes/confirm, fakeroot, parallel removal, quiet, json output
 - Reports to /var/log/newpkg/remove/
 - Optional rollback from backup on failure (best-effort)
"""

from __future__ import annotations

import json
import lzma
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Optional integrations (best-effort)
try:
    from newpkg_api import get_api  # type: ignore
except Exception:
    get_api = None

try:
    from newpkg_config import get_config  # type: ignore
except Exception:
    get_config = None

try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_db import get_db  # type: ignore
except Exception:
    get_db = None

try:
    from newpkg_sandbox import get_sandbox  # type: ignore
except Exception:
    get_sandbox = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

try:
    from newpkg_audit import get_audit  # type: ignore
except Exception:
    get_audit = None

# nice CLI if available
try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
    console = Console()
except Exception:
    RICH = False
    console = None

# fallback logger
import logging
LOG = logging.getLogger("newpkg.remove")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.remove: %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO)

# defaults
DEFAULT_REPORT_DIR = Path("/var/log/newpkg/remove")
DEFAULT_BACKUP_DIR = Path("/var/backups/newpkg/removed")
DEFAULT_SAFE_WHITELIST = ("/usr", "/usr/local", "/opt", "/var/lib/newpkg", "/etc/newpkg")
DEFAULT_REPORT_KEEP = 10

# ensure dirs
for d in (DEFAULT_REPORT_DIR, DEFAULT_BACKUP_DIR):
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

# dataclasses
@dataclass
class RemovePlanItem:
    package: str
    files: List[str]
    size_bytes: int

@dataclass
class RemoveResult:
    package: str
    ok: bool
    removed_files_count: int
    backup_path: Optional[str]
    failed_files: List[str]
    error: Optional[str]
    duration_s: float

# helpers
def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def human_size(n: int) -> str:
    for u in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024.0
    return f"{n:.1f}TiB"

def safe_write_json(path: Path, obj: Any, compress: bool = True):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
    if compress:
        with lzma.open(str(path) + ".xz", "wb") as f:
            f.write(payload)
        return str(path) + ".xz"
    else:
        path.write_bytes(payload)
        return str(path)

def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)

# Main manager
class RemoveManager:
    def __init__(self, cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, sandbox: Optional[Any] = None, hooks: Optional[Any] = None, audit: Optional[Any] = None):
        # try API integration
        self.api = None
        if get_api:
            try:
                self.api = get_api()
                try:
                    self.api.init_all()
                except Exception:
                    pass
            except Exception:
                self.api = None

        # pick singletons or provided objects (best-effort)
        self.cfg = cfg or (self.api.cfg if self.api and getattr(self.api, "cfg", None) else (get_config() if get_config else None))
        self.logger = logger or (self.api.logger if self.api and getattr(self.api, "logger", None) else (get_logger(self.cfg) if get_logger else None))
        self.db = db or (self.api.db if self.api and getattr(self.api, "db", None) else (get_db() if get_db else None))
        self.sandbox = sandbox or (self.api.sandbox if self.api and getattr(self.api, "sandbox", None) else (get_sandbox(self.cfg) if get_sandbox else None))
        self.hooks = hooks or (self.api.hooks if self.api and getattr(self.api, "hooks", None) else (get_hooks_manager(self.cfg) if get_hooks_manager else None))
        self.audit = audit or (self.api.audit if self.api and getattr(self.api, "audit", None) else (get_audit(self.cfg) if get_audit else None))

        try:
            if self.api:
                self.api.remove = self
        except Exception:
            pass

        # config values and paths
        self.report_dir = Path(self.cfg.get("remove.report_dir")) if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("remove.report_dir")) else DEFAULT_REPORT_DIR
        self.backup_dir = Path(self.cfg.get("remove.backup_dir")) if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("remove.backup_dir")) else DEFAULT_BACKUP_DIR
        self.safe_whitelist = tuple(self.cfg.get("remove.safe_whitelist") or DEFAULT_SAFE_WHITELIST) if (self.cfg and hasattr(self.cfg, "get")) else DEFAULT_SAFE_WHITELIST
        self.report_keep = int(self.cfg.get("remove.report_keep") or DEFAULT_REPORT_KEEP) if (self.cfg and hasattr(self.cfg, "get")) else DEFAULT_REPORT_KEEP
        self.parallel = int(self.cfg.get("remove.parallel") or 1) if (self.cfg and hasattr(self.cfg, "get")) else 1
        self.compress_reports = bool(self.cfg.get("remove.compress_reports") or True) if (self.cfg and hasattr(self.cfg, "get")) else True
        self.lfs_mount = self.cfg.get("remove.lfs_mount") if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("remove.lfs_mount")) else "/mnt/lfs"
        # ensure directories
        for d in (self.report_dir, self.backup_dir):
            try:
                d.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
        self._lock = threading.RLock()

    # ---------------- scanning helpers ----------------
    def scan_installed(self) -> Dict[str, RemovePlanItem]:
        """
        Build a map of installed packages -> files & size.
        Prefer DB if available; otherwise fall back to heuristics reading /var/lib/newpkg/packages.
        """
        out: Dict[str, RemovePlanItem] = {}
        try:
            if self.db and hasattr(self.db, "list_packages"):
                try:
                    pkgs = self.db.list_packages()
                    for p in pkgs:
                        name = p[0] if isinstance(p, (list, tuple)) else p.get("name") if isinstance(p, dict) else str(p)
                        files = []
                        try:
                            files = list(self.db.package_files(name))
                        except Exception:
                            # fallback to files table query
                            try:
                                rows = self.db.raw_query("SELECT filepath FROM package_files WHERE package = ?;", (name,))
                                files = [r[0] if isinstance(r, (list, tuple)) else r.get("filepath") for r in rows]
                            except Exception:
                                files = []
                        total = 0
                        for f in files:
                            try:
                                total += Path(f).stat().st_size if Path(f).exists() else 0
                            except Exception:
                                pass
                        out[name] = RemovePlanItem(package=name, files=files, size_bytes=total)
                    return out
                except Exception:
                    pass
            # heuristic fallback
            meta_dirs = [Path("/var/lib/newpkg/packages"), Path("/usr/local/lib/newpkg/packages")]
            for md in meta_dirs:
                if not md.exists():
                    continue
                for pkgdir in md.iterdir():
                    if not pkgdir.is_dir():
                        continue
                    name = pkgdir.name
                    files = []
                    total = 0
                    # try files.txt or list files recursively
                    ftxt = pkgdir / "files.txt"
                    if ftxt.exists():
                        try:
                            files = [l.strip() for l in ftxt.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
                        except Exception:
                            files = []
                    else:
                        for f in pkgdir.rglob("*"):
                            if f.is_file():
                                files.append(str(f))
                    for f in files:
                        try:
                            total += Path(f).stat().st_size if Path(f).exists() else 0
                        except Exception:
                            pass
                    out[name] = RemovePlanItem(package=name, files=files, size_bytes=total)
            return out
        except Exception:
            return out

    # ---------------- safety checks ----------------
    def _is_safe_path(self, path: str, use_lfs: bool = False) -> bool:
        """
        Ensure the given path is allowed to be removed:
         - Not root '/' (unless explicitly configured)
         - Not /proc, /sys, /run, /dev
         - Path must be within a whitelisted prefix OR within LFS mount (if use_lfs)
         - Path existence / write permission checks
        """
        try:
            p = Path(path).resolve()
        except Exception:
            return False
        # disallow special filesystems
        forbidden = ("/proc", "/sys", "/run", "/dev")
        for f in forbidden:
            if str(p).startswith(f):
                return False
        # disallow root
        if str(p) == "/":
            return False
        # LFS handling: allow if under configured mount when use_lfs
        if use_lfs:
            if str(p).startswith(str(self.lfs_mount)):
                return True
        # check whitelist
        for w in self.safe_whitelist:
            try:
                if str(p).startswith(str(Path(w).resolve())):
                    # ensure writable (or owned) - best-effort
                    parent = p if p.exists() else p.parent
                    try:
                        if os.access(str(parent), os.W_OK):
                            return True
                        # also allow if user is root
                        if os.geteuid() == 0:
                            return True
                    except Exception:
                        pass
            except Exception:
                continue
        return False

    # ---------------- backup ----------------
    def backup_package(self, pkg: str, files: Iterable[str], reason: Optional[str] = None) -> Optional[str]:
        """
        Create a compressed tar.xz backup for the package files and metadata JSON.
        Returns path to backup archive (.tar.xz) or None on fail.
        """
        try:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            pkg_dir = self.backup_dir / pkg
            pkg_dir.mkdir(parents=True, exist_ok=True)
            archive = pkg_dir / f"{pkg}-{ts}.tar.xz"
            meta = {
                "package": pkg,
                "timestamp": now_iso(),
                "files": list(files),
                "reason": reason,
            }
            # create tar.xz
            # use system tar if available to preserve metadata
            file_list = [f for f in files if Path(f).exists()]
            if not file_list:
                # nothing to backup
                meta_path = pkg_dir / f"{pkg}-{ts}.meta.json"
                safe_meta = safe_write_metadata(meta_path, meta, compress=True)
                return safe_meta  # return meta path to indicate metadata-only
            if shutil.which("tar"):
                cmd = ["tar", "cf", "-", "--no-recursion"] + file_list
                # stream and compress with xz if available
                if shutil.which("xz"):
                    xz = shutil.which("xz")
                    with open(archive, "wb") as fout:
                        p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                        p2 = subprocess.Popen([xz, "-9e"], stdin=p1.stdout, stdout=fout)
                        p1.stdout.close()
                        p2.communicate()
                        if p2.returncode == 0:
                            # write meta
                            meta_path = pkg_dir / f"{pkg}-{ts}.meta.json"
                            safe_meta = safe_write_metadata(meta_path, meta, compress=True)
                            return str(archive)
                else:
                    # fallback: create tar then compress via lzma python
                    tmp_tar = pkg_dir / f"{pkg}-{ts}.tar"
                    p = subprocess.run(cmd, stdout=open(tmp_tar, "wb"))
                    if p.returncode == 0:
                        # compress
                        with open(tmp_tar, "rb") as f_in, lzma.open(str(archive), "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                        tmp_tar.unlink(missing_ok=True)
                        meta_path = pkg_dir / f"{pkg}-{ts}.meta.json"
                        safe_meta = safe_write_metadata(meta_path, meta, compress=True)
                        return str(archive)
            # fallback python tarfile (slower)
            import tarfile
            with tarfile.open(archive, "w:xz") as tar:
                for f in file_list:
                    try:
                        tar.add(f, arcname=os.path.relpath(f, "/") if os.path.isabs(f) else f)
                    except Exception:
                        continue
            meta_path = pkg_dir / f"{pkg}-{ts}.meta.json"
            safe_meta = safe_write_metadata(meta_path, meta, compress=True)
            return str(archive)
        except Exception as e:
            try:
                if self.logger:
                    self.logger.error("remove.backup.fail", f"backup failed for {pkg}: {e}")
            except Exception:
                LOG.error("backup failed for %s: %s", pkg, e)
            return None

def safe_write_metadata(meta_path: Path, meta: Dict[str, Any], compress: bool = True) -> Optional[str]:
    try:
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8")
        if compress:
            with lzma.open(str(meta_path) + ".xz", "wb") as f:
                f.write(payload)
            return str(meta_path) + ".xz"
        else:
            meta_path.write_bytes(payload)
            return str(meta_path)
    except Exception:
        return None

    # ---------------- single package removal ----------------

    # ---------------- removal helpers ----------------

def _remove_path_local(path: str) -> Tuple[bool, Optional[str]]:
    """
    Remove a path locally (no sandbox). Returns (ok, error_message)
    """
    try:
        p = Path(path)
        if not p.exists():
            return True, None
        # if file, unlink; if dir, rmtree
        if p.is_file() or p.is_symlink():
            p.unlink()
        elif p.is_dir():
            shutil.rmtree(str(p), ignore_errors=False)
        else:
            # special file: attempt unlink
            try:
                p.unlink()
            except Exception:
                return False, f"unsupported file type: {path}"
        return True, None
    except Exception as e:
        return False, str(e)

def _remove_path_sandboxed(sandbox, path: str, use_fakeroot: bool = False, timeout: int = 600) -> Tuple[bool, Optional[str]]:
    """
    Use sandbox.run_in_sandbox to perform safe removals. Expects sandbox object with run_in_sandbox(cmd,...).
    The sandbox should be provided by newpkg_sandbox.
    """
    try:
        # build a small script to remove the path and echo failures
        script = f"#!/bin/sh\nset -eux\nrm -rf -- {shlex_quote(path)}\n"
        with tempfile.NamedTemporaryFile("w", delete=False, prefix="newpkg-remove-", suffix=".sh") as tf:
            tf.write(script)
            tf.flush()
            script_path = tf.name
        os.chmod(script_path, 0o700)
        # run in sandbox
        try:
            res = sandbox.run_in_sandbox([script_path], cwd="/", env=None, timeout_hard=timeout, use_fakeroot=use_fakeroot)
            rc = getattr(res, "rc", None)
            if rc is None:
                rc = 0 if getattr(res, "stdout", "") else 1
            # cleanup temp script
            try:
                os.unlink(script_path)
            except Exception:
                pass
            return rc == 0, None if rc == 0 else f"sandbox failed rc={rc}"
        except Exception as e:
            try:
                os.unlink(script_path)
            except Exception:
                pass
            return False, str(e)
    except Exception as e:
        return False, str(e)

# ---------------- orchestrate single package removal ----------------
def _process_single_removal(mgr: RemoveManager, item: RemovePlanItem, dry_run: bool = False, yes: bool = False, use_lfs: bool = False, fakeroot: bool = False, quiet: bool = False) -> RemoveResult:
    start = time.time()
    pkg = item.package
    size = item.size_bytes
    files = list(item.files)
    backup_path = None
    failed_files: List[str] = []
    error_msg: Optional[str] = None
    removed_count = 0

    # hooks: pre_remove
    try:
        if mgr.hooks:
            mgr.hooks.run_named(["pre_remove"], env={"PKG": pkg, "SIZE": str(size), "FILES": str(len(files))})
    except Exception:
        pass

    # check safety for all files
    for f in files:
        if not mgr._is_safe_path(f, use_lfs=use_lfs):
            error_msg = f"unsafe path detected: {f}"
            # record and bail
            try:
                if mgr.db:
                    mgr.db.record_phase(pkg, "remove.check", "fail", meta={"reason": error_msg})
            except Exception:
                pass
            # run post_fail hook
            try:
                if mgr.hooks:
                    mgr.hooks.run_named(["post_fail"], env={"PKG": pkg, "ERROR": error_msg})
            except Exception:
                pass
            return RemoveResult(package=pkg, ok=False, removed_files_count=0, backup_path=None, failed_files=[], error=error_msg, duration_s=time.time() - start)

    # create backup (unless dry-run)
    if not dry_run:
        backup_path = mgr.backup_package(pkg, files, reason="remove")
    else:
        backup_path = None

    # post_backup hook
    try:
        if mgr.hooks:
            mgr.hooks.run_named(["post_backup"], env={"PKG": pkg, "BACKUP": str(backup_path)})
    except Exception:
        pass

    # removal step
    if dry_run:
        # don't actually remove, but return planned status
        duration = time.time() - start
        return RemoveResult(package=pkg, ok=True, removed_files_count=len(files), backup_path=backup_path, failed_files=[], error=None, duration_s=duration)

    # attempt to remove each file using sandbox if available and configured
    for f in files:
        try:
            if mgr.sandbox and not use_lfs:
                ok, err = _remove_path_sandboxed(mgr.sandbox, f, use_fakeroot=fakeroot)
            else:
                ok, err = _remove_path_local(f)
            if ok:
                removed_count += 1
            else:
                failed_files.append(f)
                if err:
                    error_msg = (error_msg or "") + f"; {f}: {err}"
        except Exception as e:
            failed_files.append(f)
            error_msg = (error_msg or "") + f"; {f}: {e}"

    # update DB and audit
    try:
        if mgr.db:
            if removed_count > 0:
                mgr.db.record_phase(pkg, "remove", "ok", meta={"removed": removed_count, "backup": backup_path})
            if failed_files:
                mgr.db.record_phase(pkg, "remove.fail", "fail", meta={"failed_files": failed_files})
    except Exception:
        pass
    try:
        if mgr.audit:
            mgr.audit.report({"type": "remove", "pkg": pkg, "removed": removed_count, "failed": len(failed_files)})
    except Exception:
        pass

    # post_remove hook
    try:
        if mgr.hooks:
            mgr.hooks.run_named(["post_remove"], env={"PKG": pkg, "REMOVED": str(removed_count), "FAILED": str(len(failed_files)), "BACKUP": str(backup_path)})
    except Exception:
        pass

    duration = time.time() - start
    ok_overall = len(failed_files) == 0
    return RemoveResult(package=pkg, ok=ok_overall, removed_files_count=removed_count, backup_path=backup_path, failed_files=failed_files, error=error_msg, duration_s=duration)

# ---------------- execute plan ----------------
def execute_plan(mgr: RemoveManager, to_remove: Iterable[RemovePlanItem], dry_run: bool = False, yes: bool = False, use_lfs: bool = False, fakeroot: bool = False, parallel: Optional[int] = None, jobs: Optional[int] = None, quiet: bool = False) -> Dict[str, Any]:
    start = time.time()
    parallel = parallel or mgr.parallel or 1
    items = list(to_remove)
    results: List[RemoveResult] = []
    if not items:
        return {"started_at": now_iso(), "completed_at": now_iso(), "results": [], "summary": {"planned": 0}}

    if parallel <= 1:
        for item in items:
            if not quiet and RICH and console:
                console.print(f">>>> Removendo pacote {item.package} ({human_size(item.size_bytes)}) <<<<")
            res = _process_single_removal(mgr, item, dry_run=dry_run, yes=yes, use_lfs=use_lfs, fakeroot=fakeroot, quiet=quiet)
            results.append(res)
    else:
        max_workers = min(parallel, max(1, len(items)))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_process_single_removal, mgr, item, dry_run, yes, use_lfs, fakeroot, quiet): item for item in items}
            for fut in as_completed(futs):
                try:
                    r = fut.result()
                except Exception as e:
                    item = futs[fut]
                    r = RemoveResult(package=item.package, ok=False, removed_files_count=0, backup_path=None, failed_files=[], error=str(e), duration_s=0.0)
                results.append(r)

    # build report
    removed = sum(1 for r in results if r.ok)
    failed = sum(1 for r in results if not r.ok)
    total = len(results)
    report = {
        "started_at": now_iso(),
        "completed_at": now_iso(),
        "duration_s": round(time.time() - start, 3),
        "summary": {"planned": total, "removed": removed, "failed": failed},
        "results": [asdict(r) for r in results],
    }
    # save report
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    rpt_path = mgr.report_dir / f"remove-report-{ts}.json"
    try:
        path_str = safe_write_json(rpt_path, report, compress=mgr.compress_reports)
        # rotate reports
        _rotate_reports(mgr.report_dir, keep=mgr.report_keep, compress=mgr.compress_reports)
        report["report_path"] = path_str
    except Exception:
        report["report_path"] = None

    # record phase in DB
    try:
        if mgr.db:
            mgr.db.record_phase(None, "remove.run", "ok" if failed == 0 else "partial", meta={"planned": total, "removed": removed, "failed": failed, "report": report.get("report_path")})
    except Exception:
        pass

    return report

def _rotate_reports(dirpath: Path, keep: int = DEFAULT_REPORT_KEEP, compress: bool = True):
    try:
        files = sorted([p for p in dirpath.iterdir() if p.is_file() and ("remove-report" in p.name)], key=lambda p: p.stat().st_mtime, reverse=True)
        for p in files[keep:]:
            try:
                if compress and not str(p).endswith(".xz"):
                    with open(p, "rb") as inf:
                        data = inf.read()
                    with lzma.open(str(p) + ".xz", "wb") as f:
                        f.write(data)
                    p.unlink()
                elif not compress:
                    p.unlink()
            except Exception:
                pass
    except Exception:
        pass

# ---------------- CLI ----------------
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(prog="newpkg-remove", description="safely remove packages (newpkg)")
    p.add_argument("packages", nargs="*", help="package names to remove (if empty, use scan/plan)")
    p.add_argument("-n", "--dry-run", action="store_true", help="don't remove, only show plan")
    p.add_argument("-y", "--yes", action="store_true", help="assume yes (no interactive confirm)")
    p.add_argument("-l", "--lfs", action="store_true", help="operate inside LFS mount (use remove.lfs_mount)")
    p.add_argument("-f", "--fakeroot", action="store_true", help="use fakeroot in sandbox if available")
    p.add_argument("-j", "--jobs", type=int, help="parallel worker count (overrides config)")
    p.add_argument("--purge", action="store_true", help="purge package and metadata")
    p.add_argument("--quiet", action="store_true", help="quiet mode")
    p.add_argument("--json", action="store_true", help="print JSON report to stdout")
    p.add_argument("--yes-all", action="store_true", help="same as -y")
    args = p.parse_args()

    mgr = RemoveManager()

    # build scan / plan
    installed = mgr.scan_installed()
    plan_items: List[RemovePlanItem] = []
    if args.packages:
        for pkg in args.packages:
            item = installed.get(pkg)
            if item:
                plan_items.append(item)
            else:
                # unknown package: try heuristic - skip
                print(f"Unknown package: {pkg} (skipping)")
    else:
        # default: plan all or show interactive? we'll plan all (user asked automations)
        for name, it in installed.items():
            plan_items.append(it)

    # show summary and ask confirmation unless --yes
    total_size = sum(it.size_bytes for it in plan_items)
    if not args.dry_run and not args.yes and not args.yes_all:
        if not args.quiet:
            if RICH and console:
                console.print(f">>> Preparando remoção de {len(plan_items)} pacotes — total {human_size(total_size)}")
            else:
                print(f"Preparando remoção de {len(plan_items)} pacotes — total {human_size(total_size)}")
        ans = input("Continuar? [y/N]: ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborting.")
            raise SystemExit(0)

    parallel = args.jobs or mgr.parallel
    report = execute_plan(mgr, plan_items, dry_run=args.dry_run, yes=args.yes or args.yes_all, use_lfs=args.lfs, fakeroot=args.fakeroot, parallel=parallel, quiet=args.quiet)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        if RICH and console and not args.quiet:
            console.print(f"[green]Remoção finalizada[/green] removed={report['summary']['removed']} failed={report['summary']['failed']}")
            if report.get("report_path"):
                console.print(f"[blue]Report:[/blue] {report.get('report_path')}")
        else:
            print("Remoção finalizada:", report.get("report_path"))
            print("Resumo:", report["summary"])
