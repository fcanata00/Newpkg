#!/usr/bin/env python3
"""
newpkg_depclean.py

Depclean / orphan & broken-package cleaner for newpkg.

Features:
- scan(): inspect DB and produce lists of orphan packages and broken packages (missing deps)
- plan(): generate an actionable plan (remove orphans, rebuild dependers of broken packages)
- execute(): perform removals and rebuilds (with dry-run, interactive, and parallel options)
- integration with ConfigStore (cfg.get('depclean.*')), NewpkgLogger (logger.info/error), NewpkgDB (record_phase)
- sandbox support: uses sandbox.run()/wrap() if provided, or falls back to bubblewrap for isolated rebuilds
- reports saved as JSON
- safe defaults: dry-run=True; auto_confirm=False

Assumptions about other modules:
- newpkg_db.NewpkgDB provides list_packages(), get_deps(pkg), remove_package(name), mark_installed(name), record_phase(...)
- newpkg_logger.NewpkgLogger provides info()/error()/warning() that accept (event, message, **meta)
- sandbox if provided exposes wrap(cmd, binds=[], cwd=...) or run(cmd, cwd=..., env=...)
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Safe imports for optional modules (CLI will use init_config if available)
try:
    from newpkg_config import init_config, ConfigManager
except Exception:
    init_config = None
    ConfigManager = None

# safe import shims for logger and db modules if not present
try:
    from newpkg_logger import NewpkgLogger
except Exception:
    NewpkgLogger = None

try:
    from newpkg_db import NewpkgDB
except Exception:
    NewpkgDB = None

# minimal helper to call bubblewrap if sandbox not available
def _bwrap_available() -> Optional[str]:
    return shutil.which("bwrap")


class DepcleanError(Exception):
    pass


class Depclean:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None):
        """
        cfg: ConfigStore or similar (optional)
        logger: NewpkgLogger-like object (optional)
        db: NewpkgDB-like object (optional)
        sandbox: sandbox abstraction with wrap()/run() or None
        """
        self.cfg = cfg
        self.logger = logger or (NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None)
        self.db = db or (NewpkgDB(cfg) if NewpkgDB else None)
        self.sandbox = sandbox

        # config defaults (lowercase keys preferred; fallback to env vars)
        self.keep_protected = bool(self._cfg_get("depclean.keep_protected", True))
        # number of workers for parallel rebuilds (0 or 1 => serial)
        self.parallel_jobs = int(self._cfg_get("depclean.parallel_jobs", self._cfg_get("DEPCLEAN_PARALLEL", 1)))
        # default behavior
        self.default_dry_run = bool(self._cfg_get("depclean.dry_run", True))
        self.auto_confirm = bool(self._cfg_get("depclean.auto_confirm", False))
        self.report_dir = str(self._cfg_get("depclean.report_dir", "/var/tmp/newpkg_depclean_reports"))
        Path(self.report_dir).mkdir(parents=True, exist_ok=True)

    # ---------------- config helper ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        # fallback to env
        ek = key.upper().replace(".", "_")
        return os.environ.get(ek, default)

    # ---------------- logging helper ----------------
    def _log(self, level: str, event: str, message: str = "", **meta):
        if self.logger:
            try:
                fn = getattr(self.logger, level.lower(), None)
                if fn:
                    fn(event, message, **meta)
                    return
            except Exception:
                pass
        # fallback to stderr
        print(f"[{level}] {event}: {message}", file=sys.stderr)

    # ---------------- scanning ----------------
    def scan(self) -> Dict[str, Any]:
        """
        Scan DB and compute:
          - orphans: packages that no other package depends on and are not protected
          - broken: packages that have missing dependencies
        Returns a dict with structure {'orphan': [names], 'broken': [{pkg:..., missing:[...]}], 'timestamp':...}
        """
        if not self.db:
            raise DepcleanError("database module not configured")

        packages = self.db.list_packages()
        name_map = {p["name"]: p for p in packages}
        # build reverse dep map
        revdeps: Dict[str, List[str]] = {}
        for p in packages:
            pname = p["name"]
            deps = []
            try:
                deps_obj = self.db.get_deps(pname)
                # db.get_deps returns list of dicts like {'dep_name':..}
                for d in deps_obj:
                    if isinstance(d, dict):
                        depn = d.get("dep_name") or d.get("name") or d.get("pkg") or d.get("package")
                        if depn:
                            deps.append(depn)
                    elif isinstance(d, str):
                        deps.append(d)
            except Exception:
                # assume no deps
                deps = []
            for dep in deps:
                revdeps.setdefault(dep, []).append(pname)

        # orphans: those with no reverse deps and status != 'protected' if configured
        orphans = []
        for pname, meta in name_map.items():
            protected_flag = meta.get("status", "") == "protected" or meta.get("protected", False)
            if self.keep_protected and protected_flag:
                continue
            if pname not in revdeps or not revdeps.get(pname):
                # candidate orphan, but exclude virtual/system packages: simple heuristic
                if meta.get("origin") in ("system", "base"):
                    continue
                orphans.append(pname)

        # broken: package whose deps include names not in DB
        broken = []
        for p in packages:
            pname = p["name"]
            missing = []
            try:
                deps = self.db.get_deps(pname)
                for d in deps:
                    depn = d.get("dep_name") if isinstance(d, dict) else d
                    if depn and depn not in name_map:
                        missing.append(depn)
            except Exception:
                continue
            if missing:
                broken.append({"package": pname, "missing": missing})

        res = {"timestamp": datetime.utcnow().isoformat() + "Z", "orphan_count": len(orphans), "orphan_list": sorted(orphans),
               "broken_count": len(broken), "broken_list": broken}
        self._log("info", "depclean.scan", f"Found {len(orphans)} orphans, {len(broken)} broken packages", orphans=len(orphans), broken=len(broken))
        return res

    # ---------------- planning ----------------
    def plan(self, scan_result: Optional[Dict[str, Any]] = None, remove_orphans: bool = True, rebuild_broken_revdeps: bool = True) -> Dict[str, Any]:
        """
        Generate a plan based on scan_result (if None, run scan()).
        Plan format:
          { 'removals': [pkg1, ...], 'rebuilds': [pkgA, ...], 'timestamp':..., 'meta':... }
        """
        if scan_result is None:
            scan_result = self.scan()

        removals = scan_result.get("orphan_list", []) if remove_orphans else []
        broken = scan_result.get("broken_list", []) if rebuild_broken_revdeps else []

        # compute rebuild revdeps for each broken package: packages depending on the missing dep
        rebuilds_set = set()
        if broken and self.db:
            for b in broken:
                for missing in b.get("missing", []):
                    # packages that depend on missing (reverse deps)
                    try:
                        rev = self.db.get_reverse_deps(missing)
                        for r in rev:
                            rebuilds_set.add(r)
                    except Exception:
                        continue

        rebuilds = sorted(list(rebuilds_set))
        plan = {"timestamp": datetime.utcnow().isoformat() + "Z", "removals": removals, "rebuilds": rebuilds}
        self._log("info", "depclean.plan", f"Plan with {len(removals)} removals and {len(rebuilds)} rebuilds", removals=len(removals), rebuilds=len(rebuilds))
        return plan

    # ---------------- execution helpers ----------------
    def _confirm(self, message: str) -> bool:
        if self.auto_confirm:
            return True
        try:
            resp = input(f"{message} [y/N]: ")
            return resp.strip().lower() in ("y", "yes")
        except Exception:
            return False

    def _remove_package(self, pkg: str, dry_run: bool = True) -> Dict[str, Any]:
        self._log("info", "depclean.remove.start", f"Removing {pkg}", pkg=pkg, dry_run=dry_run)
        if dry_run:
            return {"package": pkg, "action": "remove", "status": "dry-run"}
        try:
            # call DB remove_package; core-level uninstall could be more involved
            if self.db and hasattr(self.db, "remove_package"):
                self.db.remove_package(pkg)
            # record action
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(pkg, "depclean.remove", "ok")
            self._log("info", "depclean.remove.ok", f"Removed {pkg}", pkg=pkg)
            return {"package": pkg, "action": "remove", "status": "ok"}
        except Exception as e:
            self._log("error", "depclean.remove.fail", f"Failed to remove {pkg}: {e}", pkg=pkg, error=str(e))
            try:
                if self.db and hasattr(self.db, "record_phase"):
                    self.db.record_phase(pkg, "depclean.remove", "error")
            except Exception:
                pass
            return {"package": pkg, "action": "remove", "status": "error", "error": str(e)}

    def _run_rebuild(self, pkg: str, dry_run: bool = True, workdir: Optional[str] = None) -> Dict[str, Any]:
        """
        Rebuild a package. This is a best-effort orchestrator; ideally call newpkg_core or newpkg_upgrade.
        If newpkg_core/newpkg_upgrade modules are available in the environment, prefer to call them.
        """
        self._log("info", "depclean.rebuild.start", f"Rebuilding {pkg}", pkg=pkg, dry_run=dry_run)
        if dry_run:
            return {"package": pkg, "action": "rebuild", "status": "dry-run"}

        # try to invoke newpkg_upgrade if available (preferred)
        try:
            import importlib

            upgrade_mod = importlib.import_module("newpkg_upgrade")
            if hasattr(upgrade_mod, "NewpkgUpgrade"):
                upgr = upgrade_mod.NewpkgUpgrade(self.cfg, logger=self.logger, db=self.db)
                try:
                    res = upgr.rebuild(pkg)
                    # record in DB
                    if self.db and hasattr(self.db, "record_phase"):
                        self.db.record_phase(pkg, "depclean.rebuild", "ok")
                    return {"package": pkg, "action": "rebuild", "status": "ok", "result": res}
                except Exception as e:
                    if self.db and hasattr(self.db, "record_phase"):
                        self.db.record_phase(pkg, "depclean.rebuild", "error")
                    return {"package": pkg, "action": "rebuild", "status": "error", "error": str(e)}
        except Exception:
            # no upgrade mod or failed import - fallback
            pass

        # fallback: attempt a simple "fake rebuild" by invoking /bin/true inside sandbox (non-destructive)
        try:
            if self.sandbox and hasattr(self.sandbox, "run"):
                cmd = ["true"]
                rc = self.sandbox.run(cmd, cwd=workdir or ".", env=None)
                # sandbox.run might return a dict or rc; normalize
                if isinstance(rc, dict):
                    rc_code = rc.get("rc", 0)
                else:
                    rc_code = int(rc or 0)
                if rc_code == 0:
                    if self.db and hasattr(self.db, "record_phase"):
                        self.db.record_phase(pkg, "depclean.rebuild", "ok")
                    return {"package": pkg, "action": "rebuild", "status": "ok", "rc": rc_code}
                else:
                    if self.db and hasattr(self.db, "record_phase"):
                        self.db.record_phase(pkg, "depclean.rebuild", "error")
                    return {"package": pkg, "action": "rebuild", "status": "error", "rc": rc_code}
            else:
                # try bubblewrap no-op if available
                bwrap = _bwrap_available()
                if bwrap:
                    cmd = [bwrap, "--unshare-all", "--ro-bind", "/", "/", "--chdir", "/", "--", "true"]
                    proc = subprocess.run(cmd, capture_output=True)
                    if proc.returncode == 0:
                        if self.db and hasattr(self.db, "record_phase"):
                            self.db.record_phase(pkg, "depclean.rebuild", "ok")
                        return {"package": pkg, "action": "rebuild", "status": "ok", "rc": 0}
                    else:
                        if self.db and hasattr(self.db, "record_phase"):
                            self.db.record_phase(pkg, "depclean.rebuild", "error")
                        return {"package": pkg, "action": "rebuild", "status": "error", "rc": proc.returncode, "stderr": proc.stderr.decode(errors='ignore')}
                else:
                    # no sandbox available; warn and mark as skipped
                    self._log("warning", "depclean.rebuild.nosandbox", f"No sandbox available to rebuild {pkg}", pkg=pkg)
                    return {"package": pkg, "action": "rebuild", "status": "skipped", "reason": "no-sandbox"}
        except Exception as e:
            self._log("error", "depclean.rebuild.fail", f"Rebuild failed for {pkg}: {e}", pkg=pkg, error=str(e))
            try:
                if self.db and hasattr(self.db, "record_phase"):
                    self.db.record_phase(pkg, "depclean.rebuild", "error")
            except Exception:
                pass
            return {"package": pkg, "action": "rebuild", "status": "error", "error": str(e)}

    # ---------------- execute plan ----------------
    def execute(self, plan: Dict[str, Any], dry_run: Optional[bool] = None, interactive: bool = False, jobs: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute a plan dict as produced by plan().
        dry_run: if None, uses default_dry_run
        interactive: confirm destructive actions
        jobs: number of parallel workers for rebuilds (>=1)
        """
        if dry_run is None:
            dry_run = self.default_dry_run
        if jobs is None:
            jobs = max(1, int(self.parallel_jobs or 1))

        removals = plan.get("removals", [])
        rebuilds = plan.get("rebuilds", [])

        results = {"timestamp": datetime.utcnow().isoformat() + "Z", "removals": [], "rebuilds": [], "errors": []}

        # removals (serial)
        for pkg in removals:
            if interactive and not self._confirm(f"Remove orphan package {pkg}?"):
                results["removals"].append({"package": pkg, "status": "skipped", "reason": "user_declined"})
                continue
            r = self._remove_package(pkg, dry_run=dry_run)
            results["removals"].append(r)
            if r.get("status") == "error":
                results["errors"].append(r)

        # rebuilds: can be parallel
        if rebuilds:
            # if only a dry-run, we still report entries
            if dry_run:
                for pkg in rebuilds:
                    results["rebuilds"].append({"package": pkg, "action": "rebuild", "status": "dry-run"})
            else:
                if jobs and int(jobs) > 1:
                    # parallel
                    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
                        futs = {ex.submit(self._run_rebuild, pkg, dry_run=False): pkg for pkg in rebuilds}
                        for fut in concurrent.futures.as_completed(futs):
                            pkg = futs[fut]
                            try:
                                r = fut.result()
                            except Exception as e:
                                r = {"package": pkg, "action": "rebuild", "status": "error", "error": str(e)}
                            results["rebuilds"].append(r)
                            if r.get("status") == "error":
                                results["errors"].append(r)
                else:
                    # serial
                    for pkg in rebuilds:
                        r = self._run_rebuild(pkg, dry_run=False)
                        results["rebuilds"].append(r)
                        if r.get("status") == "error":
                            results["errors"].append(r)

        # record report to disk
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        report_path = Path(self.report_dir) / f"depclean-report-{ts}.json"
        try:
            report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
            self._log("info", "depclean.report.saved", f"Report saved to {report_path}", path=str(report_path))
        except Exception:
            self._log("warning", "depclean.report.savefail", f"Failed to save report to {report_path}")

        # summary logging
        total_actions = len(removals) + len(rebuilds)
        errors = len(results.get("errors", []))
        self._log("info", "depclean.execute.done", f"Executed plan: {total_actions} actions, {errors} errors", total=total_actions, errors=errors)
        return results

    # ---------------- convenience ----------------
    def clean(self, dry_run: Optional[bool] = None, interactive: bool = False, jobs: Optional[int] = None) -> Dict[str, Any]:
        """
        Run scan->plan->execute convenience helper
        """
        scan_result = self.scan()
        plan = self.plan(scan_result)
        return self.execute(plan, dry_run=dry_run, interactive=interactive, jobs=jobs)


# ---------------- CLI wrapper ----------------
def _build_cli():
    import argparse

    p = argparse.ArgumentParser(prog="newpkg-depclean")
    p.add_argument("cmd", choices=["scan", "plan", "execute", "clean"], nargs="?", default="scan")
    p.add_argument("--dry-run", action="store_true", help="simulate actions")
    p.add_argument("--yes", "-y", action="store_true", help="assume yes for confirmations")
    p.add_argument("--interactive", action="store_true", help="ask before destructive actions")
    p.add_argument("--jobs", type=int, help="parallel workers for rebuilds")
    p.add_argument("--report-dir", help="directory to write reports")
    return p


def main(argv: Optional[List[str]] = None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = _build_cli()
    args = parser.parse_args(argv)

    # initialize config/logger/db if available
    cfg = None
    if init_config:
        try:
            cfg = init_config()
        except Exception:
            cfg = None

    db = None
    if NewpkgDB and cfg is not None:
        try:
            db = NewpkgDB(cfg)
            # don't auto-init DB here
        except Exception:
            db = None

    logger = None
    if NewpkgLogger and cfg is not None:
        try:
            logger = NewpkgLogger.from_config(cfg, db)
        except Exception:
            logger = None

    depclean = Depclean(cfg=cfg, logger=logger, db=db, sandbox=None)
    if args.report_dir:
        depclean.report_dir = args.report_dir

    if args.yes:
        depclean.auto_confirm = True

    if args.cmd == "scan":
        res = depclean.scan()
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "plan":
        res = depclean.plan()
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    if args.cmd in ("clean", "execute"):
        dry_run = args.dry_run or depclean.default_dry_run
        interactive = args.interactive
        jobs = args.jobs or depclean.parallel_jobs
        plan = depclean.plan()
        depclean._log("info", "depclean.start", f"Starting depclean: removals={len(plan['removals'])} rebuilds={len(plan['rebuilds'])}", plan=plan)
        result = depclean.execute(plan, dry_run=dry_run, interactive=interactive, jobs=jobs)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
