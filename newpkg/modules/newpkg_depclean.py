#!/usr/bin/env python3
# newpkg_depclean.py
"""
newpkg_depclean.py — detecta pacotes órfãos / dependências quebradas e planeja/executa limpeza
- Respeita newpkg_config: general.dry_run, output.quiet, output.json, depclean.parallel_jobs
- Integra com NewpkgLogger, NewpkgDB e NewpkgSandbox quando disponíveis
- Usa ThreadPoolExecutor para rebuilds/paralelismo, limitado por config / CPU
- Gera relatório em /var/log/newpkg/depclean/depclean-last.json
"""

from __future__ import annotations

import json
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional integrations
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
    from newpkg_sandbox import NewpkgSandbox
except Exception:
    NewpkgSandbox = None

# fallback stdlib logging for internal messages
import logging
_logger = logging.getLogger("newpkg.depclean")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.depclean: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


@dataclass
class OrphanEntry:
    package: str
    reason: str
    installed_files: List[str]


@dataclass
class PlanAction:
    package: str
    action: str  # 'remove', 'rebuild', 'ignore'
    reason: str
    details: Dict[str, Any]


@dataclass
class ExecResult:
    package: str
    action: str
    rc: int
    duration: float
    message: Optional[str] = None


class NewpkgDepclean:
    DEFAULT_REPORT_DIR = "/var/log/newpkg/depclean"

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None):
        # config / logger / db / sandbox
        self.cfg = cfg or (init_config() if init_config else None)

        if logger:
            self.logger = logger
        else:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, db) if NewpkgLogger and self.cfg else None
            except Exception:
                self.logger = None

        self._log = self._make_logger()

        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)
        # sandbox used for rebuilds / rebuild actions
        try:
            self.sandbox = NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgSandbox and self.cfg else None
        except Exception:
            self.sandbox = None

        # flags from config
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))

        # depclean specific
        self.parallel_jobs = int(self._cfg_get("depclean.parallel_jobs", min(4, (os.cpu_count() or 2))))
        # limit jobs by cpu_count
        cpu = os.cpu_count() or 1
        self.parallel_jobs = min(self.parallel_jobs, cpu)

        self.report_dir = Path(self._cfg_get("depclean.report_dir", self.DEFAULT_REPORT_DIR))
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.last_report = self.report_dir / "depclean-last.json"

        # safety: do not auto-confirm removals unless explicit
        self.require_confirm = bool(self._cfg_get("depclean.require_confirm", True))

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

    # ---------------- core phases ----------------
    def scan(self) -> Dict[str, Any]:
        """
        Scan the DB and the filesystem to identify:
         - orphan packages (installed but no record / no reverse deps)
         - broken packages (missing files or deps)
        Returns a dict with lists.
        """
        t0 = time.time()
        orphans: List[OrphanEntry] = []
        broken: List[Dict[str, Any]] = []

        # If DB is not available, we try a conservative scan via filesystem listing
        if not self.db:
            self._log("warning", "depclean.no_db", "No database available, performing filesystem-only scan")
            # naive heuristic: look under /usr/local and /usr and find unowned libs (best-effort)
            # We will not remove anything without DB
            return {"ok": False, "error": "no_db", "orphans": [], "broken": []}

        # enumerate packages from DB
        pkgs = self.db.list_packages()
        name_to_files = {}
        for p in pkgs:
            name = p.get("name")
            files = []
            try:
                files = self.db.list_files(name)
            except Exception:
                files = []
            name_to_files[name] = files

        # reverse dependency map
        pkg_deps = {}
        for p in pkgs:
            name = p.get("name")
            deps = []
            try:
                deps = [d["dep"] for d in self.db.get_deps(name)]
            except Exception:
                deps = []
            pkg_deps[name] = deps

        # find orphans: packages with no reverse deps and not a base system (heuristic)
        # base packages may be excluded by config list
        protected = set(self._cfg_get("depclean.protected_packages", ["base", "glibc", "linux-firmware"]) or [])
        for name, files in name_to_files.items():
            # skip protected
            if name in protected:
                continue
            # if package has zero packages depending on it (no reverse deps), consider orphan candidate
            reverse_count = sum(1 for n, deps in pkg_deps.items() if name in deps)
            if reverse_count == 0:
                # additional heuristic: if package installs no files -> consider broken instead
                if not files:
                    broken.append({"package": name, "reason": "no_files", "details": {}})
                else:
                    orphans.append(OrphanEntry(package=name, reason="no_reverse_deps", installed_files=list(files)))

        # check file existence / checksum for all packages
        for name, files in name_to_files.items():
            for f in files:
                if not f:
                    continue
                try:
                    if not os.path.exists(f):
                        broken.append({"package": name, "file": f, "reason": "missing_file"})
                    # optional: check sha if db stores it (skipped to avoid heavy IO unless configured)
                except Exception:
                    broken.append({"package": name, "file": f, "reason": "access_error"})

        duration = time.time() - t0
        self._log("info", "depclean.scan.ok", f"Scan finished in {duration:.2f}s", orphans=len(orphans), broken=len(broken))
        # DB record
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package="system", phase="depclean.scan", status="ok", meta={"orphans": len(orphans), "broken": len(broken)})
        except Exception:
            pass

        return {"ok": True, "orphans": [asdict(o) for o in orphans], "broken": broken, "duration": duration}

    def plan(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a plan of actions from scan result.
        Rules:
         - orphan -> remove (default)
         - broken -> attempt rebuild (if rebuild strategy available) else mark for manual
        """
        t0 = time.time()
        plan: List[PlanAction] = []

        # simple rules and config overrides
        rebuild_strategy = self._cfg_get("depclean.rebuild_strategy", "attempt")  # attempt|manual|ignore

        for o in scan_result.get("orphans", []):
            pkg = o.get("package")
            plan.append(PlanAction(package=pkg, action="remove", reason=o.get("reason"), details={"files": o.get("installed_files")}))

        for b in scan_result.get("broken", []):
            pkg = b.get("package")
            if rebuild_strategy == "attempt":
                plan.append(PlanAction(package=pkg, action="rebuild", reason=b.get("reason"), details=b))
            elif rebuild_strategy == "manual":
                plan.append(PlanAction(package=pkg, action="manual", reason=b.get("reason"), details=b))
            else:
                plan.append(PlanAction(package=pkg, action="ignore", reason=b.get("reason"), details=b))

        duration = time.time() - t0
        self._log("info", "depclean.plan.ok", f"Plan built in {duration:.2f}s", actions=len(plan))
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package="system", phase="depclean.plan", status="ok", meta={"actions": len(plan)})
        except Exception:
            pass

        return {"ok": True, "plan": [asdict(p) for p in plan], "duration": duration}

    # -------------- execution helpers --------------
    def _confirm(self, plan: List[PlanAction]) -> bool:
        if not self.require_confirm:
            return True
        # interactive confirm unless quiet or in CI
        if self.quiet:
            return False
        print("Depclean planned actions:")
        for p in plan:
            print(f" - {p.action.upper():6} {p.package}: {p.reason}")
        ans = input("Proceed with execution? [y/N]: ").strip().lower()
        return ans == "y"

    def _exec_remove(self, package: str) -> ExecResult:
        """
        Perform removal. We do not assume a specific package manager; attempt to remove recorded files.
        This is destructive — only called when not dry_run and with confirmation.
        """
        t0 = time.time()
        files = []
        try:
            files = self.db.list_files(package)
        except Exception:
            pass
        rc = 0
        msg = ""
        if self.dry_run:
            self._log("info", "depclean.remove.dryrun", f"Would remove package {package}", package=package)
            return ExecResult(package=package, action="remove", rc=0, duration=0.0, message="dry-run")
        try:
            for f in files:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except Exception as e:
                    rc = 1
                    msg += f"rm {f} failed: {e}; "
            # optionally remove package entry from DB
            try:
                # simple approach: mark package metadata removal by deleting package row isn't provided; leave to DB API
                pass
            except Exception:
                pass
        except Exception as e:
            rc = 2
            msg = str(e)
        duration = time.time() - t0
        self._log("info" if rc == 0 else "error", "depclean.remove.done", f"Removed {package} rc={rc}", package=package, rc=rc, duration=duration)
        return ExecResult(package=package, action="remove", rc=rc, duration=duration, message=msg or None)

    def _exec_rebuild(self, package: str) -> ExecResult:
        """
        Attempt a rebuild for a broken package. Prefer using sandbox + upgrade module if available.
        This function should be conservative and report results without assuming success.
        """
        t0 = time.time()
        if self.dry_run:
            self._log("info", "depclean.rebuild.dryrun", f"Would rebuild {package}", package=package)
            return ExecResult(package=package, action="rebuild", rc=0, duration=0.0, message="dry-run")

        # if sandbox + upgrade module available, attempt to call an external rebuild function
        try:
            # try to find an upgrade/rebuild callable in environment
            from newpkg_upgrade import NewpkgUpgrade  # optional import
            upgr = NewpkgUpgrade(cfg=self.cfg, logger=self.logger, db=self.db)
            # run rebuild inside sandbox if available
            if self.sandbox:
                # call upgr.rebuild(package) inside sandbox is non-trivial; attempt direct call as best-effort
                self._log("info", "depclean.rebuild.call", f"Triggering rebuild for {package} via NewpkgUpgrade", package=package)
                rc = 0
                try:
                    r = upgr.rebuild(package)  # user-provided API expected
                    rc = 0 if r else 1
                except Exception as e:
                    rc = 2
                    self._log("error", "depclean.rebuild.ex", f"Rebuild raised: {e}", package=package, error=str(e))
                duration = time.time() - t0
                return ExecResult(package=package, action="rebuild", rc=rc, duration=duration, message=None if rc == 0 else "rebuild failed")
            else:
                # attempt direct call without sandbox
                self._log("warning", "depclean.rebuild.nosandbox", f"No sandbox available; attempting direct rebuild for {package}", package=package)
                rc = 0
                try:
                    r = upgr.rebuild(package)
                    rc = 0 if r else 1
                except Exception as e:
                    rc = 2
                    self._log("error", "depclean.rebuild.ex", f"Rebuild raised: {e}", package=package, error=str(e))
                duration = time.time() - t0
                return ExecResult(package=package, action="rebuild", rc=rc, duration=duration, message=None if rc == 0 else "rebuild failed")
        except Exception:
            # fallback: mark as manual
            self._log("warning", "depclean.rebuild.nohandler", f"No rebuild handler available for {package}", package=package)
            duration = time.time() - t0
            return ExecResult(package=package, action="rebuild", rc=3, duration=duration, message="no-rebuild-handler")

    # -------------- execute plan --------------
    def execute(self, plan: List[PlanAction], confirm: bool = False, jobs: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute the plan. If dry_run=True only logs actions. If confirm required, user must pass confirm=True.
        Returns execution summary and list of ExecResult.
        """
        if not plan:
            return {"ok": True, "results": [], "summary": {"removed": 0, "rebuilt": 0, "failed": 0}}

        # require explicit confirm if configured
        if self.require_confirm and not confirm:
            self._log("warning", "depclean.execute.no_confirm", "Execution requires explicit confirmation (--confirm) to proceed")
            return {"ok": False, "error": "no_confirm"}

        jobs = jobs or self.parallel_jobs
        jobs = min(jobs, self.parallel_jobs)

        tasks = []
        results: List[ExecResult] = []

        # map actions to functions
        def worker(action: PlanAction) -> ExecResult:
            pkg = action.package
            if action.action == "remove":
                return self._exec_remove(pkg)
            elif action.action == "rebuild":
                return self._exec_rebuild(pkg)
            else:
                # manual or ignore
                self._log("info", "depclean.action.skip", f"Skipping package {pkg} action={action.action}", package=pkg, action=action.action)
                return ExecResult(package=pkg, action=action.action, rc=0, duration=0.0, message="skipped")

        # parallel execution
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            future_map = {ex.submit(worker, p): p for p in plan}
            for fut in as_completed(future_map):
                action = future_map[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = ExecResult(package=action.package, action=action.action, rc=254, duration=0.0, message=str(e))
                results.append(res)

        # compute summary
        summary = {"removed": sum(1 for r in results if r.action == "remove" and r.rc == 0),
                   "rebuilt": sum(1 for r in results if r.action == "rebuild" and r.rc == 0),
                   "failed": sum(1 for r in results if r.rc != 0)}

        # record phase
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package="system", phase="depclean.execute", status="ok" if summary["failed"] == 0 else "error", meta=summary)
        except Exception:
            pass

        # log summary
        self._log("info", "depclean.execute.summary", f"Execution finished: removed={summary['removed']} rebuilt={summary['rebuilt']} failed={summary['failed']}", **summary)

        return {"ok": True, "results": [asdict(r) for r in results], "summary": summary}

    # -------------- reporting --------------
    def write_report(self, scan_res: Dict[str, Any], plan_res: Dict[str, Any], exec_res: Optional[Dict[str, Any]] = None) -> Path:
        """
        Write a structured report to self.last_report and rotate previous.
        """
        report = {
            "ts": int(time.time()),
            "scan": scan_res,
            "plan": plan_res,
            "execute": exec_res,
        }
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.last_report.with_suffix(".tmp")
            tmp.write_text(json.dumps(report, indent=2), encoding="utf-8")
            tmp.replace(self.last_report)
            self._log("info", "depclean.report.write", f"Wrote report to {self.last_report}", path=str(self.last_report))
        except Exception as e:
            self._log("error", "depclean.report.fail", f"Failed to write report: {e}", error=str(e))
        return self.last_report

    # -------------- CLI convenience --------------
    @staticmethod
    def cli():
        import argparse
        p = argparse.ArgumentParser(prog="newpkg-depclean", description="Scan and clean unused/broken packages")
        p.add_argument("--scan", action="store_true", help="run scan")
        p.add_argument("--plan", action="store_true", help="build plan from last scan")
        p.add_argument("--execute", action="store_true", help="execute plan (requires --confirm or config override)")
        p.add_argument("--confirm", action="store_true", help="confirm execution")
        p.add_argument("--jobs", type=int, help="parallel jobs override")
        p.add_argument("--report", action="store_true", help="write report to disk")
        p.add_argument("--json", action="store_true", help="output JSON")
        p.add_argument("--quiet", action="store_true", help="suppress interactive prompts")
        args = p.parse_args()

        cfg = init_config() if init_config else None
        logger = NewpkgLogger.from_config(cfg, NewpkgDB(cfg)) if NewpkgLogger and cfg else None
        db = NewpkgDB(cfg) if NewpkgDB and cfg else None
        depclean = NewpkgDepclean(cfg=cfg, logger=logger, db=db)

        # override flags from CLI
        if args.quiet:
            depclean.quiet = True
        if args.json:
            depclean.json_out = True
        if args.jobs:
            depclean.parallel_jobs = args.jobs

        scan_res = {}
        plan_res = {}
        exec_res = None

        if args.scan or (not args.plan and not args.execute):
            scan_res = depclean.scan()
            if depclean.json_out or args.json:
                print(json.dumps(scan_res, indent=2))
        if args.plan or args.execute:
            if not scan_res:
                scan_res = depclean.scan()
            plan_res = depclean.plan(scan_res)
            if depclean.json_out or args.json:
                print(json.dumps(plan_res, indent=2))

        if args.execute:
            confirm = args.confirm
            exec_res = depclean.execute([ PlanAction(**p) for p in plan_res.get("plan", []) ], confirm=confirm, jobs=args.jobs)
            if depclean.json_out or args.json:
                print(json.dumps(exec_res, indent=2))

        if args.report:
            rpt = depclean.write_report(scan_res, plan_res, exec_res)
            if args.json:
                print(json.dumps({"report": str(rpt)}, indent=2))
            else:
                print(f"Wrote report to {rpt}")

        # exit code: 0 if everything ok, >0 otherwise
        if exec_res and exec_res.get("summary", {}).get("failed", 0) > 0:
            raise SystemExit(2)
        raise SystemExit(0)

# if executed directly
if __name__ == "__main__":
    NewpkgDepclean.cli()
