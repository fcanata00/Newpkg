#!/usr/bin/env python3
# newpkg_audit.py
"""
newpkg_audit.py — audit scanner and fixer for newpkg-managed system

Features:
 - Scans installed packages/files for known vulnerabilities/misconfigurations
 - Builds a remediation plan and (optionally) attempts fixes via available handlers:
     NewpkgUpgrade (rebuild), NewpkgPatcher (apply patches), NewpkgRemove (safe-remove)
 - Respects newpkg_config: general.dry_run, output.quiet, output.json, core.jobs, audit.* keys
 - Integrates with NewpkgLogger (uses perf_timer if available), NewpkgDB, NewpkgSandbox
 - Produces JSON/human reports saved under /var/log/newpkg/audit/reports/
 - Creates backups before destructive actions under /var/log/newpkg/audit/backups/
 - Parallel execution controlled by config
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import signal
import tarfile
import tempfile
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional integrations (best-effort)
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

# External handlers (optional)
try:
    from newpkg_upgrade import NewpkgUpgrade
except Exception:
    NewpkgUpgrade = None

try:
    from newpkg_patcher import NewpkgPatcher
except Exception:
    NewpkgPatcher = None

try:
    from newpkg_remove import NewpkgRemove
except Exception:
    NewpkgRemove = None

# Fallback stdlib logger for internal messages (used only if NewpkgLogger missing)
import logging
_logger = logging.getLogger("newpkg.audit")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.audit: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


@dataclass
class AuditFinding:
    package: str
    file: Optional[str]
    issue: str
    severity: str  # low/medium/high/critical
    evidence: Dict[str, Any]
    recommended: List[Dict[str, Any]]  # list of remediation suggestions

    def to_dict(self):
        return asdict(self)


@dataclass
class AuditPlanItem:
    package: str
    action: str  # 'rebuild'|'patch'|'remove'|'manual'
    reason: str
    details: Dict[str, Any]

    def to_dict(self):
        return asdict(self)


@dataclass
class AuditReport:
    ts: int
    summary: Dict[str, Any]
    findings: List[Dict[str, Any]]
    plan: List[Dict[str, Any]]
    executed: List[Dict[str, Any]]

    def to_dict(self):
        return asdict(self)


class NewpkgAudit:
    DEFAULT_REPORT_DIR = "/var/log/newpkg/audit/reports"
    DEFAULT_BACKUP_DIR = "/var/log/newpkg/audit/backups"

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None):
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

        # sandbox
        if sandbox:
            self.sandbox = sandbox
        else:
            try:
                self.sandbox = NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgSandbox and self.cfg else None
            except Exception:
                self.sandbox = None

        # handlers
        self.upgrade_handler = NewpkgUpgrade(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgUpgrade and self.cfg else None
        self.patcher_handler = NewpkgPatcher(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgPatcher and self.cfg else None
        self.remove_handler = NewpkgRemove(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgRemove and self.cfg else None

        # runtime flags from config
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))

        # audit-specific config
        self.report_dir = Path(self._cfg_get("audit.report_dir", self.DEFAULT_REPORT_DIR))
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir = Path(self._cfg_get("audit.backup_dir", self.DEFAULT_BACKUP_DIR))
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        cpu = os.cpu_count() or 1
        default_jobs = int(self._cfg_get("core.jobs", max(1, min(4, cpu))))
        self.jobs = int(self._cfg_get("audit.jobs", default_jobs))

        # risk thresholds configured by user
        self.risk_threshold = self._cfg_get("audit.risk_threshold", "medium")  # low, medium, high, critical

        # perf_timer decorator if present on logger
        self._perf_timer = getattr(self.logger, "perf_timer", None) if self.logger else None

        # internal
        self._cancelled = False

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

    # ------------- utilities -------------
    def _now_ts(self) -> int:
        return int(time.time())

    def _save_report(self, report: AuditReport) -> Path:
        ts = report.ts
        fname = f"audit-report-{datetime.utcfromtimestamp(ts).strftime('%Y%m%d-%H%M%S')}.json"
        path = self.report_dir / fname
        try:
            path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
            self._log("info", "audit.report.write", f"Wrote audit report to {path}", path=str(path))
        except Exception as e:
            self._log("error", "audit.report.fail", f"Failed to write audit report: {e}", error=str(e))
        return path

    def _backup_paths(self, package: str, paths: List[str]) -> Optional[str]:
        """
        Create tar.xz backup containing provided paths.
        Returns path to backup or None on failure. In dry-run just logs.
        """
        if not paths:
            return None
        ts = int(time.time())
        safe_name = package.replace("/", "_")
        backup_name = f"{safe_name}-audit-{ts}.tar.xz"
        backup_path = str(self.backup_dir / backup_name)
        if self.dry_run:
            self._log("info", "audit.backup.dryrun", f"DRY-RUN: would backup {len(paths)} paths for {package}", package=package, count=len(paths))
            return None
        try:
            with tarfile.open(backup_path, "w:xz") as tar:
                for p in paths:
                    try:
                        if os.path.exists(p):
                            tar.add(p, arcname=os.path.relpath(p, "/"))
                    except Exception as e:
                        self._log("warning", "audit.backup.skip", f"Skipping backup path {p}: {e}", path=p, error=str(e))
            self._log("info", "audit.backup.ok", f"Created backup {backup_path}", path=backup_path)
            return backup_path
        except Exception as e:
            self._log("error", "audit.backup.fail", f"Backup creation failed: {e}", error=str(e))
            return None

    # ------------- cancellation -------------
    def cancel(self):
        self._cancelled = True

    # ------------- scanning -------------
    def scan(self, packages: Optional[List[str]] = None) -> List[AuditFinding]:
        """
        Scan the system (or specified packages) for issues.
        - If packages is None, scans all packages known to DB.
        - Returns list of AuditFinding objects.
        """
        decorator = self._perf_timer("audit.scan") if self._perf_timer else None
        if decorator:
            return decorator(self._scan_impl)(packages)
        else:
            return self._scan_impl(packages)

    def _scan_impl(self, packages: Optional[List[str]] = None) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        # if no db, return empty but log warning
        if not self.db:
            self._log("warning", "audit.scan.no_db", "No database available; cannot scan packages reliably")
            return findings

        # choose package list
        try:
            all_pkgs = [p["name"] for p in self.db.list_packages()]
        except Exception:
            all_pkgs = []

        targets = packages or all_pkgs
        self._log("info", "audit.scan.start", f"Starting scan for {len(targets)} packages", count=len(targets))

        # simple scanner heuristics: look for missing files, known bad versions, known-vuln-markers in metadata
        def scan_pkg(pkg_name: str) -> List[AuditFinding]:
            if self._cancelled:
                return []
            local_findings: List[AuditFinding] = []
            try:
                # 1) check reverse deps and file list existence
                files = []
                try:
                    files = self.db.list_files(pkg_name)
                except Exception:
                    files = []
                missing_files = [f for f in (files or []) if not f or not os.path.exists(f)]
                if missing_files:
                    local_findings.append(AuditFinding(
                        package=pkg_name,
                        file=None,
                        issue="missing_files",
                        severity="medium",
                        evidence={"missing": missing_files},
                        recommended=[{"action": "rebuild", "reason": "files_missing"}]
                    ))
                # 2) check known vulnerable versions via db metadata (example: db.get_pkg_meta)
                try:
                    meta = self.db.get_pkg_meta(pkg_name) or {}
                except Exception:
                    meta = {}
                # Example heuristic: meta may contain 'version' and 'vulnerable' flags
                version = meta.get("version")
                if meta.get("vulnerable", False):
                    local_findings.append(AuditFinding(
                        package=pkg_name,
                        file=None,
                        issue="vulnerable_version",
                        severity="high",
                        evidence={"version": version, "meta": meta},
                        recommended=[{"action": "upgrade", "reason": "known_vulnerability"}]
                    ))
                # 3) detect setuid binaries as potential risk
                setuid_files = []
                for f in (files or []):
                    try:
                        if f and os.path.exists(f):
                            st = os.stat(f)
                            if bool(st.st_mode & 0o4000):
                                setuid_files.append(f)
                    except Exception:
                        continue
                if setuid_files:
                    local_findings.append(AuditFinding(
                        package=pkg_name,
                        file=None,
                        issue="setuid_files",
                        severity="medium",
                        evidence={"files": setuid_files},
                        recommended=[{"action": "audit_setuid", "reason": "setuid present"}]
                    ))
                # 4) check reverse deps brokenness (package depended on but missing)
                try:
                    revs = self.db.get_reverse_deps(pkg_name) or []
                except Exception:
                    revs = []
                # if no reverse deps and package not essential (heuristic), flag as orphan (low)
                protected = set(self._cfg_get("audit.protected_packages", ["glibc", "linux-firmware", "base"]) or [])
                if not revs and pkg_name not in protected:
                    local_findings.append(AuditFinding(
                        package=pkg_name,
                        file=None,
                        issue="possibly_orphan",
                        severity="low",
                        evidence={},
                        recommended=[{"action": "maybe_remove", "reason": "no_reverse_deps"}]
                    ))
                # more heuristics could be added (signature missing, packaging mismatches, known CVE DB checks, etc.)
            except Exception as e:
                self._log("warning", "audit.scan.pkgfail", f"Scan of package {pkg_name} failed: {e}", package=pkg_name, error=str(e))
            return local_findings

        # parallel scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.jobs) as ex:
            futures = {ex.submit(scan_pkg, name): name for name in targets}
            for fut in concurrent.futures.as_completed(futures):
                if self._cancelled:
                    break
                try:
                    pkg_findings = fut.result()
                    findings.extend(pkg_findings)
                except Exception as e:
                    self._log("warning", "audit.scan.threadfail", f"Task failed: {e}", error=str(e))

        self._log("info", "audit.scan.done", f"Scan completed with {len(findings)} findings", findings=len(findings))
        return findings

    # ------------- planning -------------
    def plan(self, findings: List[AuditFinding]) -> List[AuditPlanItem]:
        """
        Create a remediation plan from findings.
        Returns a list of AuditPlanItem.
        """
        decorator = self._perf_timer("audit.plan") if self._perf_timer else None
        if decorator:
            return decorator(self._plan_impl)(findings)
        else:
            return self._plan_impl(findings)

    def _plan_impl(self, findings: List[AuditFinding]) -> List[AuditPlanItem]:
        plan: List[AuditPlanItem] = []
        for f in findings:
            # choose remediation based on recommended actions in finding and installed handlers
            rec = f.recommended or []
            chosen = None
            for r in rec:
                act = r.get("action")
                # prefer upgrade/rebuild where possible
                if act in ("upgrade", "rebuild") and self.upgrade_handler:
                    chosen = AuditPlanItem(package=f.package, action="rebuild", reason=r.get("reason", ""), details={"evidence": f.evidence})
                    break
                if act == "patch" and self.patcher_handler:
                    chosen = AuditPlanItem(package=f.package, action="patch", reason=r.get("reason", ""), details={"evidence": f.evidence})
                    break
                if act in ("remove", "maybe_remove") and self.remove_handler:
                    # require lower risk threshold for removal
                    if f.severity in ("low", "medium"):
                        chosen = AuditPlanItem(package=f.package, action="remove", reason=r.get("reason", ""), details={"evidence": f.evidence})
                        break
                # fallback manual
                if not chosen:
                    chosen = AuditPlanItem(package=f.package, action="manual", reason="no_auto_action", details={"evidence": f.evidence})
            if not chosen:
                chosen = AuditPlanItem(package=f.package, action="manual", reason="no_recommend", details={})
            plan.append(chosen)
        self._log("info", "audit.plan.ok", f"Plan built with {len(plan)} items", items=len(plan))
        return plan

    # ------------- execute plan -------------
    def execute_plan(self, plan: List[AuditPlanItem], confirm: bool = False, parallel: Optional[int] = None, use_sandbox: Optional[bool] = None) -> List[Dict[str, Any]]:
        """
        Execute the remediation plan.
        Returns a list of execution result dicts.
        """
        decorator = self._perf_timer("audit.execute") if self._perf_timer else None
        if decorator:
            return decorator(self._execute_impl)(plan, confirm, parallel, use_sandbox)
        else:
            return self._execute_impl(plan, confirm, parallel, use_sandbox)

    def _execute_impl(self, plan: List[AuditPlanItem], confirm: bool, parallel: Optional[int], use_sandbox: Optional[bool]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not plan:
            return results

        parallel = parallel or self.jobs
        use_sandbox = True if use_sandbox is None else bool(use_sandbox)

        if self.require_confirm := bool(self._cfg_get("audit.require_confirm", True)):
            if not confirm and not self.dry_run:
                self._log("warning", "audit.execute.no_confirm", "Execution requires explicit confirm flag")
                return [{"package": it.package, "action": it.action, "ok": False, "error": "no_confirm"} for it in plan]

        # worker for a single plan item
        def worker(item: AuditPlanItem) -> Dict[str, Any]:
            if self._cancelled:
                return {"package": item.package, "action": item.action, "ok": False, "error": "cancelled"}
            start = time.time()
            res = {"package": item.package, "action": item.action, "reason": item.reason, "details": item.details, "ts": self._now_ts()}
            # query db for files to backup
            files = []
            try:
                files = self.db.list_files(item.package) if self.db else []
            except Exception:
                files = []
            # create backup before destructive ops
            backup = None
            if item.action in ("remove", "patch", "rebuild"):
                backup = self._backup_paths(item.package, files)
                res["backup"] = backup

            # execute action
            try:
                if item.action == "rebuild":
                    if not self.upgrade_handler:
                        res.update({"ok": False, "error": "no_upgrade_handler"})
                    else:
                        # call rebuild; rely on its own dry-run handling
                        r = self.upgrade_handler.rebuild(item.package)
                        res.update({"ok": bool(r), "result": r})
                elif item.action == "patch":
                    if not self.patcher_handler:
                        res.update({"ok": False, "error": "no_patcher"})
                    else:
                        r = self.patcher_handler.apply_patches(item.package, dry_run=self.dry_run)
                        res.update({"ok": bool(r), "result": r})
                elif item.action == "remove":
                    if not self.remove_handler:
                        res.update({"ok": False, "error": "no_remove_handler"})
                    else:
                        # call remove handler with confirm True if not dry_run
                        r = self.remove_handler.execute_removal(item.package, confirm=(not self.dry_run), purge=False, use_sandbox=use_sandbox)
                        res.update({"ok": bool(r.get("ok")), "result": r})
                else:
                    # manual action suggested — do nothing automatically
                    res.update({"ok": False, "error": "manual_action_required"})
            except Exception as e:
                res.update({"ok": False, "error": f"exception: {e}"})
            res["duration"] = time.time() - start
            # record in DB
            try:
                if self.db and hasattr(self.db, "record_phase"):
                    self.db.record_phase(package=item.package, phase="audit.execute", status="ok" if res.get("ok") else "error", meta={"action": item.action, "duration": res.get("duration", 0)})
            except Exception:
                pass
            return res

        # parallel execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
            futures = {ex.submit(worker, it): it for it in plan}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    r = fut.result()
                    results.append(r)
                except Exception as e:
                    results.append({"package": "unknown", "action": "unknown", "ok": False, "error": str(e)})
        self._log("info", "audit.execute.done", f"Executed plan items: {len(results)}", executed=len(results))
        return results

    # ------------- report assembly -------------
    def assemble_report(self, findings: List[AuditFinding], plan: List[AuditPlanItem], executed: Optional[List[Dict[str, Any]]] = None) -> AuditReport:
        ts = self._now_ts()
        # simple summary counters
        counts = {"findings": len(findings), "plan_items": len(plan), "executed": len(executed or [])}
        report = AuditReport(ts=ts,
                             summary=counts,
                             findings=[f.to_dict() for f in findings],
                             plan=[p.to_dict() for p in plan],
                             executed=executed or [])
        self._save_report(report)
        # store high-level event in DB
        try:
            if self.db and hasattr(self.db, "record_event"):
                self.db.record_event(event="audit.run", ts=ts, meta=report.summary)
        except Exception:
            pass
        return report

    # ------------- CLI -------------
    @staticmethod
    def cli():
        import argparse
        p = argparse.ArgumentParser(prog="newpkg-audit", description="Audit installed packages for vulnerabilities/misconfigurations")
        p.add_argument("subcmd", choices=["scan", "plan", "execute", "report", "check"], help="subcommand")
        p.add_argument("--packages", nargs="*", help="specific package names to target (default: all)")
        p.add_argument("--confirm", action="store_true", help="confirm execution of planned actions")
        p.add_argument("--no-sandbox", action="store_true", help="do not use sandbox for remediation actions")
        p.add_argument("--json", action="store_true", help="output JSON only")
        p.add_argument("--quiet", action="store_true", help="quiet mode")
        p.add_argument("--jobs", type=int, help="parallel jobs override")
        args = p.parse_args()

        cfg = init_config() if init_config else None
        logger = NewpkgLogger.from_config(cfg, NewpkgDB(cfg)) if NewpkgLogger and cfg else None
        db = NewpkgDB(cfg) if NewpkgDB and cfg else None
        sandbox = NewpkgSandbox(cfg=cfg, logger=logger, db=db) if NewpkgSandbox and cfg else None

        audit = NewpkgAudit(cfg=cfg, logger=logger, db=db, sandbox=sandbox)
        if args.quiet:
            audit.quiet = True
        if args.json:
            audit.json_out = True
        if args.jobs:
            audit.jobs = args.jobs
        if args.no_sandbox:
            use_sandbox = False
        else:
            use_sandbox = True

        packages = args.packages or None

        if args.subcmd == "scan":
            findings = audit.scan(packages)
            out = [f.to_dict() for f in findings]
            if audit.json_out or args.json:
                print(json.dumps(out, indent=2))
            else:
                for f in out:
                    print(f"- {f['package']}: {f['issue']} [{f['severity']}]")
            raise SystemExit(0)

        if args.subcmd == "plan":
            findings = audit.scan(packages)
            plan = audit.plan(findings)
            out = [p.to_dict() for p in plan]
            if audit.json_out or args.json:
                print(json.dumps(out, indent=2))
            else:
                for p in out:
                    print(f"- {p['package']}: {p['action']} ({p['reason']})")
            raise SystemExit(0)

        if args.subcmd == "execute":
            findings = audit.scan(packages)
            plan = audit.plan(findings)
            executed = audit.execute_plan(plan, confirm=args.confirm, parallel=args.jobs, use_sandbox=use_sandbox)
            if audit.json_out or args.json:
                print(json.dumps(executed, indent=2))
            else:
                for e in executed:
                    status = "OK" if e.get("ok") else f"FAIL ({e.get('error')})"
                    print(f"- {e.get('package')}: {e.get('action')} => {status}")
            raise SystemExit(0)

        if args.subcmd == "report":
            findings = audit.scan(packages)
            plan = audit.plan(findings)
            executed = []
            report = audit.assemble_report(findings, plan, executed)
            if audit.json_out or args.json:
                print(json.dumps(report.to_dict(), indent=2))
            else:
                print(f"Report written: {report.ts} summary: {report.summary}")
            raise SystemExit(0)

        if args.subcmd == "check":
            # shorthand: scan + plan and show human summary
            findings = audit.scan(packages)
            plan = audit.plan(findings)
            counts = {"findings": len(findings), "plan": len(plan)}
            if audit.json_out or args.json:
                print(json.dumps(counts, indent=2))
            else:
                print(f"Findings: {counts['findings']}, Plan items: {counts['plan']}")
            raise SystemExit(0)

    # expose CLI hook
    run_cli = cli


if __name__ == "__main__":
    NewpkgAudit.cli()
