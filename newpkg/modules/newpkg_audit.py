#!/usr/bin/env python3
# newpkg_audit.py
"""
newpkg_audit.py

System audit & remediation planner for Newpkg.

Features:
 - scan_system(): discovers managed packages (via DB) and candidate binaries/files
 - check_vulnerabilities(): checks candidates against a vuln DB (simple local file or in-memory data)
 - plan_remediation(): builds a best-effort plan (upgrade, rebuild, patch, remove)
 - execute_plan(): applies plan sandboxed with backups, supports dry-run and auto_confirm
 - report(): outputs human-friendly text, JSON, or Markdown
 - parallel execution with ThreadPoolExecutor
 - integrates with newpkg_logger, newpkg_db, newpkg_hooks, newpkg_sandbox, newpkg_core, newpkg_remove, newpkg_deps

Notes:
 - This module performs *no* destructive actions unless dry_run=False and user confirms (or auto_confirm=True).
 - Vulnerability DB here is pluggable; a simple JSON layout is assumed:
    { "CVE-XXXX-YYYY": {"package": "zlib", "affected": "<1.2.13", "fixed_in": "1.2.13", "severity": 7.5} }
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# optional project imports
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
    from newpkg_hooks import HooksManager
except Exception:
    HooksManager = None

try:
    from newpkg_sandbox import Sandbox
except Exception:
    Sandbox = None

try:
    from newpkg_core import NewpkgCore
except Exception:
    NewpkgCore = None

try:
    from newpkg_remove import NewpkgRemover
except Exception:
    NewpkgRemover = None

try:
    from newpkg_deps import NewpkgDeps
except Exception:
    NewpkgDeps = None

# packaging.version for robust version comparisons
try:
    from packaging.version import Version, InvalidVersion
    _HAS_PACKAGING = True
except Exception:
    Version = None
    InvalidVersion = Exception
    _HAS_PACKAGING = False

# defaults
VULN_DB_DEFAULT = Path.home() / ".cache" / "newpkg" / "vulndb.json"
DEFAULT_PARALLEL = 8


@dataclass
class VulnRecord:
    cve: str
    package: str
    affected: str  # version spec like "<1.2.13"
    fixed_in: Optional[str] = None
    severity: float = 0.0
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Candidate:
    name: str
    version: Optional[str] = None
    path: Optional[str] = None
    source: str = "db"  # 'db' or 'filesystem' or 'other'
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FixAction:
    action: str  # 'upgrade' | 'rebuild' | 'patch' | 'remove' | 'manual'
    package: str
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditFinding:
    candidate: Candidate
    vulns: List[VulnRecord] = field(default_factory=list)
    recommended: List[FixAction] = field(default_factory=list)


class AuditError(Exception):
    pass


class NewpkgAudit:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.logger = logger or (NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None)
        self.db = db or (NewpkgDB(cfg) if NewpkgDB and cfg is not None else None)
        self.hooks = hooks or (HooksManager(cfg, self.logger, self.db) if HooksManager and cfg is not None else None)
        self.sandbox = sandbox or (Sandbox(cfg, self.logger, self.db) if Sandbox and cfg is not None else None)
        self.core = NewpkgCore(cfg, self.logger, self.db) if NewpkgCore and cfg is not None else None
        self.remover = NewpkgRemover(cfg, self.logger, self.db) if NewpkgRemover and cfg is not None else None
        self.deps = NewpkgDeps(cfg, self.logger, self.db) if NewpkgDeps and cfg is not None else None

        # settings
        self.vuln_db_path = Path(self._cfg_get("audit.vuln_db", os.environ.get("NEWPKG_AUDIT_VULNDB", str(VULN_DB_DEFAULT))))
        self.parallel = int(self._cfg_get("audit.parallel", os.environ.get("NEWPKG_AUDIT_PARALLEL", DEFAULT_PARALLEL)))
        self.auto_confirm = bool(self._cfg_get("audit.auto_confirm", False))
        self.use_sandbox = bool(self._cfg_get("audit.sandbox", True))
        self.backup_dir = Path(self._cfg_get("audit.backup_dir", os.environ.get("NEWPKG_AUDIT_BACKUP", "/var/tmp/newpkg_audit_backups")))
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # load vuln DB into memory
        self.vuln_db: Dict[str, VulnRecord] = {}
        self._load_vuln_db()

    # ---------------- helpers ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return default

    def _log(self, level: str, event: str, message: str = "", **meta):
        if self.logger:
            try:
                fn = getattr(self.logger, level.lower(), None)
                if fn:
                    fn(event, message, **meta)
                    return
            except Exception:
                pass
        # fallback
        print(f"[{level}] {event}: {message}")

    def _load_vuln_db(self):
        try:
            if self.vuln_db_path.exists():
                j = json.loads(self.vuln_db_path.read_text(encoding="utf-8"))
                for cve, rec in j.items():
                    vr = VulnRecord(
                        cve=cve,
                        package=rec.get("package"),
                        affected=rec.get("affected"),
                        fixed_in=rec.get("fixed_in"),
                        severity=float(rec.get("severity", 0.0)),
                        meta=rec.get("meta", {}),
                    )
                    self.vuln_db.setdefault(vr.package, []).append(vr)
            else:
                # empty DB is ok
                self.vuln_db = {}
        except Exception as e:
            self._log("warning", "audit.vulndb.load_fail", f"Failed loading vuln DB: {e}")

    def update_vuln_db(self, path_or_url: str, force: bool = False) -> bool:
        """
        Replace local vuln DB from a given JSON file path (or URL in future).
        Returns True on success.
        """
        try:
            p = Path(path_or_url)
            data = None
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                self.vuln_db_path.parent.mkdir(parents=True, exist_ok=True)
                p_dst = self.vuln_db_path
                p_dst.write_text(json.dumps(data, indent=2), encoding="utf-8")
            else:
                # TODO: support URLs (download via downloader)
                raise FileNotFoundError(path_or_url)
            # reload
            self._load_vuln_db()
            self._log("info", "audit.vulndb.update", f"Vuln DB updated from {path_or_url}")
            return True
        except Exception as e:
            self._log("error", "audit.vulndb.update_fail", f"Failed to update vuln DB: {e}", error=str(e))
            return False

    # ---------------- scanning ----------------
    def scan_system(self, include_unmanaged: bool = False) -> List[Candidate]:
        """
        Discover managed packages (via DB) and optionally scan common filesystem locations for binaries.
        Returns list of Candidate records.
        """
        candidates: List[Candidate] = []
        # prefer DB: list_packages() expected to return dicts with name/version
        if self.db and hasattr(self.db, "list_packages"):
            try:
                pkgs = self.db.list_packages()
                for p in pkgs:
                    candidates.append(Candidate(name=p.get("name"), version=p.get("version"), source="db", meta={"db": p}))
            except Exception:
                self._log("warning", "audit.scan.db_fail", "DB list_packages failed; falling back to filesystem")
        # if include_unmanaged, scan /usr/bin, /usr/lib, /opt, etc for ELF files
        if include_unmanaged:
            scan_paths = ["/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/opt"]
            for base in scan_paths:
                b = Path(base)
                if not b.exists():
                    continue
                for p in b.rglob("*"):
                    try:
                        if p.is_file():
                            # quick ELF detect
                            with p.open("rb") as fh:
                                hdr = fh.read(4)
                                if hdr == b"\x7fELF":
                                    candidates.append(Candidate(name=p.name, version=None, path=str(p), source="filesystem"))
                    except Exception:
                        continue
        self._log("info", "audit.scan.done", f"Scan produced {len(candidates)} candidates", count=len(candidates))
        return candidates

    # ---------------- vulnerability checks ----------------
    def _version_in_spec(self, version: Optional[str], spec: str) -> bool:
        """
        Basic check if a version satisfies an affected spec like '<1.2.13'.
        Uses packaging.version when available, otherwise naive compare.
        """
        if not version:
            return True  # unknown version should be considered potentially affected
        if not spec:
            return False
        # support only simple prefix operator for now: <, <=, >, >=, ==, !=
        ops = ["<=", ">=", "<", ">", "==", "!="]
        for op in ops:
            if spec.strip().startswith(op):
                target = spec.strip()[len(op) :].strip()
                if _HAS_PACKAGING:
                    try:
                        v = Version(version)
                        t = Version(target)
                        if op == "<":
                            return v < t
                        if op == "<=":
                            return v <= t
                        if op == ">":
                            return v > t
                        if op == ">=":
                            return v >= t
                        if op == "==":
                            return v == t
                        if op == "!=":
                            return v != t
                    except InvalidVersion:
                        return True
                else:
                    # fallback: lexicographic compare (best-effort)
                    try:
                        if op == "<":
                            return version < target
                        if op == "<=":
                            return version <= target
                        if op == ">":
                            return version > target
                        if op == ">=":
                            return version >= target
                        if op == "==":
                            return version == target
                        if op == "!=":
                            return version != target
                    except Exception:
                        return True
        # unknown spec form: be conservative
        return True

    def check_vulnerabilities(self, candidates: List[Candidate], severity_threshold: Optional[float] = None) -> List[AuditFinding]:
        """
        Check each candidate against the loaded vuln DB. Returns a list of AuditFinding
        including all matched CVEs for each candidate.
        severity_threshold: if provided, filter to vulns with severity >= threshold.
        """
        findings: List[AuditFinding] = []
        # helper function for one candidate
        def analyze(cand: Candidate) -> AuditFinding:
            vulns: List[VulnRecord] = []
            pkg = cand.name
            if pkg in self.vuln_db:
                for vr in self.vuln_db.get(pkg, []):
                    try:
                        if self._version_in_spec(cand.version, vr.affected):
                            if severity_threshold is None or vr.severity >= severity_threshold:
                                vulns.append(vr)
                    except Exception:
                        vulns.append(vr)
            return AuditFinding(candidate=cand, vulns=vulns)

        # parallel analyze
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel) as ex:
            futs = {ex.submit(analyze, c): c for c in candidates}
            for fut in concurrent.futures.as_completed(futs):
                af = fut.result()
                if af.vulns:
                    findings.append(af)
        self._log("info", "audit.check.done", f"Found {len(findings)} vulnerable candidates", vulnerabilities=sum(len(f.vulns) for f in findings))
        return findings

    # ---------------- plan remediation ----------------
    def plan_remediation(self, findings: List[AuditFinding]) -> Dict[str, Any]:
        """
        From findings, create a remediation plan.
        Strategy (best-effort):
         - If vuln.fixed_in present and version < fixed_in -> recommend 'upgrade'
         - If package is glibc-like or core system package -> recommend 'patch' or 'manual'
         - If no upgrade available but rebuild can help (e.g. needs rebuild against newer lib) -> 'rebuild'
         - If package is unmaintained -> 'remove'
        Returns plan with actions grouped by type.
        """
        plan: Dict[str, List[FixAction]] = defaultdict(list)
        summary: Dict[str, Any] = {"generated_at": datetime.utcnow().isoformat() + "Z", "actions": []}

        for af in findings:
            pkg = af.candidate.name
            # choose highest severity vuln for decision
            vulns_sorted = sorted(af.vulns, key=lambda v: v.severity, reverse=True)
            top = vulns_sorted[0]
            action = None
            details = {"vulns": [v.cve for v in vulns_sorted], "severity": top.severity, "fixed_in": top.fixed_in}
            # if fixed_in known and candidate version is older -> upgrade
            if top.fixed_in:
                if _HAS_PACKAGING and af.candidate.version:
                    try:
                        if Version(af.candidate.version) < Version(top.fixed_in):
                            action = FixAction("upgrade", pkg, f"upgrade to {top.fixed_in}", details)
                        else:
                            action = FixAction("rebuild", pkg, "rebuild against updated libs", details)
                    except Exception:
                        action = FixAction("upgrade", pkg, f"upgrade to {top.fixed_in}", details)
                else:
                    action = FixAction("upgrade", pkg, f"upgrade to {top.fixed_in}", details)
            else:
                # no known fix: if package has reverse deps big -> rebuild else manual/remove
                try:
                    rev = []
                    if self.db and hasattr(self.db, "get_reverse_deps"):
                        rev = self.db.get_reverse_deps(pkg)
                    if rev and len(rev) > 5:
                        action = FixAction("rebuild", pkg, "rebuild affected dependents", details)
                    else:
                        action = FixAction("manual", pkg, "no automated fix available; manual inspection", details)
                except Exception:
                    action = FixAction("manual", pkg, "no automated fix available", details)

            plan[action.action].append(action)
            summary["actions"].append({"package": pkg, "action": action.action, "reason": action.reason, "details": action.details})

        self._log("info", "audit.plan.generated", f"Generated plan with {sum(len(v) for v in plan.values())} actions")
        return {"plan": plan, "summary": summary}

    # ---------------- execution ----------------
    def _backup_before_action(self, targets: List[str], pkg: str) -> Optional[str]:
        """
        Create a compressed archive (tar.xz) of the target paths to enable rollback.
        Returns archive path or None.
        """
        try:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            out = self.backup_dir / f"{pkg}-audit-backup-{ts}.tar.xz"
            with tempfile.TemporaryDirectory(prefix="newpkg_audit_bkp_") as td:
                tmpdir = Path(td)
                # copy minimal set into tmp to preserve tree structure
                for t in targets:
                    tp = Path(t)
                    if tp.exists():
                        # preserve relative path under tmpdir root
                        dest = tmpdir / tp.name
                        if tp.is_dir():
                            shutil.copytree(tp, dest)
                        else:
                            shutil.copy2(tp, dest)
                # tar the tmpdir contents
                import tarfile
                with tarfile.open(out, "w:xz") as tar:
                    for item in tmpdir.iterdir():
                        tar.add(item, arcname=item.name)
            self._log("info", "audit.backup.ok", f"Backup created {out}", backup=str(out))
            return str(out)
        except Exception as e:
            self._log("warning", "audit.backup.fail", f"Backup failed: {e}")
            return None

    def execute_plan(self, plan: Dict[str, List[FixAction]], dry_run: bool = True, auto_confirm: Optional[bool] = None) -> Dict[str, Any]:
        """
        Execute remediation plan.
        - dry_run: if True, only simulate and return what would be done.
        - auto_confirm: override default auto_confirm behavior.
        Returns execution report.
        """
        auto_confirm = self.auto_confirm if auto_confirm is None else bool(auto_confirm)
        report: Dict[str, Any] = {"started_at": datetime.utcnow().isoformat() + "Z", "actions": [], "dry_run": bool(dry_run)}
        # run pre-exec hook
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("pre_audit_fix")
        except Exception:
            pass

        # helper to attempt an upgrade via newpkg_core or newpkg_upgrade if available
        def do_upgrade(action: FixAction) -> Dict[str, Any]:
            pkg = action.package
            rec = {"action": "upgrade", "package": pkg, "status": "skipped", "note": ""}
            if dry_run:
                rec["status"] = "planned"
                return rec
            # if core has update/upgrade API (best-effort)
            # we try to call core.full_build_cycle to rebuild a newer version only if we had source; prefer using a dedicated upgrade module if present
            try:
                # Example: call external upgrade module if exists
                mod = None
                try:
                    import importlib
                    mod = importlib.import_module("newpkg_upgrade")
                except Exception:
                    mod = None
                if mod and hasattr(mod, "NewpkgUpgrade"):
                    upgr = mod.NewpkgUpgrade(self.cfg, logger=self.logger, db=self.db)
                    r = upgr.install(action.package)
                    rec["status"] = "ok" if r else "error"
                    rec["result"] = r
                    return rec
                # fallback: run 'core.full_build_cycle' if available to rebuild latest sources (this is heuristic)
                if self.core:
                    res = self.core.full_build_cycle(pkg, do_package=False, do_deploy=False, dry_run=False)
                    rec["status"] = "ok" if res.status == "ok" else "error"
                    rec["result"] = {"core_result": res.status}
                    return rec
                rec["note"] = "no-upgrade-interface"
                return rec
            except Exception as e:
                rec["status"] = "error"
                rec["note"] = str(e)
                return rec

        def do_rebuild(action: FixAction) -> Dict[str, Any]:
            pkg = action.package
            rec = {"action": "rebuild", "package": pkg, "status": "skipped", "note": ""}
            if dry_run:
                rec["status"] = "planned"
                return rec
            try:
                # attempt to trigger rebuild via core or deps
                if self.core:
                    # best-effort: run a build cycle with do_package=False to rebuild libs
                    res = self.core.full_build_cycle(pkg, do_package=False, do_deploy=False, dry_run=False)
                    rec["status"] = "ok" if res.status == "ok" else "error"
                    rec["result"] = {"core_result": res.status}
                    return rec
                rec["note"] = "no-core-interface"
                return rec
            except Exception as e:
                rec["status"] = "error"
                rec["note"] = str(e)
                return rec

        def do_remove(action: FixAction) -> Dict[str, Any]:
            pkg = action.package
            rec = {"action": "remove", "package": pkg, "status": "skipped", "note": ""}
            if dry_run:
                rec["status"] = "planned"
                return rec
            try:
                # backup before destructive action
                # attempt to obtain file list from db
                targets = []
                if self.db and hasattr(self.db, "list_files"):
                    try:
                        files = self.db.list_files(pkg)
                        targets = files
                    except Exception:
                        targets = []
                # fallback heuristics: typical dirs
                if not targets:
                    targets = [f"/usr/lib/{pkg}", f"/usr/share/{pkg}", f"/etc/{pkg}"]
                backup = self._backup_before_action(targets, pkg)
                # call remover
                if self.remover:
                    r = self.remover.remove(pkg, purge=True, simulate=False, backup=False, use_sandbox=self.use_sandbox)
                    rec["status"] = "ok" if not r.get("errors") else "partial"
                    rec["result"] = r
                    rec["backup"] = backup
                    return rec
                # fallback: naive rm (dangerous!) -- do not perform unless explicitly allowed
                rec["note"] = "no-remover-interface"
                return rec
            except Exception as e:
                rec["status"] = "error"
                rec["note"] = str(e)
                return rec

        def do_patch(action: FixAction) -> Dict[str, Any]:
            pkg = action.package
            rec = {"action": "patch", "package": pkg, "status": "skipped", "note": ""}
            if dry_run:
                rec["status"] = "planned"
                return rec
            # Patching strategy is highly package-specific; attempt to call patcher module if exists
            try:
                import importlib
                try:
                    mod = importlib.import_module("newpkg_patcher")
                except Exception:
                    mod = None
                if mod and hasattr(mod, "NewpkgPatcher"):
                    patcher = mod.NewpkgPatcher(self.cfg, logger=self.logger, db=self.db)
                    # expectation: action.details contains patch info or CVE->patch mapping
                    patch_info = action.details.get("patch_info")
                    if patch_info:
                        r = patcher.apply_patch(patch_info.get("path"), cwd=None)
                        rec["status"] = "ok" if r and r.get("status") == "ok" else "error"
                        rec["result"] = r
                        return rec
                rec["note"] = "no-patcher-interface"
                return rec
            except Exception as e:
                rec["status"] = "error"
                rec["note"] = str(e)
                return rec

        # flatten actions in a safe execution order: upgrade -> patch -> rebuild -> remove -> manual
        order = ["upgrade", "patch", "rebuild", "remove", "manual"]
        for phase in order:
            actions = plan.get(phase, []) if isinstance(plan, dict) else []
            for act in actions:
                # require confirmation unless auto_confirm True
                if not auto_confirm and not dry_run:
                    ok = self._prompt_confirm(f"About to execute {act.action} on {act.package} (reason: {act.reason}). Continue? [y/N]: ")
                    if not ok:
                        report["actions"].append({"package": act.package, "action": act.action, "status": "skipped", "note": "user_cancelled"})
                        continue
                # dispatch
                if act.action == "upgrade":
                    rec = do_upgrade(act)
                elif act.action == "rebuild":
                    rec = do_rebuild(act)
                elif act.action == "remove":
                    rec = do_remove(act)
                elif act.action == "patch":
                    rec = do_patch(act)
                else:
                    rec = {"action": act.action, "package": act.package, "status": "manual", "note": act.reason}
                report["actions"].append(rec)
        report["finished_at"] = datetime.utcnow().isoformat() + "Z"
        # post-exec hook
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("post_audit_fix")
        except Exception:
            pass
        self._log("info", "audit.execute.done", f"Executed plan (dry_run={dry_run})", summary=report.get("actions"))
        return report

    def _prompt_confirm(self, prompt: str) -> bool:
        try:
            ans = input(prompt)
            return ans.strip().lower() in ("y", "yes")
        except Exception:
            return False

    # ---------------- report generation ----------------
    def report(self, findings: List[AuditFinding], plan_summary: Optional[Dict[str, Any]] = None, format: str = "text") -> str:
        """
        Produce a report in text, json, or markdown.
        """
        if format == "json":
            out = {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "findings": [
                    {
                        "package": f.candidate.name,
                        "version": f.candidate.version,
                        "path": f.candidate.path,
                        "vulns": [{"cve": v.cve, "affected": v.affected, "fixed_in": v.fixed_in, "severity": v.severity} for v in f.vulns],
                        "recommended": [{"action": a.action, "reason": a.reason, "details": a.details} for a in f.recommended],
                    }
                    for f in findings
                ],
                "plan_summary": plan_summary,
            }
            return json.dumps(out, indent=2)
        if format == "markdown":
            lines: List[str] = []
            lines.append(f"# Audit Report — {datetime.utcnow().isoformat()}Z\n")
            for f in findings:
                lines.append(f"## Package: `{f.candidate.name}`  ")
                lines.append(f"- Version: `{f.candidate.version}`")
                if f.candidate.path:
                    lines.append(f"- Path: `{f.candidate.path}`")
                lines.append(f"- Vulnerabilities:")
                for v in f.vulns:
                    lines.append(f"  - **{v.cve}** severity={v.severity} affected=`{v.affected}` fixed_in=`{v.fixed_in}`")
                if f.recommended:
                    lines.append("- Recommended fixes:")
                    for a in f.recommended:
                        lines.append(f"  - `{a.action}` — {a.reason} — details: {json.dumps(a.details)}")
                lines.append("")  # blank
            if plan_summary:
                lines.append("## Plan Summary")
                lines.append(f"```\n{json.dumps(plan_summary, indent=2)}\n```")
            return "\n".join(lines)
        # default text
        out_lines: List[str] = []
        out_lines.append(f"Audit Report — {datetime.utcnow().isoformat()}Z")
        out_lines.append("=" * 60)
        for f in findings:
            out_lines.append(f"Package: {f.candidate.name}  Version: {f.candidate.version or 'unknown'}")
            if f.candidate.path:
                out_lines.append(f"  Path: {f.candidate.path}")
            for v in f.vulns:
                out_lines.append(f"  - {v.cve}: affected {v.affected}  fixed_in={v.fixed_in} severity={v.severity}")
            if f.recommended:
                out_lines.append("  Recommended:")
                for a in f.recommended:
                    out_lines.append(f"    * {a.action} — {a.reason} — {a.details}")
            out_lines.append("-" * 40)
        if plan_summary:
            out_lines.append("Plan Summary:")
            out_lines.append(json.dumps(plan_summary, indent=2))
        return "\n".join(out_lines)

    # ---------------- convenience CLI ----------------
    @classmethod
    def cli_main(cls, argv: Optional[List[str]] = None):
        import argparse
        import sys

        p = argparse.ArgumentParser(prog="newpkg-audit", description="Audit system for vulnerable packages and plan remediation")
        p.add_argument("cmd", choices=["scan", "check", "plan", "execute", "report", "update-db"])
        p.add_argument("--include-unmanaged", action="store_true", help="scan filesystem for unmanaged ELF binaries")
        p.add_argument("--severity", type=float, help="minimum severity to report (e.g. 5.0)")
        p.add_argument("--dry-run", action="store_true", default=True, help="do not apply changes (default true)")
        p.add_argument("--auto-confirm", action="store_true", help="do not prompt for confirmation when executing plan")
        p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
        p.add_argument("--vulndb", help="path to vuln DB json file to use/update")
        args = p.parse_args(argv)

        cfg = None
        if init_config:
            try:
                cfg = init_config()
            except Exception:
                cfg = None
        db = NewpkgDB(cfg) if NewpkgDB and cfg is not None else None
        logger = NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None
        hooks = HooksManager(cfg, logger, db) if HooksManager and cfg is not None else None
        sandbox = Sandbox(cfg, logger, db) if Sandbox and cfg is not None else None

        auditor = cls(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)

        if args.cmd == "update-db":
            if not args.vulndb:
                print("please provide --vulndb path")
                return 2
            ok = auditor.update_vuln_db(args.vulndb)
            print("updated" if ok else "failed")
            return 0 if ok else 1

        if args.cmd == "scan":
            cands = auditor.scan_system(include_unmanaged=args.include_unmanaged)
            print(json.dumps([c.__dict__ for c in cands], indent=2))
            return 0

        if args.cmd == "check":
            cands = auditor.scan_system(include_unmanaged=args.include_unmanaged)
            finds = auditor.check_vulnerabilities(cands, severity_threshold=args.severity)
            print(auditor.report(finds, format=args.format))
            return 0

        if args.cmd == "plan":
            cands = auditor.scan_system(include_unmanaged=args.include_unmanaged)
            finds = auditor.check_vulnerabilities(cands, severity_threshold=args.severity)
            plan = auditor.plan_remediation(finds)
            # attach recommended fixes to findings for report
            for f in finds:
                # find from plan summary
                recs = []
                for action_group in plan["plan"].values():
                    for act in action_group:
                        if act.package == f.candidate.name:
                            recs.append(act)
                f.recommended = recs
            print(auditor.report(finds, plan_summary=plan["summary"], format=args.format))
            return 0

        if args.cmd == "execute":
            cands = auditor.scan_system(include_unmanaged=args.include_unmanaged)
            finds = auditor.check_vulnerabilities(cands, severity_threshold=args.severity)
            plan = auditor.plan_remediation(finds)
            report = auditor.execute_plan(plan["plan"], dry_run=args.dry_run, auto_confirm=args.auto_confirm)
            print(json.dumps(report, indent=2))
            return 0

        if args.cmd == "report":
            # load last scan from DB? For now run a fresh one
            cands = auditor.scan_system(include_unmanaged=args.include_unmanaged)
            finds = auditor.check_vulnerabilities(cands, severity_threshold=args.severity)
            plan = auditor.plan_remediation(finds)
            print(auditor.report(finds, plan_summary=plan["summary"], format=args.format))
            return 0

        p.print_help()
        return 1


if __name__ == "__main__":
    NewpkgAudit.cli_main()
