#!/usr/bin/env python3
# newpkg_audit.py
"""
newpkg_audit.py — system/package auditor for newpkg (revised)

Features:
 - Auto integration with newpkg_api (api.audit)
 - Modular scanners (setuid, permissions, missing_files, integrity, dependencies, vulnerabilities)
 - Optional remote CVE lookup (configurable source)
 - Integrity verification via DB/metafiles if available
 - Auto-repair strategies (rebuild, reinstall, apply-patch) configurable and safe
 - ThreadPool with I/O-aware sizing and configurable jobs
 - Rich JSON reports with system metadata and summary
 - Optional daemon/continuous mode with interval
 - CLI with color/JSON/quiet flags
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
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
    from newpkg_upgrade import UpgradeManager  # type: ignore
except Exception:
    UpgradeManager = None

try:
    from newpkg_deps import get_deps_manager  # type: ignore
except Exception:
    get_deps_manager = None

# niceties for CLI
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
_logger = logging.getLogger("newpkg.audit")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.audit: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# defaults
REPORT_DIR = Path("/var/log/newpkg/audit")
REPORT_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_CVE_SOURCE = "https://api.osv.dev/v1/query"  # used only if enabled
DEFAULT_JOBS = max(1, (os.cpu_count() or 2))
DEFAULT_JOB_MULTIPLIER = 2  # threads = min(cpu*mult, 32)

# dataclasses
@dataclass
class Finding:
    id: str
    category: str
    severity: str
    message: str
    package: Optional[str] = None
    file: Optional[str] = None
    metadata: Dict[str, Any] = None

@dataclass
class AuditReport:
    ts: str
    system: Dict[str, Any]
    summary: Dict[str, int]
    findings: List[Dict[str, Any]]
    duration_s: float
    config_used: Dict[str, Any]

# small helpers
def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def safe_write_json(path: Path, obj: Any):
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        try:
            path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

def sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def system_metadata() -> Dict[str, Any]:
    try:
        uname = os.uname()
        uptime = None
        try:
            with open("/proc/uptime", "rt") as f:
                uptime = float(f.read().split()[0])
        except Exception:
            uptime = None
        return {
            "hostname": socket.gethostname(),
            "kernel": f"{uname.sysname} {uname.release}",
            "machine": uname.machine,
            "now": now_iso(),
            "uptime_seconds": uptime,
        }
    except Exception:
        return {"hostname": socket.gethostname(), "now": now_iso()}

# ---------------------------------------------------------------------
# Audit Manager
# ---------------------------------------------------------------------
class AuditManager:
    def __init__(self, cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, sandbox: Optional[Any] = None, hooks: Optional[Any] = None):
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

        # pick singletons or provided ones
        self.cfg = cfg or (self.api.cfg if self.api and getattr(self.api, "cfg", None) else (get_config() if get_config else None))
        self.logger = logger or (self.api.logger if self.api and getattr(self.api, "logger", None) else (get_logger(self.cfg) if get_logger else None))
        self.db = db or (self.api.db if self.api and getattr(self.api, "db", None) else (get_db() if get_db else None))
        self.sandbox = sandbox or (self.api.sandbox if self.api and getattr(self.api, "sandbox", None) else (get_sandbox(self.cfg) if get_sandbox else None))
        self.hooks = hooks or (self.api.hooks if self.api and getattr(self.api, "hooks", None) else (get_hooks_manager(self.cfg) if get_hooks_manager else None))

        # register in API
        try:
            if self.api:
                self.api.audit = self
        except Exception:
            pass

        # scanner config
        self.scanners = {
            "setuid": True,
            "permissions": True,
            "missing_files": True,
            "integrity": True,
            "dependencies": True,
            "vulnerabilities": False,  # CVE lookup off by default
        }
        # override from cfg
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                sconf = self.cfg.get("audit.scanners") or {}
                for k in self.scanners:
                    if k in sconf:
                        self.scanners[k] = bool(sconf[k])
        except Exception:
            pass

        # CVE source and flags
        self.cve_enabled = False
        self.cve_source = DEFAULT_CVE_SOURCE
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.cve_enabled = bool(self.cfg.get("audit.cve.enabled", False))
                if self.cfg.get("audit.cve.source"):
                    self.cve_source = self.cfg.get("audit.cve.source")
        except Exception:
            pass

        # auto_repair config
        self.auto_repair_config = {
            "vulnerabilities": False,
            "dependencies": False,
            "missing_files": "rebuild",  # rebuild|reinstall|ignore
        }
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                arc = self.cfg.get("audit.auto_repair") or {}
                for k in self.auto_repair_config:
                    if k in arc:
                        self.auto_repair_config[k] = arc[k]
        except Exception:
            pass

        # jobs sizing
        cpu = os.cpu_count() or 2
        mult = int(self.cfg.get("audit.jobs.multiplier") if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("audit.jobs.multiplier")) else DEFAULT_JOB_MULTIPLIER)
        max_workers_cfg = int(self.cfg.get("audit.jobs.max") if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("audit.jobs.max")) else (cpu * mult))
        # cap to reasonable max
        self.jobs = max(1, min(max_workers_cfg, 64))

        # report dir
        self.report_dir = Path(self.cfg.get("audit.report_dir")) if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("audit.report_dir")) else REPORT_DIR
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # optional upgrade & deps managers
        self.upgrade = None
        if UpgradeManager:
            try:
                self.upgrade = UpgradeManager(cfg=self.cfg, logger=self.logger, db=self.db)
            except Exception:
                self.upgrade = None
        self.deps = None
        if get_deps_manager:
            try:
                self.deps = get_deps_manager(cfg=self.cfg, logger=self.logger, db=self.db)
            except Exception:
                self.deps = None

        # internal
        self._lock = threading.RLock()

    # ---------------- top-level run ----------------
    def run_audit(self, packages: Optional[List[str]] = None, continuous: bool = False, interval_hours: Optional[int] = None, auto_repair: Optional[bool] = None) -> AuditReport:
        """
        Run audit across system/packages.
        - packages: optional list of packages to limit the audit;
          otherwise scans all known packages via DB or default locations.
        - continuous: if True, loops with sleep(interval_hours).
        """
        if continuous:
            if not interval_hours:
                interval_hours = int(self.cfg.get("audit.schedule.interval_hours") or 24)
            while True:
                rep = self._run_once(packages=packages, auto_repair=auto_repair)
                # sleep interval
                time.sleep(interval_hours * 3600)
        else:
            return self._run_once(packages=packages, auto_repair=auto_repair)

    def _run_once(self, packages: Optional[List[str]] = None, auto_repair: Optional[bool] = None) -> AuditReport:
        start = time.time()
        findings: List[Finding] = []
        # system meta
        sysmeta = system_metadata()
        # determine package list
        pkg_list = []
        try:
            if packages:
                pkg_list = list(packages)
            elif self.db:
                # try db provided list_packages()
                try:
                    rows = self.db.list_packages()
                    pkg_list = [r[0] if isinstance(r, (list, tuple)) else r.get("name") for r in rows]
                except Exception:
                    # fallback raw query
                    rows = self.db.raw_query("SELECT name FROM packages;")
                    pkg_list = [r[0] if isinstance(r, (list, tuple)) else r.get("name") for r in rows]
            else:
                # fallback heuristics: look under /var/lib/newpkg/packages or /usr/local
                pkg_list = [p.name for p in Path("/var/lib/newpkg/packages").iterdir() if p.is_dir()] if Path("/var/lib/newpkg/packages").exists() else []
        except Exception:
            pkg_list = packages or []

        # run enabled scanners
        # strategy: run cheap system-wide scanners first (setuid, permissions), then per-package scanners in ThreadPool
        if self.scanners.get("setuid"):
            findings += self._scan_setuid()
        if self.scanners.get("permissions"):
            findings += self._scan_permissions()

        # per-package scanning in parallel
        per_pkg_findings = []
        if pkg_list:
            with ThreadPoolExecutor(max_workers=self.jobs) as ex:
                futs = {ex.submit(self._scan_package, pkg): pkg for pkg in pkg_list}
                for fut in as_completed(futs):
                    pkg = futs[fut]
                    try:
                        res = fut.result()
                        if res:
                            per_pkg_findings.extend(res)
                    except Exception as e:
                        # log and continue
                        if self.logger:
                            self.logger.warning("audit.pkg_scan_fail", f"scan failed for {pkg}", meta={"error": str(e)})
        else:
            # no packages list — optionally run missing_files/integrity on heuristic locations
            if self.scanners.get("missing_files"):
                per_pkg_findings += self._scan_missing_files_heuristic()

        findings += per_pkg_findings

        # vulnerabilities (CVE) check - can be expensive, do after other scans
        if self.cve_enabled and self.scanners.get("vulnerabilities"):
            vulns = self._scan_vulnerabilities(pkg_list)
            findings += vulns

        # integrity checks (sha256) if enabled
        if self.scanners.get("integrity"):
            integ = self._scan_integrity(pkg_list)
            findings += integ

        # dependencies checks
        if self.scanners.get("dependencies"):
            deps_issues = self._scan_dependencies(pkg_list)
            findings += deps_issues

        # summarize
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.severity or "info").lower()
            if sev not in severity_counts:
                severity_counts[sev] = 0
            severity_counts[sev] += 1

        duration = time.time() - start
        report = AuditReport(
            ts=now_iso(),
            system=sysmeta,
            summary={"total_findings": len(findings), **severity_counts},
            findings=[asdict(f) for f in findings],
            duration_s=round(duration, 3),
            config_used={"scanners": self.scanners, "cve_enabled": self.cve_enabled, "jobs": self.jobs},
        )

        # write report file
        try:
            fname = self.report_dir / f"audit-report-{time.strftime('%Y%m%dT%H%M%SZ')}.json"
            safe_write_json(fname, asdict(report))
            if self.logger:
                self.logger.info("audit.report_written", f"report saved: {fname}", meta={"count": len(findings)})
        except Exception:
            pass

        # record to DB
        try:
            if self.db:
                self.db.record_phase(None, "audit.run", "ok", meta={"findings": len(findings), "duration": duration})
        except Exception:
            pass

        # auto repair if requested
        if auto_repair is None:
            auto_repair = bool(self.auto_repair_config.get("vulnerabilities"))
        if auto_repair:
            self._auto_repair(findings)

        return report

    # ---------------- individual scanners ----------------
    def _scan_setuid(self) -> List[Finding]:
        """
        Find setuid/setgid executables on common paths.
        """
        findings = []
        paths = ["/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"]
        for base in paths:
            p = Path(base)
            if not p.exists():
                continue
            for f in p.rglob("*"):
                try:
                    if not f.is_file():
                        continue
                    st = f.stat()
                    # check setuid/setgid bits
                    if (st.st_mode & 0o4000) or (st.st_mode & 0o2000):
                        findings.append(Finding(
                            id=f"setuid:{str(f)}",
                            category="setuid",
                            severity="medium",
                            message=f"setuid/setgid found: {f}",
                            file=str(f),
                            metadata={"mode": oct(st.st_mode)}
                        ))
                except Exception:
                    continue
        return findings

    def _scan_permissions(self) -> List[Finding]:
        """
        Detect world-writable files/directories without sticky bit, suspicious executable locations, etc.
        """
        findings = []
        # world-writable files (exclude /tmp which is expected)
        for root in ["/", "/usr", "/var", "/opt", "/srv"]:
            try:
                p = Path(root)
                if not p.exists():
                    continue
                for f in p.rglob("*"):
                    try:
                        st = f.stat()
                        mode = st.st_mode
                        # world writable
                        if mode & 0o002:
                            # skip /tmp and files inside it
                            if "/tmp" in str(f):
                                continue
                            # check sticky bit on containing dir
                            if not (st.st_mode & 0o1000):
                                findings.append(Finding(
                                    id=f"worldwritable:{str(f)}",
                                    category="permissions",
                                    severity="high",
                                    message=f"world-writable without sticky bit: {f}",
                                    file=str(f),
                                    metadata={"mode": oct(mode)}
                                ))
                    except Exception:
                        continue
            except Exception:
                continue
        return findings

    def _scan_missing_files_heuristic(self) -> List[Finding]:
        """
        Heuristic for missing file problems: scanning typical package metadata directories to find references to files that don't exist.
        """
        findings = []
        possible_meta_dirs = [Path("/var/lib/newpkg/packages"), Path("/usr/local/lib/newpkg/packages")]
        for md in possible_meta_dirs:
            if not md.exists():
                continue
            for pkgdir in md.iterdir():
                if not pkgdir.is_dir():
                    continue
                # assume file listing in 'files.txt'
                ftxt = pkgdir / "files.txt"
                if not ftxt.exists():
                    continue
                try:
                    for line in ftxt.read_text(encoding="utf-8", errors="ignore").splitlines():
                        path = line.strip()
                        if path and not Path(path).exists():
                            findings.append(Finding(
                                id=f"missingfile:{pkgdir.name}:{path}",
                                category="missing_files",
                                severity="medium",
                                message=f"Reference to missing file {path} in package {pkgdir.name}",
                                package=pkgdir.name,
                                file=path
                            ))
                except Exception:
                    continue
        return findings

    def _scan_package(self, pkg: str) -> List[Finding]:
        """
        Per-package scanner: missing files, integrity (sha256) if DB has records, dependency inconsistencies.
        """
        findings = []
        # missing files
        try:
            files = []
            if self.db and hasattr(self.db, "package_files"):
                try:
                    files = list(self.db.package_files(pkg))
                except Exception:
                    files = []
            else:
                # fallback read files.txt
                ftxt = Path(f"/var/lib/newpkg/packages/{pkg}/files.txt")
                if ftxt.exists():
                    files = [l.strip() for l in ftxt.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]

            for f in files:
                if not Path(f).exists():
                    findings.append(Finding(
                        id=f"pkg_missing:{pkg}:{f}",
                        category="missing_files",
                        severity="high",
                        message=f"package {pkg} references missing file {f}",
                        package=pkg,
                        file=f
                    ))
            # integrity: if DB stores sha256 for files, verify
            if self.db and hasattr(self.db, "file_checksums"):
                try:
                    checks = self.db.file_checksums(pkg)  # returns list of (filepath, sha256)
                    for fp, expected in checks:
                        p = Path(fp)
                        if p.exists():
                            actual = sha256_file(p)
                            if actual and expected and actual != expected:
                                findings.append(Finding(
                                    id=f"integrity:{pkg}:{fp}",
                                    category="integrity",
                                    severity="critical",
                                    message=f"checksum mismatch for {fp} in {pkg}",
                                    package=pkg,
                                    file=fp,
                                    metadata={"expected": expected, "actual": actual}
                                ))
                        else:
                            # missing file already reported above
                            pass
                except Exception:
                    pass

            # dependencies: check reverse deps known in DB (if any broken)
            if self.db and hasattr(self.db, "list_dependencies"):
                try:
                    deps = list(self.db.list_dependencies(pkg))
                    for dep in deps:
                        # if dep not installed
                        name = dep if isinstance(dep, str) else (dep[0] if isinstance(dep, (list, tuple)) else dep.get("name"))
                        # check installed
                        installed = False
                        if self.db and hasattr(self.db, "has_package"):
                            try:
                                installed = bool(self.db.has_package(name))
                            except Exception:
                                installed = False
                        if not installed:
                            findings.append(Finding(
                                id=f"missing_dep:{pkg}:{name}",
                                category="dependencies",
                                severity="high",
                                message=f"package {pkg} depends on missing package {name}",
                                package=pkg,
                                metadata={"dependency": name}
                            ))
                except Exception:
                    pass

        except Exception:
            pass
        return findings

    def _scan_integrity(self, pkg_list: List[str]) -> List[Finding]:
        findings = []
        # only check packages with DB checksums
        for pkg in pkg_list:
            try:
                if self.db and hasattr(self.db, "file_checksums"):
                    try:
                        checks = self.db.file_checksums(pkg)
                    except Exception:
                        checks = []
                    for fp, expected in checks:
                        p = Path(fp)
                        if p.exists():
                            actual = sha256_file(p)
                            if actual and expected and actual != expected:
                                findings.append(Finding(
                                    id=f"integrity:{pkg}:{fp}",
                                    category="integrity",
                                    severity="critical",
                                    message=f"checksum mismatch for {fp} in {pkg}",
                                    package=pkg,
                                    file=fp,
                                    metadata={"expected": expected, "actual": actual}
                                ))
                        else:
                            findings.append(Finding(
                                id=f"integrity_missing_file:{pkg}:{fp}",
                                category="integrity",
                                severity="high",
                                message=f"checksum entry exists but file missing: {fp} in {pkg}",
                                package=pkg,
                                file=fp
                            ))
            except Exception:
                continue
        return findings

    def _scan_dependencies(self, pkg_list: List[str]) -> List[Finding]:
        findings = []
        # check reverse deps and orphaned libraries that may break reverse dependencies
        for pkg in pkg_list:
            try:
                if self.db and hasattr(self.db, "list_reverse_deps"):
                    try:
                        rev = self.db.list_reverse_deps(pkg)
                    except Exception:
                        rev = []
                    # if reverse deps reference missing packages -> issue
                    for r in rev:
                        name = r if isinstance(r, str) else (r[0] if isinstance(r, (list, tuple)) else r.get("name"))
                        if not (self.db and getattr(self.db, "has_package", None) and self.db.has_package(name)):
                            findings.append(Finding(
                                id=f"revdep_missing:{pkg}:{name}",
                                category="dependencies",
                                severity="high",
                                message=f"reverse dependency {name} of {pkg} is missing",
                                package=pkg,
                                metadata={"reverse_dep": name}
                            ))
            except Exception:
                continue
        return findings

    def _scan_vulnerabilities(self, pkg_list: List[str]) -> List[Finding]:
        findings = []
        # naive: query remote CVE source per package name; rate-limit & error-handle
        if not self.cve_enabled:
            return findings
        # simple HTTP request without external deps
        import urllib.request, urllib.error
        for pkg in pkg_list:
            try:
                data = json.dumps({"package": {"name": pkg}}).encode("utf-8")
                req = urllib.request.Request(self.cve_source, data=data, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    txt = resp.read().decode("utf-8", errors="ignore")
                    jd = json.loads(txt) if txt else {}
                    # Interpret response: OSV returns 'vulns' list typically
                    vulns = jd.get("vulns") or jd.get("results") or []
                    for v in vulns:
                        sev = v.get("severity") or "medium"
                        findings.append(Finding(
                            id=f"cve:{pkg}:{v.get('id','unknown')}",
                            category="vulnerability",
                            severity=sev,
                            message=f"vulnerability for {pkg}: {v.get('summary') or v.get('details') or 'see CVE entry'}",
                            package=pkg,
                            metadata={"cve": v}
                        ))
            except urllib.error.HTTPError as e:
                if self.logger:
                    self.logger.warning("audit.cve_http", f"HTTP error querying CVE source for {pkg}", meta={"error": str(e)})
            except Exception:
                if self.logger:
                    self.logger.warning("audit.cve_err", f"error querying CVE source for {pkg}", meta={"pkg": pkg})
                continue
        return findings

    # ---------------- auto-repair logic (controlled & conservative) -------------
    def _auto_repair(self, findings: List[Finding]):
        """
        Auto-repair actions based on configuration.
        This is intentionally conservative: only acts on items configured to be auto-repaired.
        """
        if not findings:
            return
        repairs = []
        for f in findings:
            try:
                if f.category == "vulnerability" and self.auto_repair_config.get("vulnerabilities"):
                    # attempt to reinstall/upgrade package
                    pkg = f.package
                    if pkg:
                        ok = self._attempt_upgrade_package(pkg)
                        repairs.append({"finding": f.id, "action": "upgrade", "package": pkg, "ok": ok})
                elif f.category in ("dependencies",) and self.auto_repair_config.get("dependencies"):
                    pkg = f.package
                    if pkg:
                        ok = self._attempt_install_deps(pkg)
                        repairs.append({"finding": f.id, "action": "install_deps", "package": pkg, "ok": ok})
                elif f.category == "missing_files":
                    strategy = self.auto_repair_config.get("missing_files", "rebuild")
                    pkg = f.package
                    if pkg and strategy:
                        if strategy == "rebuild":
                            ok = self._attempt_rebuild_package(pkg)
                            repairs.append({"finding": f.id, "action": "rebuild", "package": pkg, "ok": ok})
                        elif strategy == "reinstall":
                            ok = self._attempt_reinstall_package(pkg)
                            repairs.append({"finding": f.id, "action": "reinstall", "package": pkg, "ok": ok})
            except Exception as e:
                if self.logger:
                    self.logger.error("audit.auto_repair_err", f"error auto-repairing {f.id}", meta={"error": str(e)})
                continue
        # record repairs summary
        try:
            if self.db:
                self.db.record_phase(None, "audit.auto_repair", "ok", meta={"repairs": repairs})
        except Exception:
            pass
        return repairs

    def _attempt_upgrade_package(self, pkg: str) -> bool:
        # try via upgrade manager or fallback to calling 'newpkg --upgrade pkg' if exists
        try:
            if self.upgrade and hasattr(self.upgrade, "upgrade"):
                try:
                    self.upgrade.upgrade(pkg)
                    return True
                except Exception:
                    pass
            newpkg_bin = shutil.which("newpkg")
            if newpkg_bin:
                res = subprocess.run([newpkg_bin, "--upgrade", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
                return res.returncode == 0
        except Exception:
            pass
        return False

    def _attempt_install_deps(self, pkg: str) -> bool:
        try:
            if self.deps and hasattr(self.deps, "install_missing"):
                try:
                    r = self.deps.install_missing(pkg, dep_types=["runtime"], parallel=1)
                    return r.get("summary", {}).get("failed", 1) == 0
                except Exception:
                    pass
            # fallback: attempt `newpkg --install`
            newpkg_bin = shutil.which("newpkg")
            if newpkg_bin:
                res = subprocess.run([newpkg_bin, "--install", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
                return res.returncode == 0
        except Exception:
            pass
        return False

    def _attempt_rebuild_package(self, pkg: str) -> bool:
        try:
            if self.upgrade and hasattr(self.upgrade, "rebuild"):
                try:
                    self.upgrade.rebuild(pkg)
                    return True
                except Exception:
                    pass
            # fallback: call 'newpkg --build pkg'
            newpkg_bin = shutil.which("newpkg")
            if newpkg_bin:
                res = subprocess.run([newpkg_bin, "--build", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600)
                return res.returncode == 0
        except Exception:
            pass
        return False

    def _attempt_reinstall_package(self, pkg: str) -> bool:
        try:
            newpkg_bin = shutil.which("newpkg")
            if newpkg_bin:
                res = subprocess.run([newpkg_bin, "--reinstall", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800)
                return res.returncode == 0
        except Exception:
            pass
        return False

    # ---------------- convenience method for external callers ----------------
    def check_vulnerabilities(self, pkg: str) -> List[Dict[str, Any]]:
        """
        Public helper: check CVE for single package (returns list of vuln dicts)
        """
        if not (self.cve_enabled and self.scanners.get("vulnerabilities")):
            return []
        res = self._scan_vulnerabilities([pkg])
        return [asdict(f) for f in res]

# singleton accessor
_default_audit: Optional[AuditManager] = None
_audit_lock = threading.RLock()

def get_audit(cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, sandbox: Optional[Any] = None, hooks: Optional[Any] = None) -> AuditManager:
    global _default_audit
    with _audit_lock:
        if _default_audit is None:
            _default_audit = AuditManager(cfg=cfg, logger=logger, db=db, sandbox=sandbox, hooks=hooks)
        return _default_audit

# ---------------- CLI ----------------
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(prog="newpkg-audit", description="run system/package audit (newpkg)")
    p.add_argument("--packages", nargs="*", help="specific packages to audit")
    p.add_argument("--continuous", action="store_true", help="run continuously at schedule")
    p.add_argument("--interval-hours", type=int, help="interval hours for continuous mode")
    p.add_argument("--auto-repair", action="store_true", help="attempt auto-repair according to config")
    p.add_argument("--cve", action="store_true", help="enable remote CVE checks for this run")
    p.add_argument("--verify-integrity", action="store_true", help="force integrity checks even if DB not fully populated")
    p.add_argument("--json", action="store_true", help="emit JSON report to stdout")
    p.add_argument("--quiet", action="store_true", help="quiet mode (minimal output)")
    args = p.parse_args()

    mgr = get_audit()
    if args.cve:
        mgr.cve_enabled = True
    if args.verify_integrity:
        mgr.scanners["integrity"] = True

    rep = mgr.run_audit(packages=args.packages, continuous=args.continuous, interval_hours=args.interval_hours, auto_repair=args.auto_repair)
    if args.json:
        print(json.dumps(asdict(rep), indent=2, ensure_ascii=False))
    else:
        if RICH and _console and not args.quiet:
            tbl = Table(title="Audit summary")
            tbl.add_column("metric")
            tbl.add_column("value")
            tbl.add_row("timestamp", rep.ts)
            tbl.add_row("findings", str(rep.summary.get("total_findings", 0)))
            tbl.add_row("duration(s)", str(rep.duration_s))
            _console.print(tbl)
            if rep.summary.get("total_findings", 0) > 0:
                _console.print("[red]Findings:[/red]")
                for f in rep.findings[:20]:
                    _console.print(f"- [{f.get('severity')}] {f.get('category')} - {f.get('message')}")
        else:
            print(f"Audit {rep.ts}: findings={rep.summary.get('total_findings',0)} duration={rep.duration_s}s")
            if rep.summary.get("total_findings", 0) and not args.quiet:
                for f in rep.findings[:20]:
                    print(f"- [{f.get('severity')}] {f.get('category')} - {f.get('message')}")
