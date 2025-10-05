#!/usr/bin/env python3
# newpkg_deps.py
"""
newpkg_deps.py — dependency resolver & installer for newpkg (revised)

Key features:
 - auto-integrates with newpkg_api / get_db / get_logger / get_sandbox / get_hooks_manager
 - separates build/runtime/optional deps with TTL-specific caches
 - persistent phase recording to DB for each resolved/installed dep
 - offline mode (use local DB only)
 - parallel installation with retry/backoff and sandbox profile selection
 - auto-invalidate caches and optional auto-rebuild root package
 - JSON reports saved to /var/log/newpkg/deps/reports/
 - CLI with color (rich) and JSON output
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Optional components (best-effort)
try:
    from newpkg_api import get_api  # type: ignore
except Exception:
    get_api = None

try:
    from newpkg_db import get_db  # type: ignore
except Exception:
    get_db = None

try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_sandbox import get_sandbox  # type: ignore
except Exception:
    get_sandbox = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

# try rich for nicer CLI output
try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
    console = Console()
except Exception:
    RICH = False
    console = None

# fallback simple logger
import logging
log = logging.getLogger("newpkg.deps")
if not log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.deps: %(message)s"))
    log.addHandler(h)
log.setLevel(logging.INFO)

# Defaults and paths
REPORT_DIR = Path("/var/log/newpkg/deps/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_THREADS = 4
DEFAULT_INSTALL_RETRIES = 2
DEFAULT_RETRY_DELAY = 3  # seconds
DEFAULT_CACHE_TTLS = {"build": 30, "runtime": 3600, "optional": 300}
DEFAULT_SANDBOX_PROFILES = {"build": "full", "runtime": "light", "optional": "none"}

# Dataclasses
@dataclass
class DepSpec:
    name: str
    version: Optional[str] = None
    dep_type: str = "runtime"  # 'build' | 'runtime' | 'optional'
    meta: Dict[str, Any] = None

@dataclass
class DepInstallResult:
    spec: DepSpec
    ok: bool
    attempt: int
    duration: float
    error: Optional[str] = None
    installed_by: Optional[str] = None  # e.g. newpkg_core / newpkg_upgrade

# Utility helpers
def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

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

# Main manager
class DepsManager:
    def __init__(self, cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, sandbox: Optional[Any] = None, hooks: Optional[Any] = None):
        # integrate with api if available
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

        # use provided or try to fetch from api / imports
        self.cfg = cfg or (self.api.cfg if self.api and getattr(self.api, "cfg", None) else None)
        self.logger = logger or (self.api.logger if self.api and getattr(self.api, "logger", None) else (get_logger(self.cfg) if get_logger else None))
        self.db = db or (self.api.db if self.api and getattr(self.api, "db", None) else (get_db() if get_db else None))
        self.sandbox = sandbox or (self.api.sandbox if self.api and getattr(self.api, "sandbox", None) else (get_sandbox(self.cfg) if get_sandbox else None))
        self.hooks = hooks or (self.api.hooks if self.api and getattr(self.api, "hooks", None) else (get_hooks_manager(self.cfg) if get_hooks_manager else None))
        # register in api
        try:
            if self.api:
                self.api.deps = self
        except Exception:
            pass

        # configuration defaults and overrides
        # threads
        self.threads = DEFAULT_THREADS
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.threads = int(self.cfg.get("deps.threads") or self.cfg.get("general.threads") or self.threads)
        except Exception:
            pass

        # retries and delays
        self.install_retries = DEFAULT_INSTALL_RETRIES
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.install_retries = int(self.cfg.get("deps.install_retries") or self.install_retries)
        except Exception:
            pass
        self.retry_delay = DEFAULT_RETRY_DELAY
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.retry_delay = int(self.cfg.get("deps.retry_delay") or self.retry_delay)
        except Exception:
            pass

        # cache TTLS per type
        self.cache_ttls = DEFAULT_CACHE_TTLS.copy()
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                for k in ("build", "runtime", "optional"):
                    v = self.cfg.get(f"deps.cache_ttl.{k}")
                    if v is not None:
                        self.cache_ttls[k] = int(v)
        except Exception:
            pass

        # offline mode
        self.offline = False
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.offline = bool(self.cfg.get("deps.offline", False))
        except Exception:
            pass

        # auto rebuild root after installs
        self.auto_rebuild_root = False
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.auto_rebuild_root = bool(self.cfg.get("deps.auto_rebuild_root", False))
        except Exception:
            pass

        # sandbox profiles mapping
        self.sandbox_profiles = DEFAULT_SANDBOX_PROFILES.copy()
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                for typ in ("build", "runtime", "optional"):
                    v = self.cfg.get(f"deps.sandbox_profile.{typ}")
                    if v:
                        self.sandbox_profiles[typ] = v
        except Exception:
            pass

        # internal caches: { (pkg, type) : (timestamp, resolved_set) }
        self._cache_lock = threading.RLock()
        self._resolved_cache: Dict[Tuple[str, str], Tuple[float, Set[Tuple[str, Optional[str]]]]] = {}

        # ensure report dir
        try:
            REPORT_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    # ---------------- cache helpers ----------------
    def _cache_key(self, package: str, dep_type: str) -> Tuple[str, str]:
        return (package, dep_type)

    def _is_cache_valid(self, package: str, dep_type: str) -> bool:
        key = self._cache_key(package, dep_type)
        with self._cache_lock:
            v = self._resolved_cache.get(key)
            if not v:
                return False
            ts, _ = v
        ttl = self.cache_ttls.get(dep_type, self.cache_ttls.get("runtime", 300))
        return (time.time() - ts) < ttl

    def _store_cache(self, package: str, dep_type: str, resolved: Set[Tuple[str, Optional[str]]]):
        key = self._cache_key(package, dep_type)
        with self._cache_lock:
            self._resolved_cache[key] = (time.time(), resolved)

    def _invalidate_cache_for(self, package: str):
        # invalidate caches for package and for dependents (best-effort)
        with self._cache_lock:
            to_delete = [k for k in self._resolved_cache if k[0] == package]
            for k in to_delete:
                del self._resolved_cache[k]

    def _invalidate_related(self, root_package: str):
        # conservative invalidation: all caches referencing root_package in names
        with self._cache_lock:
            keys = list(self._resolved_cache.keys())
            for k in keys:
                pkgname = k[0]
                if pkgname == root_package or root_package in pkgname:
                    try:
                        del self._resolved_cache[k]
                    except Exception:
                        pass

    # ---------------- resolver (stub / pluggable) ----------------
    def resolve_dependencies(self, package: str, dep_type: str = "runtime") -> Set[Tuple[str, Optional[str]]]:
        """
        Resolve dependencies for a package. This method is pluggable/overridable by callers.
        Returns set of tuples (dep_name, version_or_none).
        - If offline mode is enabled, tries to derive from DB if possible; otherwise returns empty set.
        - Caches results with TTL per dep_type.
        """
        # check cache
        if self._is_cache_valid(package, dep_type):
            key = self._cache_key(package, dep_type)
            with self._cache_lock:
                return set(self._resolved_cache[key][1])

        resolved: Set[Tuple[str, Optional[str]]] = set()

        if self.offline:
            # best-effort: read known deps from DB (if schema supports it). We fallback to empty.
            try:
                if self.db:
                    rows = self.db.raw_query("SELECT dep_name, dep_type FROM deps WHERE dep_type = ? AND dep_name IS NOT NULL;", (dep_type,))
                    for r in rows:
                        # db.raw_query returns sqlite3.Row-like objects; adapt defensively
                        name = r[0] if isinstance(r, (list, tuple)) else r.get("dep_name")
                        resolved.add((name, None))
            except Exception:
                pass
            self._store_cache(package, dep_type, resolved)
            return resolved

        # default behavior: naive heuristic resolver — this is the place to plug in TOML/metafile parsing
        # For robustness, we'll look for a local metafile under /etc/newpkg/metafiles/<package>.json or similar
        try:
            # search standard metafile locations if present
            candidate_paths = [
                Path(f"/var/lib/newpkg/metafiles/{package}.json"),
                Path(f"/etc/newpkg/metafiles/{package}.json"),
                Path(f"{package}.deps.json")
            ]
            for p in candidate_paths:
                if p.exists():
                    txt = p.read_text(encoding="utf-8")
                    data = json.loads(txt)
                    # data expected: {"build": [...], "runtime":[...], "optional":[...]}
                    keys = []
                    if dep_type in data:
                        keys = data.get(dep_type, [])
                    else:
                        # fallback: data may be flat list
                        keys = data if isinstance(data, list) else []
                    for ent in keys:
                        if isinstance(ent, str):
                            resolved.add((ent, None))
                        elif isinstance(ent, dict):
                            resolved.add((ent.get("name"), ent.get("version")))
                    break
        except Exception:
            pass

        # As fallback use an empty set (caller will behave accordingly)
        self._store_cache(package, dep_type, resolved)

        # record each resolved child in DB for audit
        try:
            if self.db:
                for name, ver in resolved:
                    try:
                        self.db.record_phase(package, "deps.resolve.child", "ok", meta={"child": name, "version": ver, "type": dep_type})
                    except Exception:
                        pass
        except Exception:
            pass

        return resolved

    # ---------------- installation backing (pluggable) ----------------
    def _determine_install_command(self, dep_name: str, dep_version: Optional[str] = None) -> List[str]:
        """
        Determine the system command to install a dependency.
        This is intentionally simple and should be replaced by a distro-specific backend.
        The default behavior attempts to use `newpkg` packaging (newpkg install <pkg>) if available,
        otherwise returns a placeholder that will fail.
        """
        # prefer newpkg CLI if present
        newpkg_bin = shutil.which("newpkg")
        if newpkg_bin:
            cmd = [newpkg_bin, "--install", dep_name]
            if dep_version:
                cmd += [f"={dep_version}"]
            return cmd
        # fallback to apt/dnf/pacman? Not assumed. Return a failing echo to let caller handle.
        return ["sh", "-c", f"echo 'no installer configured for {dep_name}' && exit 2"]

    def _install_one(self, spec: DepSpec, sandbox_profile: Optional[str] = None, retries: Optional[int] = None, timeout: Optional[int] = None) -> DepInstallResult:
        """
        Attempt to install a single dependency, honoring sandbox profile and retries.
        Returns DepInstallResult.
        """
        start = time.time()
        retries = self.install_retries if retries is None else retries
        attempt = 0
        last_err = None
        ok = False

        # choose sandbox profile
        profile = sandbox_profile or self.sandbox_profiles.get(spec.dep_type, "none")
        timeout_val = timeout

        # get install command
        cmd = self._determine_install_command(spec.name, spec.version)

        while attempt <= retries:
            attempt += 1
            try:
                if self.logger:
                    self.logger.info("deps.install.attempt", f"installing {spec.name} (attempt {attempt})", meta={"pkg": spec.name, "type": spec.dep_type, "cmd": cmd, "profile": profile})
                # ideally run inside sandbox if available and profile != 'none'
                if profile != "none" and self.sandbox:
                    res = self.sandbox.run_in_sandbox(cmd, cwd=None, env=None, timeout_hard=timeout_val, use_fakeroot=(profile in ("full",)), overlay=(profile == "full"))
                    rc = res.rc
                    out = getattr(res, "stdout", "") or ""
                    err = getattr(res, "stderr", "") or ""
                else:
                    # direct subprocess
                    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_val)
                    rc = proc.returncode
                    out = proc.stdout.decode("utf-8", errors="ignore")
                    err = proc.stderr.decode("utf-8", errors="ignore")
                if rc == 0:
                    ok = True
                    # record DB & logger
                    if self.db:
                        try:
                            self.db.record_phase(spec.name, "deps.install.child", "ok", meta={"root": None, "pkg": spec.name, "attempt": attempt})
                        except Exception:
                            pass
                    if self.logger:
                        self.logger.info("deps.install.ok", f"{spec.name} installed", meta={"pkg": spec.name, "attempt": attempt, "duration": round(time.time() - start, 2)})
                    return DepInstallResult(spec=spec, ok=True, attempt=attempt, duration=time.time() - start)
                else:
                    last_err = f"rc={rc} out={out} err={err}"
                    if self.logger:
                        self.logger.warning("deps.install.failed", f"install failed for {spec.name}", meta={"pkg": spec.name, "rc": rc, "attempt": attempt, "stderr": err})
                    # on failure, record in DB
                    if self.db:
                        try:
                            self.db.record_phase(spec.name, "deps.install.child", "fail", meta={"pkg": spec.name, "rc": rc, "attempt": attempt, "stderr": err})
                        except Exception:
                            pass
            except subprocess.TimeoutExpired as e:
                last_err = f"timeout: {e}"
                if self.logger:
                    self.logger.warning("deps.install.timeout", f"timeout installing {spec.name}", meta={"pkg": spec.name, "attempt": attempt})
            except Exception as e:
                last_err = str(e)
                if self.logger:
                    self.logger.error("deps.install.exception", f"exception installing {spec.name}", meta={"pkg": spec.name, "error": last_err})
            # retry logic
            if attempt <= retries:
                time.sleep(self.retry_delay * attempt)
                continue
            break

        # final failure
        return DepInstallResult(spec=spec, ok=False, attempt=attempt, duration=time.time() - start, error=last_err)

    # ---------------- top-level install orchestration ----------------
    def install_missing(self, root_package: str, dep_types: Optional[List[str]] = None, parallel: Optional[int] = None, retries: Optional[int] = None, timeout: Optional[int] = None, sandbox_override: Optional[str] = None, offline: Optional[bool] = None, auto_rebuild: Optional[bool] = None, json_report: bool = False) -> Dict[str, Any]:
        """
        Resolve and install missing dependencies for a given root package.
        - dep_types: list of dep types to handle (default: ['build','runtime'])
        - parallel: number of worker threads
        - retries: per-package retry count (overrides manager)
        - sandbox_override: force a sandbox profile for all installs
        - offline: override manager.offline
        - auto_rebuild: override manager.auto_rebuild_root
        Returns a report dict.
        """
        t0 = time.time()
        parallel = parallel or self.threads
        retries = self.install_retries if retries is None else retries
        offline = self.offline if offline is None else offline
        auto_rebuild = self.auto_rebuild_root if auto_rebuild is None else auto_rebuild
        dep_types = dep_types or ["build", "runtime"]

        # top-level bookkeeping
        report = {
            "root": root_package,
            "started_at": now_iso(),
            "dep_types": dep_types,
            "threads": parallel,
            "results": [],
            "errors": [],
        }

        # resolve all deps for each type
        all_to_install: List[DepSpec] = []
        resolved_map = {}
        for t in dep_types:
            children = self.resolve_dependencies(root_package, dep_type=t)
            resolved_map[t] = children
            for name, ver in children:
                all_to_install.append(DepSpec(name=name, version=ver, dep_type=t, meta={"resolved_from": root_package}))

        # filter out already installed packages using DB (best-effort)
        to_install = []
        for spec in all_to_install:
            installed = False
            try:
                if self.db:
                    # check packages table for package presence
                    rows = self.db.raw_query("SELECT 1 FROM packages WHERE name = ? LIMIT 1;", (spec.name,))
                    if rows:
                        installed = True
            except Exception:
                installed = False
            if not installed:
                to_install.append(spec)

        report["planned"] = len(all_to_install)
        report["to_install"] = len(to_install)

        # install in parallel with retries
        results: List[DepInstallResult] = []
        if to_install:
            if parallel <= 1:
                # sequential
                for s in to_install:
                    profile = sandbox_override or self.sandbox_profiles.get(s.dep_type, "none")
                    res = self._install_one(s, sandbox_profile=profile, retries=retries, timeout=timeout)
                    results.append(res)
            else:
                # parallel threading
                max_workers = min(parallel, max(1, len(to_install)))
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futs = {ex.submit(self._install_one, s, sandbox_override or self.sandbox_profiles.get(s.dep_type, "none"), retries, timeout): s for s in to_install}
                    for fut in as_completed(futs):
                        s = futs[fut]
                        try:
                            res = fut.result()
                        except Exception as e:
                            res = DepInstallResult(spec=s, ok=False, attempt=0, duration=0.0, error=str(e))
                        results.append(res)

        # record results & build report
        success_count = 0
        fail_count = 0
        for r in results:
            report["results"].append({
                "name": r.spec.name,
                "version": r.spec.version,
                "type": r.spec.dep_type,
                "ok": r.ok,
                "attempt": r.attempt,
                "duration": r.duration,
                "error": r.error,
            })
            if r.ok:
                success_count += 1
            else:
                fail_count += 1
                report["errors"].append({"name": r.spec.name, "error": r.error})

        # finalize report
        report["completed_at"] = now_iso()
        report["duration_s"] = round(time.time() - t0, 3)
        report["summary"] = {"planned": report["planned"], "installed": success_count, "failed": fail_count}

        # save report file
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        report_name = f"deps-install-{root_package}-{timestamp}.json"
        out_path = REPORT_DIR / report_name
        try:
            safe_write_json(out_path, report)
            report_path = str(out_path)
        except Exception:
            report_path = None
        report["report_path"] = report_path

        # record top-level DB phase
        try:
            if self.db:
                status = "ok" if fail_count == 0 else "partial" if success_count > 0 else "fail"
                self.db.record_phase(root_package, "deps.install", status, meta={"planned": report["planned"], "installed": success_count, "failed": fail_count, "report": report_path})
        except Exception:
            pass

        # invalidate caches if installs succeeded
        if success_count > 0:
            try:
                self._invalidate_related(root_package)
            except Exception:
                pass

        # optional auto-rebuild
        if auto_rebuild and success_count > 0:
            try:
                # call upgrade.rebuild if available from api
                if self.api and getattr(self.api, "upgrade", None) and hasattr(self.api.upgrade, "rebuild"):
                    try:
                        self.api.upgrade.rebuild(root_package)
                        report.setdefault("auto_rebuild", {})["status"] = "ok"
                    except Exception as e:
                        report.setdefault("auto_rebuild", {})["status"] = "fail"
                        report.setdefault("auto_rebuild", {})["error"] = str(e)
                else:
                    # try to import upgrade module directly if available
                    from newpkg_upgrade import UpgradeManager  # type: ignore
                    try:
                        um = UpgradeManager(cfg=self.cfg, logger=self.logger, db=self.db)
                        um.rebuild(root_package)
                        report.setdefault("auto_rebuild", {})["status"] = "ok"
                    except Exception as e:
                        report.setdefault("auto_rebuild", {})["status"] = "fail"
                        report.setdefault("auto_rebuild", {})["error"] = str(e)
            except Exception as e:
                report.setdefault("auto_rebuild", {})["status"] = "fail"
                report.setdefault("auto_rebuild", {})["error"] = str(e)

        return report

    # ---------------- helpers / public API ----------------
    def resolve_and_report(self, package: str, dep_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Convenience: resolve deps for package and return structured dict.
        """
        dep_types = dep_types or ["build", "runtime", "optional"]
        out = {"package": package, "resolved": {}, "ts": now_iso()}
        for t in dep_types:
            s = list(self.resolve_dependencies(package, dep_type=t))
            out["resolved"][t] = [{"name": n, "version": v} for n, v in s]
        # persist summary
        try:
            p = REPORT_DIR / f"deps-resolve-{package}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
            safe_write_json(p, out)
        except Exception:
            pass
        return out

# module-level singleton
_default_deps: Optional[DepsManager] = None
_deps_lock = threading.RLock()

def get_deps_manager(cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, sandbox: Optional[Any] = None, hooks: Optional[Any] = None) -> DepsManager:
    global _default_deps
    with _deps_lock:
        if _default_deps is None:
            _default_deps = DepsManager(cfg=cfg, logger=logger, db=db, sandbox=sandbox, hooks=hooks)
        return _default_deps

# ---------------- CLI ----------------
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-deps", description="resolve & install dependencies (newpkg)")
    p.add_argument("package", help="root package name")
    p.add_argument("--types", nargs="+", choices=["build", "runtime", "optional"], default=["build", "runtime"], help="dependency types to process")
    p.add_argument("--threads", type=int, help="parallel install threads")
    p.add_argument("--retries", type=int, help="install retries per package")
    p.add_argument("--offline", action="store_true", help="force offline resolution/install (use DB only)")
    p.add_argument("--sandbox", choices=["full", "light", "none"], help="force sandbox profile for installs")
    p.add_argument("--no-auto-rebuild", dest="auto_rebuild", action="store_false", help="do not auto-rebuild root after install")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON report")
    args = p.parse_args()

    mgr = get_deps_manager()
    if args.threads:
        mgr.threads = args.threads
    if args.retries is not None:
        mgr.install_retries = args.retries
    if args.offline:
        mgr.offline = True
    if args.sandbox:
        # override global mapping for this run
        for k in mgr.sandbox_profiles:
            mgr.sandbox_profiles[k] = args.sandbox
    if args.auto_rebuild is False:
        mgr.auto_rebuild_root = False

    report = mgr.install_missing(args.package, dep_types=args.types, parallel=mgr.threads, retries=mgr.install_retries, sandbox_override=None, offline=mgr.offline, auto_rebuild=mgr.auto_rebuild_root)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        # human-friendly summary
        summary = report.get("summary", {})
        if RICH and console:
            table = Table(title=f"Deps install report for {args.package}")
            table.add_column("planned", justify="right")
            table.add_column("installed", justify="right")
            table.add_column("failed", justify="right")
            table.add_column("duration_s", justify="right")
            table.add_row(str(summary.get("planned", 0)), str(summary.get("installed", 0)), str(summary.get("failed", 0)), str(report.get("duration_s", 0)))
            console.print(table)
            if report.get("report_path"):
                console.print(f"[green]Report saved:[/green] {report.get('report_path')}")
            if report.get("errors"):
                console.print(f"[red]Errors:[/red] {len(report.get('errors'))}")
        else:
            print(f"Planned: {summary.get('planned',0)} Installed: {summary.get('installed',0)} Failed: {summary.get('failed',0)} Duration: {report.get('duration_s',0)}s")
            if report.get("report_path"):
                print("Report:", report.get("report_path"))
            if report.get("errors"):
                print("Errors:", report.get("errors"))
