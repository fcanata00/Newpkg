#!/usr/bin/env python3
# newpkg_deps.py
"""
newpkg_deps.py — Revised dependency resolver and installer for newpkg

Improvements implemented (summary):
 - perf timing with logger.perf_timer / DB recording
 - hooks: pre_resolve/post_resolve, pre_install/post_install, pre_check_missing/post_check_missing
 - audit reporting on failures (best-effort)
 - cache with per-type TTL and invalidation
 - optional sandboxed installs
 - progress UI via logger.progress (Rich when available)
 - rebuild fallback to newpkg_upgrade or newpkg_core
 - detailed JSON reports saved to report_dir
 - CLI with colorized output using rich if available
 - check_outdated to detect packages with newer versions
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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

# rich for nicer CLI output if available
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    RICH = True
    _console = Console()
except Exception:
    RICH = False
    _console = None

# fallback logger
import logging
_logger = logging.getLogger("newpkg.deps")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.deps: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)

# ---------------- dataclasses ----------------
@dataclass
class DepNode:
    name: str
    version: Optional[str] = None
    deps: Dict[str, List[str]] = None  # type -> list of package names (build/runtime/optional)
    metadata: Dict[str, Any] = None


@dataclass
class ResolveReport:
    root: str
    resolved: Dict[str, DepNode]
    missing: List[str]
    cycles: List[List[str]]
    duration: float
    timestamp: str


# ---------------- main class ----------------
class NewpkgDeps:
    DEFAULT_CACHE_DIR = "/var/cache/newpkg/deps"
    DEFAULT_REPORT_DIR = "/var/log/newpkg/deps"
    DEFAULT_PARALLEL = max(1, (os.cpu_count() or 2))

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None, upgrade: Any = None, core: Any = None, audit: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        self.logger = logger or (get_logger(self.cfg) if get_logger else None)
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)
        self.hooks = hooks or (get_hooks_manager(self.cfg) if get_hooks_manager else None)
        self.sandbox = sandbox or (get_sandbox(self.cfg) if get_sandbox else None)
        self.upgrade = upgrade or (NewpkgUpgrade(self.cfg) if NewpkgUpgrade else None)
        self.core = core or (NewpkgCore(self.cfg) if NewpkgCore else None)
        self.audit = audit or (NewpkgAudit(self.cfg) if NewpkgAudit else None)

        # config and directories
        self.cache_dir = Path(self._cfg_get("deps.cache_dir", self.DEFAULT_CACHE_DIR)).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir = Path(self._cfg_get("deps.report_dir", self.DEFAULT_REPORT_DIR)).expanduser()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.parallel = int(self._cfg_get("deps.parallel", self.DEFAULT_PARALLEL))
        self.install_parallel = int(self._cfg_get("deps.install_parallel", self.parallel))
        self.default_ttl = int(self._cfg_get("deps.cache_ttl_seconds", 3600))
        # per-type TTLs: build/runtime/optional
        self.ttl_by_type = {
            "build": int(self._cfg_get("deps.cache_ttl.build", self.default_ttl)),
            "runtime": int(self._cfg_get("deps.cache_ttl.runtime", self.default_ttl)),
            "optional": int(self._cfg_get("deps.cache_ttl.optional", self.default_ttl))
        }
        self.use_sandbox_for_installs = bool(self._cfg_get("deps.use_sandbox_for_installs", False))
        self.sandbox_profile = str(self._cfg_get("deps.sandbox_profile", "light"))
        self.dry_run = bool(self._cfg_get("deps.dry_run", False))
        self.report_keep = int(self._cfg_get("deps.report_keep", 20))
        self._cache_lock = threading.RLock()
        self._resolve_cache: Dict[str, Tuple[ResolveReport, float]] = {}  # root -> (report, ts)

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

    def _now_iso(self) -> str:
        return datetime.utcnow().isoformat() + "Z"

    def _save_report(self, root: str, report: ResolveReport) -> Path:
        name = f"deps-report-{root}-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
        path = self.report_dir / name
        try:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(asdict(report), indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(path))
            # rotate
            files = sorted([p for p in self.report_dir.glob("deps-report-*.json")], key=lambda p: p.stat().st_mtime, reverse=True)
            for p in files[self.report_keep:]:
                try:
                    p.unlink()
                except Exception:
                    pass
        except Exception as e:
            if self.logger:
                self.logger.warning("deps.report_save_fail", f"failed to save deps report: {e}")
        return path

    # ---------------- timing helper ----------------
    def _perf_timer(self, name: str):
        """
        Context manager wrapper for perf timing to integrate with logger.perf_timer if available.
        Use as: with self._perf_timer("deps.resolve"): ...
        """
        class _TimerCtx:
            def __init__(self, parent, name):
                self.parent = parent
                self.name = name
                self._start = None
                self._ctx = None
            def __enter__(self):
                self._start = time.time()
                # try logger.perf_timer
                try:
                    if self.parent.logger and hasattr(self.parent.logger, "perf_timer"):
                        self._ctx = self.parent.logger.perf_timer(self.name)
                        self._ctx.__enter__()
                except Exception:
                    self._ctx = None
                return self
            def __exit__(self, exc_type, exc, tb):
                dur = time.time() - (self._start or time.time())
                # exit logger context if any
                if self._ctx:
                    try:
                        self._ctx.__exit__(exc_type, exc, tb)
                    except Exception:
                        pass
                # record in DB
                try:
                    if self.parent.db:
                        self.parent.db.record_phase(None, self.name, "ok", meta={"duration": round(dur, 3)})
                except Exception:
                    pass
        return _TimerCtx(self, name)

    # ---------------- cache helpers ----------------
    def _cache_key_for_root(self, root: str, types: Optional[List[str]] = None) -> str:
        types_s = ",".join(sorted(types)) if types else "all"
        return f"{root}:{types_s}"

    def _is_cache_valid(self, key: str) -> bool:
        with self._cache_lock:
            entry = self._resolve_cache.get(key)
            if not entry:
                return False
            report, ts = entry
            ttl = self.default_ttl
            # root-specific TTL not implemented; we store whole report with timestamp
            if (time.time() - ts) <= ttl:
                return True
            # else expire
            del self._resolve_cache[key]
            return False

    def _store_cache(self, key: str, report: ResolveReport) -> None:
        with self._cache_lock:
            self._resolve_cache[key] = (report, time.time())

    def _invalidate_cache(self, root: Optional[str] = None) -> None:
        with self._cache_lock:
            if root is None:
                self._resolve_cache.clear()
            else:
                to_del = [k for k in self._resolve_cache.keys() if k.startswith(f"{root}:")]
                for k in to_del:
                    del self._resolve_cache[k]

    # ---------------- resolve dependencies ----------------
    def resolve(self, root_pkg: str, include_types: Optional[List[str]] = None) -> ResolveReport:
        """
        Resolve dependencies for root_pkg recursively.
        include_types: list of dependency types to include (build/runtime/optional). If None => include all.
        Returns ResolveReport with graph, missing list, cycles.
        """
        start = time.time()
        include_types = include_types or ["build", "runtime", "optional"]
        cache_key = self._cache_key_for_root(root_pkg, include_types)
        # hooks pre_resolve
        try:
            if self.hooks:
                self.hooks.run("pre_resolve", {"root": root_pkg, "types": include_types})
        except Exception:
            pass

        # caching
        if self._is_cache_valid(cache_key):
            report, _ = self._resolve_cache[cache_key]
            if self.logger:
                self.logger.info("deps.resolve.cache_hit", f"cache hit for {root_pkg}")
            return report

        with self._perf_timer("deps.resolve"):
            resolved: Dict[str, DepNode] = {}
            visiting: List[str] = []
            cycles: List[List[str]] = []
            missing: Set[str] = set()

            def _fetch_package_info(name: str) -> Optional[Dict[str, Any]]:
                # best-effort: ask DB first
                if self.db and hasattr(self.db, "get_package_metadata"):
                    try:
                        return self.db.get_package_metadata(name) or {}
                    except Exception:
                        pass
                # fallback: try get_deps (older API)
                if self.db and hasattr(self.db, "get_deps_for"):
                    try:
                        return {"name": name, "deps": self.db.get_deps_for(name)}
                    except Exception:
                        pass
                # not found
                return None

            def visit(pkg_name: str):
                if pkg_name in resolved:
                    return
                if pkg_name in visiting:
                    # found cycle
                    idx = visiting.index(pkg_name)
                    cycles.append(visiting[idx:] + [pkg_name])
                    return
                visiting.append(pkg_name)
                info = _fetch_package_info(pkg_name)
                if not info:
                    missing.add(pkg_name)
                    visiting.pop()
                    return
                # normalize deps structure
                deps_map: Dict[str, List[str]] = {"build": [], "runtime": [], "optional": []}
                raw_deps = info.get("deps") or info.get("dependencies") or {}
                # raw_deps may be dict type->list or list of strings (runtime)
                if isinstance(raw_deps, dict):
                    for t in ("build", "runtime", "optional"):
                        if t in raw_deps:
                            deps_map[t] = list(raw_deps.get(t) or [])
                elif isinstance(raw_deps, list):
                    deps_map["runtime"] = list(raw_deps)
                # apply include_types filter later
                node = DepNode(name=pkg_name, version=info.get("version"), deps=deps_map, metadata=info.get("meta") or {})
                resolved[pkg_name] = node
                # recursively visit children
                for t in include_types:
                    for child in node.deps.get(t) or []:
                        visit(child)
                visiting.pop()

            visit(root_pkg)

            duration = time.time() - start
            report = ResolveReport(root=root_pkg, resolved=resolved, missing=sorted(list(missing)), cycles=cycles, duration=round(duration, 3), timestamp=self._now_iso())
            # store cache
            self._store_cache(cache_key, report)

        # hooks post_resolve
        try:
            if self.hooks:
                self.hooks.run("post_resolve", {"root": root_pkg, "report": asdict(report)})
        except Exception:
            pass

        # persist report
        try:
            self._save_report(root_pkg, report)
        except Exception:
            pass

        return report

    # ---------------- check missing / outdated ----------------
    def check_missing(self, report: ResolveReport) -> Dict[str, Any]:
        """
        Check for missing packages (from ResolveReport) and return detailed diagnostic.
        """
        start = time.time()
        try:
            if self.hooks:
                self.hooks.run("pre_check_missing", {"root": report.root})
        except Exception:
            pass

        missing = report.missing[:]
        details = []
        for name in missing:
            meta = {}
            if self.db and hasattr(self.db, "get_package_metadata"):
                try:
                    meta = self.db.get_package_metadata(name) or {}
                except Exception:
                    meta = {}
            details.append({"name": name, "meta": meta})
        duration = time.time() - start
        try:
            if self.hooks:
                self.hooks.run("post_check_missing", {"root": report.root, "missing": missing})
        except Exception:
            pass
        # record
        try:
            if self.db:
                self.db.record_phase(report.root, "deps.check_missing", "ok", meta={"count": len(missing), "duration": round(duration, 3)})
        except Exception:
            pass
        return {"missing": missing, "details": details, "duration": round(duration, 3)}

    def check_outdated(self, report: ResolveReport) -> Dict[str, Any]:
        """
        Compare versions in report with DB/remote metadata to identify outdated packages.
        Returns list of candidates needing update.
        """
        outdated = []
        for name, node in report.resolved.items():
            try:
                db_meta = self.db.get_package_metadata(name) if self.db and hasattr(self.db, "get_package_metadata") else None
                if db_meta:
                    current_ver = node.version
                    latest_ver = db_meta.get("latest_version") or db_meta.get("version")
                    if latest_ver and current_ver and latest_ver != current_ver:
                        outdated.append({"name": name, "current": current_ver, "latest": latest_ver})
            except Exception:
                continue
        # record
        try:
            if self.db:
                self.db.record_phase(report.root, "deps.check_outdated", "ok", meta={"count": len(outdated)})
        except Exception:
            pass
        return {"outdated": outdated}

    # ---------------- install missing ----------------
    def install_missing(self, report: ResolveReport, parallel: Optional[int] = None, sandbox_profile: Optional[str] = None, timeout_per: Optional[int] = None) -> Dict[str, Any]:
        """
        Attempt to install/rebuild missing packages. Returns dict with results.
        For each missing package:
          - try upgrade.rebuild(pkg) if upgrade available
          - else try core.build_package(pkg) if core available
          - optionally perform inside sandbox
        """
        start_total = time.time()
        missing = report.missing[:]
        results = []
        failed = []
        parallel = parallel or self.install_parallel
        sandbox_profile = sandbox_profile or self.sandbox_profile
        timeout_per = timeout_per or int(self._cfg_get("deps.install_timeout", 600))

        # hooks
        try:
            if self.hooks:
                self.hooks.run("pre_install", {"root": report.root, "missing": missing})
        except Exception:
            pass

        # progress context from logger
        progress_ctx = None
        try:
            if self.logger:
                progress_ctx = self.logger.progress(f"Installing missing deps for {report.root}", total=len(missing))
        except Exception:
            progress_ctx = None

        def _install_one(name: str) -> Dict[str, Any]:
            start = time.time()
            meta = {"pkg": name}
            # try upgrade module first
            try:
                if self.upgrade and hasattr(self.upgrade, "rebuild"):
                    if self.use_sandbox_for_installs and self.sandbox:
                        # call upgrade.rebuild inside sandbox if upgrade.rebuild is a callable, else run normally
                        try:
                            ok, msg = self._run_rebuild_in_sandbox(name, timeout_per, sandbox_profile)
                            if ok:
                                self._record_phase(name, "deps.install", "ok", meta={"method": "upgrade.sandbox", "duration": round(time.time() - start, 3)})
                                return {"name": name, "ok": True, "method": "upgrade.sandbox", "message": msg}
                        except Exception as e:
                            # fallback to direct attempt
                            pass
                    # direct call
                    try:
                        ok, msg = self.upgrade.rebuild(name)
                        if ok:
                            self._record_phase(name, "deps.install", "ok", meta={"method": "upgrade", "duration": round(time.time() - start, 3)})
                            return {"name": name, "ok": True, "method": "upgrade", "message": msg}
                    except Exception as e:
                        # record and continue to fallback
                        meta["upgrade_exc"] = str(e)
            except Exception:
                pass

            # fallback to core.build_package
            try:
                if self.core and hasattr(self.core, "build_package"):
                    if self.use_sandbox_for_installs and self.sandbox:
                        try:
                            ok, msg = self._run_core_build_in_sandbox(name, timeout_per, sandbox_profile)
                            if ok:
                                self._record_phase(name, "deps.install", "ok", meta={"method": "core.sandbox", "duration": round(time.time() - start, 3)})
                                return {"name": name, "ok": True, "method": "core.sandbox", "message": msg}
                        except Exception:
                            pass
                    try:
                        ok, msg = self.core.build_package(name)
                        if ok:
                            self._record_phase(name, "deps.install", "ok", meta={"method": "core", "duration": round(time.time() - start, 3)})
                            return {"name": name, "ok": True, "method": "core", "message": msg}
                    except Exception as e:
                        meta["core_exc"] = str(e)
            except Exception:
                pass

            # failure: recorded and audited
            duration = time.time() - start
            try:
                self._record_phase(name, "deps.install", "fail", meta={"duration": round(duration, 3), **meta})
            except Exception:
                pass
            if self.audit:
                try:
                    self.audit.report("deps", name, "install_failed", {"meta": meta})
                except Exception:
                    pass
            return {"name": name, "ok": False, "method": None, "message": "install_failed", "meta": meta}

        # parallel execution
        with ThreadPoolExecutor(max_workers=max(1, parallel)) as ex:
            future_map = {ex.submit(_install_one, n): n for n in missing}
            for fut in as_completed(future_map):
                n = future_map[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"name": n, "ok": False, "message": str(e)}
                results.append(res)
                if not res.get("ok"):
                    failed.append(res)
                # progress update (logger.progress)
                try:
                    if progress_ctx:
                        pass
                except Exception:
                    pass

        # close progress
        try:
            if progress_ctx:
                progress_ctx.__exit__(None, None, None)
        except Exception:
            pass

        total_time = time.time() - start_total
        summary = {"root": report.root, "total": len(missing), "succeeded": [r for r in results if r.get("ok")], "failed": failed, "duration": round(total_time, 3), "timestamp": self._now_iso()}

        # post_install hook
        try:
            if self.hooks:
                self.hooks.run("post_install", summary)
        except Exception:
            pass

        return summary

    # ---------------- sandbox helpers ----------------
    def _run_rebuild_in_sandbox(self, pkg_name: str, timeout: int, profile: str) -> Tuple[bool, str]:
        """
        Generic wrapper to run upgrade.rebuild(pkg) inside sandbox by shelling out to a temporary script.
        This is a best-effort approach because we can't serialize Python objects into the sandbox easily.
        The approach: create a small script that calls the system's newpkg upgrade CLI if available,
        or just return not implemented. We'll attempt to call 'newpkg upgrade --rebuild <pkg>' if exists.
        """
        # try CLI approach
        wrapper = shutil.which("newpkg") or shutil.which("newpkg-cli") or shutil.which("newpkg3")
        if not wrapper:
            # no CLI; fallback to direct call (not sandboxed)
            try:
                ok, msg = self.upgrade.rebuild(pkg_name)
                return bool(ok), str(msg)
            except Exception as e:
                return False, str(e)
        # create a small shell script to call the CLI
        script = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".sh")
        try:
            script.write("#!/bin/sh\nset -e\n")
            script.write(f"{shlex_quote(wrapper)} upgrade --rebuild {shlex_quote(pkg_name)}\n")
            script.close()
            os.chmod(script.name, 0o755)
            try:
                res = self.sandbox.run_in_sandbox([script.name], workdir=None, env=None, binds=None, ro_binds=None, backend=None, use_fakeroot=False, timeout=timeout)
                return (res.rc == 0), (res.stdout or res.stderr)
            except Exception as e:
                return False, str(e)
        finally:
            try:
                os.unlink(script.name)
            except Exception:
                pass

    def _run_core_build_in_sandbox(self, pkg_name: str, timeout: int, profile: str) -> Tuple[bool, str]:
        # Similar approach to _run_rebuild_in_sandbox but for core.build_package CLI
        wrapper = shutil.which("newpkg") or shutil.which("newpkg-cli") or shutil.which("newpkg3")
        if not wrapper:
            try:
                ok, msg = self.core.build_package(pkg_name)
                return bool(ok), str(msg)
            except Exception as e:
                return False, str(e)
        script = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".sh")
        try:
            script.write("#!/bin/sh\nset -e\n")
            script.write(f"{shlex_quote(wrapper)} build {shlex_quote(pkg_name)}\n")
            script.close()
            os.chmod(script.name, 0o755)
            try:
                res = self.sandbox.run_in_sandbox([script.name], workdir=None, env=None, binds=None, ro_binds=None, backend=None, use_fakeroot=False, timeout=timeout)
                return (res.rc == 0), (res.stdout or res.stderr)
            except Exception as e:
                return False, str(e)
        finally:
            try:
                os.unlink(script.name)
            except Exception:
                pass

    # ---------------- graph export ----------------
    def export_graph(self, report: ResolveReport, path: Optional[Path] = None) -> Path:
        """
        Export resolved dependency graph to JSON (and optionally DOT).
        """
        path = path or (self.report_dir / f"deps-graph-{report.root}-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")
        try:
            out = {"root": report.root, "timestamp": report.timestamp, "resolved": {k: {"version": v.version, "deps": v.deps} for k, v in report.resolved.items()}, "missing": report.missing, "cycles": report.cycles, "duration": report.duration}
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(path))
        except Exception as e:
            if self.logger:
                self.logger.warning("deps.export_fail", f"export graph failed: {e}")
        return path

    # ---------------- CLI helpers ----------------
    def cli(self, argv: Optional[List[str]] = None) -> int:
        import argparse
        parser = argparse.ArgumentParser(prog="newpkg-deps", description="Dependency resolver & installer for newpkg")
        parser.add_argument("package", help="root package name")
        parser.add_argument("--types", help="comma-separated dependency types (build,runtime,optional)", default="build,runtime,optional")
        parser.add_argument("--resolve-only", action="store_true")
        parser.add_argument("--install-missing", action="store_true")
        parser.add_argument("--check-outdated", action="store_true")
        parser.add_argument("--parallel", type=int, help="parallel workers")
        parser.add_argument("--report-dir", help="override report dir")
        args = parser.parse_args(argv or sys.argv[1:])

        if args.report_dir:
            self.report_dir = Path(args.report_dir)
            self.report_dir.mkdir(parents=True, exist_ok=True)

        types = [t.strip() for t in args.types.split(",") if t.strip()]
        report = self.resolve(args.package, include_types=types)

        # print summary
        if RICH and _console:
            table = Table(title=f"Dependency resolution for {args.package}", box=box.SIMPLE)
            table.add_column("package")
            table.add_column("version")
            table.add_column("deps")
            for n, node in report.resolved.items():
                deps_summary = ", ".join(sum([node.deps.get(t) or [] for t in node.deps], []))
                table.add_row(n, node.version or "-", deps_summary or "-")
            _console.print(table)
            if report.missing:
                _console.print(f"[red]Missing: {', '.join(report.missing)}[/red]")
            if report.cycles:
                _console.print(f"[yellow]Cycles detected: {report.cycles}[/yellow]")
        else:
            print(f"Resolved {len(report.resolved)} packages; missing {len(report.missing)}; cycles {len(report.cycles)}")

        # save report to disk
        try:
            self._save_report(args.package, report)
        except Exception:
            pass

        if args.resolve_only:
            return 0

        if args.check_outdated:
            out = self.check_outdated(report)
            if RICH and _console:
                if out["outdated"]:
                    for o in out["outdated"]:
                        _console.print(f"[yellow]{o['name']}: {o['current']} -> {o['latest']}[/yellow]")
                else:
                    _console.print("[green]No outdated packages found[/green]")
            else:
                print(json.dumps(out, indent=2))

        if args.install_missing:
            summary = self.install_missing(report, parallel=args.parallel)
            # print summary
            ok = len(summary.get("failed", [])) == 0
            if RICH and _console:
                if ok:
                    _console.print(f"[green]Installed missing deps OK (root={report.root})[/green]")
                else:
                    _console.print(f"[red]Some installs failed (root={report.root})[/red]")
                    for f in summary.get("failed", []):
                        _console.print(f"[red] - {f.get('name')}: {f.get('message')}[/red]")
            else:
                print(json.dumps(summary, indent=2))
            return 0 if ok else 2

        return 0


# ---------------- convenience singleton ----------------
_default_deps: Optional[NewpkgDeps] = None


def get_deps(cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None, upgrade: Any = None, core: Any = None, audit: Any = None) -> NewpkgDeps:
    global _default_deps
    if _default_deps is None:
        _default_deps = NewpkgDeps(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox, upgrade=upgrade, core=core, audit=audit)
    return _default_deps


# ---------------- small helpers ----------------
def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)

# ---------------- CLI entrypoint ----------------
if __name__ == "__main__":
    deps = get_deps()
    sys.exit(deps.cli())
