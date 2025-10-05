#!/usr/bin/env python3
# newpkg_deps.py
"""
newpkg_deps.py — resolver e gerenciar dependências para newpkg

Principais funcionalidades:
 - resolve dependências (build/runtime/optional separados)
 - detecta dependências faltantes
 - exporta grafo (JSON e opcional DOT text)
 - encontra reverse-deps
 - tenta "install_missing" via newpkg_core / newpkg_upgrade quando disponível (dry-run padrão)
 - cache com TTL e relatório em /var/log/newpkg/deps/
 - integra com newpkg_config, newpkg_logger, newpkg_db, newpkg_sandbox
 - paralelo controlado por config (dep.parallel_jobs)
"""

from __future__ import annotations

import json
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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

# fallback logger
import logging
_logger = logging.getLogger("newpkg.deps")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.deps: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


@dataclass
class ResolveResult:
    package: str
    dep_type: str
    resolved: Dict[str, List[str]]  # {'build': [...], 'runtime': [...], 'optional': [...]}
    cycles: List[List[str]]
    timestamp: float

    def to_dict(self):
        return asdict(self)


class NewpkgDeps:
    DEFAULT_REPORT_DIR = "/var/log/newpkg/deps"
    CACHE_FILE = ".newpkg/deps_cache.json"

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)

        # logger
        if logger:
            self.logger = logger
        else:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, db) if NewpkgLogger and self.cfg else None
            except Exception:
                self.logger = None

        # db
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)

        # sandbox (for optional operations)
        try:
            self.sandbox = NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgSandbox and self.cfg else None
        except Exception:
            self.sandbox = None

        # config-driven flags
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))

        # cache & reports
        self.cache_file = Path(self._cfg_get("deps.cache_file", self.CACHE_FILE))
        if self.cache_file.parent:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = int(self._cfg_get("deps.cache_ttl_seconds", 3600))  # default 1h

        # parallel jobs
        cpu = os.cpu_count() or 1
        default_jobs = int(self._cfg_get("deps.parallel_jobs", min(4, cpu)))
        self.parallel_jobs = max(1, min(default_jobs, cpu))

        # reports dir
        self.report_dir = Path(self._cfg_get("deps.report_dir", self.DEFAULT_REPORT_DIR))
        self.report_dir.mkdir(parents=True, exist_ok=True)

        # internal
        self._log = self._make_logger()
        # try to obtain perf_timer decorator if available
        self._perf_timer = getattr(self.logger, "perf_timer", None) if self.logger else None

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

    # ----------------- caching helpers -----------------
    def _cache_load(self) -> Dict[str, Any]:
        if not self.cache_file.exists():
            return {}
        try:
            text = self.cache_file.read_text(encoding="utf-8")
            data = json.loads(text)
            # expire old entries
            now = time.time()
            out = {}
            for k, v in data.items():
                ts = v.get("ts", 0)
                if (now - ts) <= self.cache_ttl:
                    out[k] = v
            return out
        except Exception:
            return {}

    def _cache_save(self, data: Dict[str, Any]):
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    # ----------------- resolver -----------------
    def resolve(self, package: str, dep_type: str = "all", use_cache: bool = True) -> ResolveResult:
        """
        Resolve dependencies for a package.
        dep_type: 'build', 'runtime', 'optional' or 'all'
        Returns ResolveResult with lists of package names and cycles detected.
        """
        start = time.time()
        cache = self._cache_load() if use_cache else {}
        cache_key = f"{package}::{dep_type}"
        if use_cache and cache_key in cache:
            entry = cache[cache_key]
            self._log("info", "deps.resolve.cache", f"Using cache for {package}", package=package, dep_type=dep_type)
            # register phase
            try:
                if self.db and hasattr(self.db, "record_phase"):
                    self.db.record_phase(package=package, phase="deps.resolve", status="ok", meta={"from_cache": True})
            except Exception:
                pass
            return ResolveResult(package=package, dep_type=dep_type, resolved=entry.get("resolved", {}), cycles=entry.get("cycles", []), timestamp=entry.get("ts", time.time()))

        # use DB to walk dependencies
        if not self.db:
            self._log("warning", "deps.resolve.no_db", "No DB available; cannot resolve dependencies accurately", package=package)
            return ResolveResult(package=package, dep_type=dep_type, resolved={"build": [], "runtime": [], "optional": []}, cycles=[], timestamp=time.time())

        resolved = {"build": [], "runtime": [], "optional": []}
        visited: Set[str] = set()
        stack: List[str] = []
        cycles: List[List[str]] = []

        def walk(pkg: str, dtype: str):
            if pkg in stack:
                # cycle detected
                idx = stack.index(pkg)
                cycles.append(stack[idx:] + [pkg])
                return
            if pkg in visited:
                return
            visited.add(pkg)
            stack.append(pkg)
            # fetch deps from DB
            try:
                deps = self.db.get_deps(pkg) or []
            except Exception:
                deps = []
            for d in deps:
                dep_name = d.get("dep")
                dep_t = d.get("type", "runtime")
                # normalize types
                if dep_t not in ("build", "runtime", "optional"):
                    dep_t = "runtime"
                # respect requested dep_type
                if dep_type == "all" or dep_type == dep_t or (dep_type == "build" and dep_t == "build") or (dep_type == "runtime" and dep_t == "runtime"):
                    if dep_t not in resolved:
                        resolved[dep_t] = []
                    if dep_name not in resolved[dep_t]:
                        resolved[dep_t].append(dep_name)
                # always continue walking to collect deeper deps
                walk(dep_name, dep_t)
            stack.pop()

        walk(package, dep_type)
        # dedupe and flatten
        for k in resolved:
            # preserve order but ensure unique
            seen = set()
            ordered = []
            for x in resolved[k]:
                if x not in seen:
                    seen.add(x)
                    ordered.append(x)
            resolved[k] = ordered

        res = ResolveResult(package=package, dep_type=dep_type, resolved=resolved, cycles=cycles, timestamp=time.time())

        # cache result
        try:
            cache[cache_key] = {"resolved": resolved, "cycles": cycles, "ts": res.timestamp}
            self._cache_save(cache)
        except Exception:
            pass

        # record phase and duration
        duration = time.time() - start
        self._log("info", "deps.resolve.ok", f"Resolved deps for {package} in {duration:.2f}s", package=package, dep_type=dep_type, cycles=len(cycles))
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="deps.resolve", status="ok", meta={"duration": duration, "cycles": len(cycles)})
        except Exception:
            pass

        return res

    # ----------------- check missing -----------------
    def check_missing(self, package: str, dep_type: str = "all") -> Dict[str, Any]:
        """
        Check which resolved dependencies are missing (not present in DB packages).
        Returns dict {missing: [...], present: [...]}.
        """
        start = time.time()
        res = self.resolve(package, dep_type=dep_type, use_cache=True)
        missing = []
        present = []
        # list available packages
        try:
            db_pkgs = {p["name"] for p in (self.db.list_packages() if self.db else [])}
        except Exception:
            db_pkgs = set()

        for t, lst in res.resolved.items():
            for dep in lst:
                if dep not in db_pkgs:
                    missing.append({"name": dep, "type": t})
                else:
                    present.append({"name": dep, "type": t})

        duration = time.time() - start
        self._log("info", "deps.missing", f"Missing check for {package}: {len(missing)} missing", package=package, missing=len(missing), duration=duration)
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="deps.check_missing", status="ok", meta={"missing": len(missing)})
        except Exception:
            pass

        return {"package": package, "missing": missing, "present": present, "duration": duration}

    # ----------------- reverse deps -----------------
    def reverse(self, package: str) -> List[str]:
        """
        Return list of packages that depend on the given package (reverse deps).
        """
        out = []
        if not self.db:
            return out
        try:
            pkgs = self.db.list_packages()
            for p in pkgs:
                name = p.get("name")
                deps = self.db.get_deps(name) or []
                for d in deps:
                    if d.get("dep") == package:
                        out.append(name)
                        break
        except Exception:
            pass
        self._log("info", "deps.reverse", f"Found {len(out)} reverse deps for {package}", package=package, count=len(out))
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="deps.reverse", status="ok", meta={"count": len(out)})
        except Exception:
            pass
        return out

    # ----------------- graph export -----------------
    def graph(self, package: str, dep_type: str = "all", format: str = "json", dest: Optional[str] = None) -> Dict[str, Any]:
        """
        Export dependency graph for a package.
        format: 'json' (structured) or 'dot' (Graphviz plain text)
        dest: optional path to write the output; if None writes to report_dir and returns path
        """
        start = time.time()
        res = self.resolve(package, dep_type=dep_type, use_cache=True)
        graph_obj = {"package": package, "dep_type": dep_type, "resolved": res.resolved, "cycles": res.cycles, "ts": res.timestamp}
        output_text = ""
        if format == "json":
            output_text = json.dumps(graph_obj, indent=2)
        elif format == "dot":
            # produce a small DOT graph
            lines = ["digraph deps {"]
            # add edges
            for t, lst in res.resolved.items():
                for dep in lst:
                    lines.append(f'  "{package}" -> "{dep}" [label="{t}"];')
            # add cycles
            for c in res.cycles:
                for i in range(len(c) - 1):
                    lines.append(f'  "{c[i]}" -> "{c[i+1]}" [style=dashed];')
            lines.append("}")
            output_text = "\n".join(lines)
        else:
            raise ValueError("unsupported format")

        # write to dest or report dir
        ts = int(time.time())
        filename = f"{package.replace('/', '_')}-deps-{dep_type}-{ts}.{('json' if format=='json' else 'dot')}"
        target = Path(dest) if dest else (self.report_dir / filename)
        try:
            target.write_text(output_text, encoding="utf-8")
            self._log("info", "deps.graph.write", f"Wrote graph to {target}", path=str(target))
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="deps.graph", status="ok", meta={"format": format, "path": str(target)})
        except Exception as e:
            self._log("error", "deps.graph.fail", f"Failed to write graph: {e}", error=str(e))
            return {"ok": False, "error": str(e)}
        duration = time.time() - start
        return {"ok": True, "path": str(target), "duration": duration}

    # ----------------- install missing -----------------
    def install_missing(self, package: str, dep_type: str = "all", confirm: bool = False, jobs: Optional[int] = None) -> Dict[str, Any]:
        """
        Try to install missing dependencies. By default runs in dry-run mode (no changes).
        confirm: must be True to actually attempt real installation (unless self.dry_run False).
        This method will try to call newpkg_upgrade.NewpkgUpgrade.rebuild(pkg) or fallback to logging.
        """
        start = time.time()
        missing_info = self.check_missing(package, dep_type=dep_type)
        missing = [m["name"] for m in missing_info["missing"]]

        if not missing:
            return {"ok": True, "installed": [], "skipped": 0, "duration": time.time() - start}

        if self.dry_run:
            self._log("info", "deps.install.dryrun", f"Dry-run: would install {len(missing)} packages", package=package, missing=missing)
            return {"ok": True, "installed": [], "skipped": len(missing), "duration": time.time() - start, "dry_run": True}

        if not confirm and self._cfg_get("deps.require_confirm", True):
            self._log("warning", "deps.install.no_confirm", "Installing missing packages requires explicit confirm=True")
            return {"ok": False, "error": "no_confirm", "missing": missing}

        # try to import and use NewpkgUpgrade if available
        try:
            from newpkg_upgrade import NewpkgUpgrade  # type: ignore
            upgr = NewpkgUpgrade(cfg=self.cfg, logger=self.logger, db=self.db)
        except Exception:
            upgr = None

        jobs = jobs or self.parallel_jobs
        installed = []
        skipped = []

        def worker(pkgname: str) -> Tuple[str, bool, Optional[str]]:
            # attempts to install/rebuild pkgname; return (pkgname, ok_bool, message)
            try:
                if upgr and hasattr(upgr, "rebuild"):
                    self._log("info", "deps.install.call", f"Attempting rebuild via NewpkgUpgrade for {pkgname}", package=pkgname)
                    ok = False
                    try:
                        r = upgr.rebuild(pkgname)
                        ok = bool(r)
                    except Exception as e:
                        return (pkgname, False, f"rebuild exception: {e}")
                    return (pkgname, ok, None if ok else "rebuild failed")
                else:
                    # fallback: log and skip (could call distro package manager if desired)
                    return (pkgname, False, "no upgrade handler")
            except Exception as e:
                return (pkgname, False, f"exception: {e}")

        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futures = {ex.submit(worker, pkgname): pkgname for pkgname in missing}
            for fut in as_completed(futures):
                pkgname = futures[fut]
                try:
                    name, ok, msg = fut.result()
                except Exception as e:
                    name, ok, msg = pkgname, False, f"exception: {e}"
                if ok:
                    installed.append(name)
                else:
                    skipped.append({"name": name, "reason": msg})

        duration = time.time() - start
        self._log("info", "deps.install.done", f"Install_missing finished: installed={len(installed)} skipped={len(skipped)}", installed=len(installed), skipped=len(skipped), duration=duration)
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="deps.install_missing", status="ok" if not skipped else "partial", meta={"installed": len(installed), "skipped": len(skipped)})
        except Exception:
            pass

        return {"ok": True, "installed": installed, "skipped": skipped, "duration": duration}

    # ----------------- CLI -----------------
    @staticmethod
    def cli():
        import argparse
        p = argparse.ArgumentParser(prog="newpkg-deps", description="Dependency resolver for newpkg")
        p.add_argument("package", help="package name to inspect")
        p.add_argument("--resolve", action="store_true", help="resolve dependencies")
        p.add_argument("--missing", action="store_true", help="check missing dependencies")
        p.add_argument("--graph", metavar="FORMAT", choices=["json", "dot"], help="export graph to report dir (json|dot)")
        p.add_argument("--reverse", action="store_true", help="show reverse deps")
        p.add_argument("--install-missing", action="store_true", help="attempt to install missing deps (requires --confirm)")
        p.add_argument("--confirm", action="store_true", help="confirm install actions")
        p.add_argument("--jobs", type=int, help="parallel jobs override")
        p.add_argument("--json", action="store_true", help="print JSON output")
        p.add_argument("--quiet", action="store_true", help="quiet mode")
        p.add_argument("--no-cache", action="store_true", help="disable cache for resolve")
        args = p.parse_args()

        cfg = init_config() if init_config else None
        logger = NewpkgLogger.from_config(cfg, NewpkgDB(cfg)) if NewpkgLogger and cfg else None
        db = NewpkgDB(cfg) if NewpkgDB and cfg else None
        nd = NewpkgDeps(cfg=cfg, logger=logger, db=db)

        if args.quiet:
            nd.quiet = True
        if args.json:
            nd.json_out = True
        if args.jobs:
            nd.parallel_jobs = args.jobs

        out = {}
        if args.resolve:
            res = nd.resolve(args.package, dep_type="all", use_cache=not args.no_cache)
            out = res.to_dict()
            if nd.json_out or args.json:
                print(json.dumps(out, indent=2))
            else:
                print(f"Resolved for {args.package}:")
                for t, lst in out["resolved"].items():
                    print(f"  {t}: {', '.join(lst) if lst else '<none>'}")
                if out["cycles"]:
                    print("  Cycles detected:")
                    for c in out["cycles"]:
                        print("   - " + " -> ".join(c))
        if args.missing:
            res = nd.check_missing(args.package)
            out = res
            if nd.json_out or args.json:
                print(json.dumps(out, indent=2))
            else:
                print(f"Missing for {args.package}:")
                for m in res["missing"]:
                    print(f"  - {m['name']} ({m['type']})")
        if args.graph:
            res = nd.graph(args.package, dep_type="all", format=args.graph)
            out = res
            if nd.json_out or args.json:
                print(json.dumps(out, indent=2))
            else:
                print(f"Graph written to {res.get('path')}")
        if args.reverse:
            r = nd.reverse(args.package)
            out = {"reverse": r}
            if nd.json_out or args.json:
                print(json.dumps(out, indent=2))
            else:
                print(f"Reverse deps for {args.package}: {', '.join(r) if r else '<none>'}")
        if args.install_missing:
            res = nd.install_missing(args.package, confirm=args.confirm, jobs=args.jobs)
            out = res
            if nd.json_out or args.json:
                print(json.dumps(out, indent=2))
            else:
                print("Install missing result:")
                print(res)

        # write a small last-run report
        try:
            if out:
                rpt = Path(nd.report_dir) / f"{args.package}-deps-last.json"
                rpt.write_text(json.dumps(out, indent=2), encoding="utf-8")
                nd._log("info", "deps.report.write", f"Wrote report {rpt}", path=str(rpt))
        except Exception:
            pass

    # expose CLI convenience
    run_cli = cli


# If executed directly
if __name__ == "__main__":
    NewpkgDeps.cli()
