#!/usr/bin/env python3
"""
newpkg_deps.py

Dependency resolver and graph utilities for Newpkg.

Features:
 - resolve(pkg, dep_type='all') -> ordered list (basic topological like DFS)
 - check_missing(pkg) -> list of missing deps
 - parse_depfile(pkg_dir) -> read metafile (toml/json/yaml) to extract declared deps (best-effort)
 - get_reverse_deps(pkg) -> list packages that depend on pkg (uses DB if available)
 - cache results to .newpkg/deps_cache.json with TTL
 - export graph to JSON or DOT
 - install_missing -> best-effort delegate to newpkg_core/newpkg_upgrade or log actions
 - integrated with ConfigStore, NewpkgLogger, NewpkgDB
"""

from __future__ import annotations

import json
import os
import time
import shutil
import threading
import concurrent.futures
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Try to import init_config / ConfigStore
try:
    from newpkg_config import init_config, ConfigManager
except Exception:
    init_config = None
    ConfigManager = None

# Try to import logger & db
try:
    from newpkg_logger import NewpkgLogger
except Exception:
    NewpkgLogger = None

try:
    from newpkg_db import NewpkgDB
except Exception:
    NewpkgDB = None

# Optional parsers
try:
    import tomllib as _toml  # py3.11+
except Exception:
    try:
        import tomli as _toml  # type: ignore
    except Exception:
        _toml = None

try:
    import yaml
    _HAS_YAML = True
except Exception:
    yaml = None
    _HAS_YAML = False

# constants
CACHE_DIR = Path(".newpkg")
CACHE_FILE = CACHE_DIR / "deps_cache.json"
DEFAULT_CACHE_TTL = 60 * 60 * 24  # 24h


class DepsError(Exception):
    pass


class NewpkgDeps:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None):
        """
        cfg: optional ConfigStore or dict-like
        logger: NewpkgLogger-like
        db: NewpkgDB-like
        """
        self.cfg = cfg
        self.logger = logger or (NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None)
        self.db = db or (NewpkgDB(cfg) if NewpkgDB and cfg is not None else None)

        # config defaults (prefer lowercase hierarchical keys)
        self.cache_path = Path(self._cfg_get("deps.cache_path", str(CACHE_FILE)))
        self.cache_ttl = int(self._cfg_get("deps.cache_ttl", os.environ.get("NEWPKG_DEPS_CACHE_TTL", DEFAULT_CACHE_TTL)))
        self.graph_format = self._cfg_get("deps.graph_format", "json")
        self.resolve_depth = int(self._cfg_get("deps.resolve_depth", self._cfg_get("DEPS_RESOLVE_DEPTH", 0)))  # 0 = unlimited
        self.parallel = bool(self._cfg_get("deps.parallel", False))

        # internal caches
        self._mem_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()
        # ensure cache dir exists
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._load_cache()

    # ---------------- config helper ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        # legacy env fallback
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
        # fallback
        print(f"[{level}] {event}: {message}")

    # ---------------- cache management ----------------
    def _load_cache(self):
        with self._cache_lock:
            try:
                if not self.cache_path.exists():
                    self._mem_cache = {}
                    return
                raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
                # verify structure: {pkg: {ts:..., data:...}}
                self._mem_cache = raw or {}
            except Exception:
                self._mem_cache = {}

    def _save_cache(self):
        with self._cache_lock:
            try:
                tmp = self.cache_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(self._mem_cache, indent=2), encoding="utf-8")
                tmp.replace(self.cache_path)
            except Exception:
                pass

    def _cache_get(self, key: str) -> Optional[Any]:
        with self._cache_lock:
            entry = self._mem_cache.get(key)
            if not entry:
                return None
            ts = entry.get("ts", 0)
            if self.cache_ttl and (time.time() - ts) > self.cache_ttl:
                # stale
                self._mem_cache.pop(key, None)
                return None
            return entry.get("data")

    def _cache_set(self, key: str, data: Any):
        with self._cache_lock:
            self._mem_cache[key] = {"ts": time.time(), "data": data}
            # persist async-ish
            try:
                self._save_cache()
            except Exception:
                pass

    # ---------------- parsing manifest / metafile ----------------
    def parse_depfile(self, pkg_dir: str) -> Dict[str, List[str]]:
        """
        Best-effort parse of local metafile to extract declared dependencies.
        Supports: newpkg.toml, package.toml, package.json, deps.json, deps.yaml.
        Returns dict: {'build':[], 'runtime':[], 'optional':[]}
        """
        p = Path(pkg_dir)
        candidates = [
            p / "newpkg.toml",
            p / "package.toml",
            p / "package.json",
            p / "deps.json",
            p / "deps.yaml",
            p / "deps.yml",
        ]
        res = {"build": [], "runtime": [], "optional": []}
        for c in candidates:
            if not c.exists():
                continue
            try:
                raw = c.read_bytes()
                if c.suffix in (".toml", ".tml") and _toml:
                    doc = _toml.loads(raw.decode("utf-8"))
                elif c.suffix in (".yaml", ".yml") and _HAS_YAML:
                    doc = yaml.safe_load(raw.decode("utf-8"))
                else:
                    doc = json.loads(raw.decode("utf-8"))
                # try common keys
                for key in ("deps", "dependencies", "requires"):
                    if key in doc:
                        deps = doc.get(key) or {}
                        # doc may be mapping or list
                        if isinstance(deps, dict):
                            for k, v in deps.items():
                                # attempt classify: if v contains 'build' or 'runtime' keyword
                                if isinstance(v, dict) and v.get("type") == "build":
                                    res["build"].append(k)
                                elif isinstance(v, dict) and v.get("optional"):
                                    res["optional"].append(k)
                                else:
                                    res["runtime"].append(k)
                        elif isinstance(deps, list):
                            for d in deps:
                                if isinstance(d, str):
                                    res["runtime"].append(d)
                        break
                # some toml formats may contain [build-deps], [runtime-deps]
                for section, outk in (("build-deps", "build"), ("runtime-deps", "runtime"), ("optional-deps", "optional")):
                    if section in doc:
                        val = doc.get(section)
                        if isinstance(val, dict):
                            res[outk].extend(list(val.keys()))
                        elif isinstance(val, list):
                            res[outk].extend(val)
                # dedupe
                for k in res:
                    res[k] = sorted(list(set(res[k])))
                return res
            except Exception as e:
                self._log("warning", "deps.parse_fail", f"Failed to parse {c}: {e}", file=str(c))
                continue
        return res

    # ---------------- core resolution ----------------
    def resolve(self, pkg: str, dep_type: str = "all", include_optional: bool = False, depth: int = 0) -> List[str]:
        """
        Resolve dependencies for a package name or a local path.
        - dep_type: 'all', 'build', 'runtime'
        - include_optional: include optional deps
        - returns ordered list of dependencies (naive DFS, duplicates removed preserving order)
        Uses DB when available; otherwise parse local metafile (if pkg path exists).
        """
        cache_key = f"resolve:{pkg}:{dep_type}:{include_optional}:{self.resolve_depth}"
        cached = self._cache_get(cache_key)
        if cached:
            self._log("debug", "deps.cache_hit", f"Cache hit for {pkg}", package=pkg)
            return list(cached)

        resolved_order: List[str] = []
        seen: Set[str] = set()

        def _add(dep_name: str):
            if dep_name in seen:
                return
            seen.add(dep_name)
            resolved_order.append(dep_name)

        # use DB if possible
        if self.db:
            try:
                # try db.get_deps which may return dicts or strings
                deps_list = self.db.get_deps(pkg)
                # normalize into list of names
                normalized = []
                for d in deps_list or []:
                    if isinstance(d, dict):
                        name = d.get("dep_name") or d.get("name") or d.get("package")
                        dtype = d.get("dep_type") or "runtime"
                    else:
                        name = d
                        dtype = "runtime"
                    if not name:
                        continue
                    if dep_type == "all" or dtype == dep_type:
                        normalized.append((name, dtype))
                # recursively resolve
                def _dfs(name, curdepth=0):
                    if self.resolve_depth and curdepth > self.resolve_depth:
                        return
                    # fetch deps of name from DB
                    try:
                        child_deps = self.db.get_deps(name)
                    except Exception:
                        child_deps = []
                    for cd in child_deps or []:
                        if isinstance(cd, dict):
                            cname = cd.get("dep_name") or cd.get("name")
                            ctype = cd.get("dep_type") or "runtime"
                        else:
                            cname = cd
                            ctype = "runtime"
                        if not cname:
                            continue
                        if dep_type != "all" and ctype != dep_type:
                            continue
                        _dfs(cname, curdepth + 1)
                        _add(cname)
                # seed
                for name, dtype in normalized:
                    _dfs(name)
                    _add(name)
            except Exception as e:
                self._log("warning", "deps.db_resolve_fail", f"DB resolve failed for {pkg}: {e}", package=pkg)

        # if pkg is a path or DB failed, try parse local
        p = Path(pkg)
        if (not self.db) or p.exists():
            parsed = self.parse_depfile(pkg) if p.exists() else {}
            items = []
            if dep_type in ("all", "build"):
                items.extend(parsed.get("build", []))
            if dep_type in ("all", "runtime"):
                items.extend(parsed.get("runtime", []))
            if include_optional:
                items.extend(parsed.get("optional", []))
            # recursively resolve parsed items (best-effort without DB)
            def _dfs_local(name, curdepth=0):
                if self.resolve_depth and curdepth > self.resolve_depth:
                    return
                # attempt to find local dir under ./packages/<name> or ./sources/<name>
                candidates = [Path("packages") / name, Path("sources") / name, Path(name)]
                for cand in candidates:
                    if cand.exists() and cand.is_dir():
                        sub = self.parse_depfile(str(cand))
                        for subn in (sub.get("runtime", []) + sub.get("build", []) + (sub.get("optional", []) if include_optional else [])):
                            _dfs_local(subn, curdepth + 1)
                            _add(subn)
                # if not found locally, nothing more to do
            for it in items:
                _dfs_local(it)
                _add(it)

        # final dedupe & preserve order is done via seen/resolved_order
        self._cache_set(cache_key, resolved_order)
        self._log("info", "deps.resolve", f"Resolved {len(resolved_order)} deps for {pkg}", package=pkg, deps=len(resolved_order))
        return resolved_order

    def check_missing(self, pkg: str, dep_type: str = "all", include_optional: bool = False) -> List[str]:
        """
        Return list of dependency names that are referenced but not present in DB or local packages.
        """
        resolved = self.resolve(pkg, dep_type=dep_type, include_optional=include_optional)
        missing = []
        # build map of known packages (DB preferred)
        known: Set[str] = set()
        if self.db:
            try:
                pkgs = self.db.list_packages()
                known.update([p["name"] for p in pkgs])
            except Exception:
                known = set()
        # local packages
        for d in Path(".").iterdir():
            if d.is_dir():
                known.add(d.name)
        for r in resolved:
            if r not in known:
                missing.append(r)
        self._log("info", "deps.check_missing", f"{len(missing)} missing deps for {pkg}", package=pkg, missing=len(missing))
        return sorted(list(set(missing)))

    # ---------------- reverse deps ----------------
    def get_reverse_deps(self, pkg: str) -> List[str]:
        """
        Return list of packages that depend on `pkg`.
        Uses DB if available, else does a brute-force scan through known packages.
        """
        if self.db and hasattr(self.db, "get_reverse_deps"):
            try:
                return self.db.get_reverse_deps(pkg)
            except Exception:
                pass
        # brute force: scan packages and see who contains pkg in resolved deps
        result = []
        try:
            pkgs = [d.name for d in Path("packages").iterdir() if d.is_dir()] if Path("packages").exists() else []
            # also include DB packages names if present
            if self.db:
                try:
                    db_pkgs = self.db.list_packages()
                    pkgs += [p["name"] for p in db_pkgs]
                except Exception:
                    pass
            pkgs = sorted(set(pkgs))
            # optionally parallelize
            if self.parallel:
                with concurrent.futures.ThreadPoolExecutor() as ex:
                    futs = {ex.submit(self.resolve, p, "all", True): p for p in pkgs}
                    for fut in concurrent.futures.as_completed(futs):
                        p = futs[fut]
                        try:
                            deps = fut.result()
                            if pkg in deps:
                                result.append(p)
                        except Exception:
                            continue
            else:
                for p in pkgs:
                    try:
                        deps = self.resolve(p, "all", True)
                        if pkg in deps:
                            result.append(p)
                    except Exception:
                        continue
        except Exception:
            pass
        return sorted(result)

    # ---------------- graph export ----------------
    def graph(self, pkg: str, dep_type: str = "all", include_optional: bool = False, fmt: Optional[str] = None, out: Optional[str] = None) -> str:
        """
        Export dependency graph for a package.
        fmt: 'json' or 'dot' (graphviz). Defaults to self.graph_format or 'json'.
        If out specified, write to file and return path; otherwise return content string.
        """
        fmt = (fmt or self.graph_format or "json").lower()
        deps = self.resolve(pkg, dep_type=dep_type, include_optional=include_optional)
        # build adjacency (simple)
        adj = {}
        for d in deps:
            try:
                children = self.resolve(d, dep_type=dep_type, include_optional=include_optional)
            except Exception:
                children = []
            adj[d] = children

        if fmt == "dot":
            lines = ["digraph deps {"]
            lines.append('  node [shape=box];')
            for k, vals in adj.items():
                kq = k.replace("-", "_")
                if not vals:
                    lines.append(f'  "{kq}";')
                for v in vals:
                    vq = v.replace("-", "_")
                    lines.append(f'  "{kq}" -> "{vq}";')
            lines.append("}")
            content = "\n".join(lines)
        else:
            content = json.dumps({"package": pkg, "graph": adj}, indent=2)
        if out:
            p = Path(out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            self._log("info", "deps.graph.export", f"Wrote graph to {out}", path=str(p))
            return str(p)
        return content

    # ---------------- mutate DB helpers ----------------
    def add_dep(self, package_name: str, dep_name: str, dep_type: str = "runtime") -> bool:
        """
        Add a dependency to DB (if DB present) and update cache.
        """
        try:
            if self.db and hasattr(self.db, "add_dep"):
                self.db.add_dep(package_name, dep_name, dep_type)
                # invalidate cache for the package
                self._cache_set(f"resolve:{package_name}:all:False:{self.resolve_depth}", None)
                self._log("info", "deps.add", f"Added dep {dep_name} to {package_name}", package=package_name, dep=dep_name)
                return True
        except Exception as e:
            self._log("error", "deps.add_fail", f"Failed to add dep: {e}", package=package_name, dep=dep_name)
        return False

    def remove_dep(self, package_name: str, dep_name: str) -> bool:
        """
        Remove a dependency (if DB exposes such). Also updates cache.
        """
        try:
            if self.db and hasattr(self.db, "remove_dep"):
                self.db.remove_dep(package_name, dep_name)
                self._cache_set(f"resolve:{package_name}:all:False:{self.resolve_depth}", None)
                self._log("info", "deps.remove", f"Removed dep {dep_name} from {package_name}", package=package_name, dep=dep_name)
                return True
        except Exception as e:
            self._log("error", "deps.remove_fail", f"Failed to remove dep: {e}", package=package_name, dep=dep_name)
        return False

    # ---------------- install missing (best-effort) ----------------
    def install_missing(self, pkg: str, dep_type: str = "all", include_optional: bool = False, dry_run: bool = True) -> Dict[str, Any]:
        """
        Try to install missing dependencies:
         - first attempt: delegate to newpkg_upgrade.NewpkgUpgrade.rebuild or .install_missing if available
         - fallback: log and return list for manual action
        """
        missing = self.check_missing(pkg, dep_type=dep_type, include_optional=include_optional)
        res = {"package": pkg, "missing": missing, "attempts": [], "dry_run": dry_run}
        if not missing:
            return res
        if dry_run:
            self._log("info", "deps.install_missing.dry", f"Dry-run: would install {len(missing)} missing deps for {pkg}", package=pkg, missing=len(missing))
            return res

        # try to call newpkg_upgrade if available
        try:
            import importlib

            mod = importlib.import_module("newpkg_upgrade")
            if hasattr(mod, "NewpkgUpgrade"):
                upgr = mod.NewpkgUpgrade(self.cfg, logger=self.logger, db=self.db)
                for dep in missing:
                    try:
                        r = upgr.install(dep)
                        res["attempts"].append({dep: "ok"})
                        self._log("info", "deps.install_missing.ok", f"Installed {dep} via newpkg_upgrade", dep=dep)
                    except Exception as e:
                        res["attempts"].append({dep: f"error: {e}"})
                        self._log("error", "deps.install_missing.fail", f"Failed to install {dep}: {e}", dep=dep)
                return res
        except Exception:
            pass

        # fallback: log what to do
        self._log("warning", "deps.install_missing.manual", f"No installer available; missing deps for {pkg}: {missing}", package=pkg, missing=list(missing))
        res["note"] = "no-installer"
        return res

    # ---------------- CLI convenience ----------------
    @classmethod
    def cli_main(cls, argv: Optional[List[str]] = None):
        import argparse
        import sys

        p = argparse.ArgumentParser(prog="newpkg-deps", description="newpkg dependency tools")
        p.add_argument("cmd", choices=["resolve", "missing", "graph", "reverse"], help="subcommand")
        p.add_argument("target", help="package name or directory")
        p.add_argument("--type", choices=["all", "build", "runtime"], default="all")
        p.add_argument("--optional", action="store_true")
        p.add_argument("--out", help="output file (for graph)")
        p.add_argument("--format", choices=["json", "dot"], help="graph format")
        args = p.parse_args(argv)

        cfg = None
        if init_config:
            try:
                cfg = init_config()
            except Exception:
                cfg = None

        db = NewpkgDB(cfg) if NewpkgDB and cfg is not None else None
        logger = NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None
        deps = cls(cfg=cfg, logger=logger, db=db)

        if args.cmd == "resolve":
            out = deps.resolve(args.target, dep_type=args.type, include_optional=args.optional)
            print(json.dumps(out, indent=2))
            return 0
        if args.cmd == "missing":
            out = deps.check_missing(args.target, dep_type=args.type, include_optional=args.optional)
            print(json.dumps(out, indent=2))
            return 0
        if args.cmd == "graph":
            content = deps.graph(args.target, dep_type=args.type, include_optional=args.optional, fmt=args.format, out=args.out)
            if args.out:
                print(f"Wrote to {content}")
            else:
                print(content)
            return 0
        if args.cmd == "reverse":
            out = deps.get_reverse_deps(args.target)
            print(json.dumps(out, indent=2))
            return 0
        return 1


# If executed as script
if __name__ == "__main__":
    NewpkgDeps.cli_main()
