#!/usr/bin/env python3
# newpkg_cli.py — enhanced CLI with info/search/revdep/depclean/deps
"""
Unified newpkg CLI (revised) — adds info, search, revdep, depclean, deps commands.

Key points:
 - Auto-discovers modules in modules/
 - Supports module-provided mapping __newpkg_cmds__ = {"info": "func_name", ...}
 - If module doesn't provide mapping, attempts to call common function names
 - Integrates with newpkg_api singletons when available
 - Hooks: pre_command, post_command, on_error, on_complete
 - Colors & progress with rich if available
 - Outputs report JSON to /var/log/newpkg/cli/
 - Commands implemented: install, remove, upgrade, build, audit, sync, info, search, revdep, depclean, deps (mapping to modules/db when possible)
"""
from __future__ import annotations

import argparse
import importlib
import inspect
import json
import os
import pkgutil
import shutil
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Optional nice CLI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    RICH = True
    console = Console()
except Exception:
    RICH = False
    console = None

# Optional local API
try:
    from newpkg_api import get_api  # type: ignore
except Exception:
    get_api = None

# helpers & defaults
DEFAULT_CLI_LOGDIR = Path("/var/log/newpkg/cli")
DEFAULT_MODULES_DIR = Path(__file__).parent / "modules"
DEFAULT_EXIT_CODES = {"success": 0, "partial": 1, "error": 2, "critical": 3}

for d in (DEFAULT_CLI_LOGDIR, DEFAULT_MODULES_DIR):
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

@dataclass
class CLIResult:
    command: str
    targets: List[str]
    ok: bool
    exit_code: int
    duration_s: float
    report_paths: List[str]
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def save_cli_report(obj: Dict[str, Any], name: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    fname = DEFAULT_CLI_LOGDIR / f"cli-{name}-{ts}.json"
    try:
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        return str(fname)
    except Exception:
        return ""

def _print(msg: str, quiet: bool):
    if quiet:
        return
    if RICH and console:
        console.print(msg)
    else:
        print(msg)

# CLI core
class NewpkgCLI:
    def __init__(self):
        # API detection & singletons
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

        self.cfg = getattr(self.api, "cfg", None) if self.api else None
        self.logger = getattr(self.api, "logger", None) if self.api else None
        self.db = getattr(self.api, "db", None) if self.api else None
        self.hooks = getattr(self.api, "hooks", None) if self.api else None
        self.sandbox = getattr(self.api, "sandbox", None) if self.api else None
        self.core = getattr(self.api, "core", None) if self.api else None
        self.upgrade = getattr(self.api, "upgrade", None) if self.api else None
        self.audit = getattr(self.api, "audit", None) if self.api else None
        self.deps = getattr(self.api, "deps", None) if self.api else None
        # register CLI
        try:
            if self.api:
                self.api.cli = self
        except Exception:
            pass

        # modules discovery
        self.modules_dir = Path(self.cfg.get("cli.modules_dir")) if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("cli.modules_dir")) else DEFAULT_MODULES_DIR
        self.commands: Dict[str, Dict[str, Any]] = {}
        self._discover_modules()

    def _discover_modules(self):
        self.commands.clear()
        p = str(self.modules_dir)
        if p not in sys.path:
            sys.path.insert(0, p)
        # iterate modules dir with pkgutil
        try:
            for finder, name, ispkg in pkgutil.iter_modules([p]):
                try:
                    mod = importlib.import_module(name)
                except Exception:
                    continue
                # if module declares mapping __newpkg_cmds__
                mapping = getattr(mod, "__newpkg_cmds__", None)
                if isinstance(mapping, dict):
                    for cmd, func in mapping.items():
                        self.commands[cmd] = {"module": mod, "callable_name": func, "meta": getattr(mod, "META", {})}
                else:
                    # infer common names
                    for candidate in ("install", "remove", "upgrade", "build_package", "build", "sync", "download", "audit", "info", "search", "revdep", "depclean", "deps", "run", "main"):
                        if hasattr(mod, candidate):
                            self.commands.setdefault(candidate, {"module": mod, "callable_name": candidate, "meta": getattr(mod, "META", {})})
        except Exception:
            pass

        # modules available via API take precedence
        if self.core:
            self.commands.setdefault("build", {"module": self.core, "callable_name": "build_package", "meta": {}})
        if self.upgrade:
            self.commands.setdefault("upgrade", {"module": self.upgrade, "callable_name": "upgrade_package", "meta": {}})
        if self.deps:
            # if deps manager exists via API, ensure mapping
            self.commands.setdefault("deps", {"module": self.deps, "callable_name": "deps", "meta": {}})

    def _run_hook(self, hook_name: str, ctx: Dict[str, Any]):
        try:
            if self.hooks and hasattr(self.hooks, "run_named"):
                try:
                    self.hooks.run_named([hook_name], env=ctx)
                except Exception:
                    pass
        except Exception:
            pass

    def _invoke(self, entry: Dict[str, Any], target: Optional[str], opts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoke an entry (module + callable_name). Tries multiple call signatures.
        Normalizes and returns dict: {"ok": bool, "report": dict|None, "error": str|None}
        """
        mod = entry.get("module")
        func_name = entry.get("callable_name")
        # prefer explicit callable; fallback to common aliases inside module
        candidates = [func_name, "info", "search", "revdep", "depclean", "deps", "install", "remove", "upgrade", "build_package", "build", "run", "main"]
        last_err = None
        for fname in candidates:
            if not hasattr(mod, fname):
                continue
            func = getattr(mod, fname)
            try:
                sig = None
                try:
                    sig = inspect.signature(func)
                except Exception:
                    sig = None
                args = []
                kwargs = {}
                # if function accepts name as first parameter
                if target is not None:
                    if sig and len(sig.parameters) >= 1:
                        args.append(target)
                    else:
                        kwargs["name"] = target
                # pass options as 'opts' param if accepted
                if sig:
                    if "opts" in sig.parameters:
                        kwargs["opts"] = opts
                    elif any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
                        kwargs.update(opts)
                    else:
                        # if signature expects positional opts, append
                        if len(sig.parameters) >= (1 if target is not None else 0) + 1:
                            args.append(opts)
                else:
                    # best-effort: try (target, opts)
                    if target is not None:
                        args.append(target)
                    args.append(opts)
                res = func(*args, **kwargs)
                # normalize return
                if isinstance(res, dict):
                    return {"ok": True, "report": res, "error": None}
                # dataclass-like or object
                if hasattr(res, "__dict__"):
                    try:
                        return {"ok": True, "report": dict(res.__dict__), "error": None}
                    except Exception:
                        pass
                return {"ok": True, "report": {"result": res}, "error": None}
            except Exception as e:
                last_err = str(e)
                # if function raised, return failure for this candidate (do not try others if it's main)
                return {"ok": False, "report": None, "error": last_err}
        return {"ok": False, "report": None, "error": last_err or "callable_not_found"}

    # --- fallback helpers when module not present ---
    def _info_fallback(self, name: str, opts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Provide package info using DB and metafile heuristics if no module implements info.
        """
        out = {"package": name, "found": False, "installed": False, "metafile": None, "files": [], "checksum_ok": None}
        try:
            # try DB
            if self.db and hasattr(self.db, "get_package"):
                try:
                    pkg = self.db.get_package(name)
                    if pkg:
                        out["found"] = True
                        out["installed"] = True
                        out["meta"] = pkg
                except Exception:
                    pass
            # try metafile dirs
            metas = []
            mdirs = [Path("/etc/newpkg/metafiles"), Path("/var/lib/newpkg/metafiles")]
            for md in mdirs:
                if not md.exists():
                    continue
                for f in md.iterdir():
                    try:
                        txt = f.read_text(encoding="utf-8", errors="ignore")
                        if name in txt:
                            metas.append(str(f))
                    except Exception:
                        continue
            if metas:
                out["metafile"] = metas[0]
                out["found"] = True
            # files from db.package_files if available
            if self.db and hasattr(self.db, "package_files"):
                try:
                    out["files"] = list(self.db.package_files(name))
                    out["installed"] = len(out["files"]) > 0
                except Exception:
                    pass
            # checksum verification optional
            if opts.get("checksum") and self.db and hasattr(self.db, "file_checksums"):
                mismatches = []
                try:
                    for fp, expected in self.db.file_checksums(name):
                        from hashlib import sha256
                        p = Path(fp)
                        if p.exists():
                            h = sha256(p.read_bytes()).hexdigest()
                            if h != expected:
                                mismatches.append({"file": fp, "expected": expected, "actual": h})
                    out["checksum_ok"] = len(mismatches) == 0
                    if mismatches:
                        out["checksum_mismatches"] = mismatches
                except Exception:
                    out["checksum_ok"] = None
            return {"ok": True, "report": out, "error": None}
        except Exception as e:
            return {"ok": False, "report": None, "error": str(e)}

    def _search_fallback(self, query: str, opts: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        try:
            # search DB names or metafiles for query
            if self.db and hasattr(self.db, "list_packages"):
                try:
                    for r in self.db.list_packages():
                        name = r[0] if isinstance(r, (list, tuple)) else (r.get("name") if isinstance(r, dict) else str(r))
                        if query.lower() in name.lower():
                            results.append({"name": name, "source": "db"})
                except Exception:
                    pass
            # search metafiles
            mdirs = [Path("/etc/newpkg/metafiles"), Path("/var/lib/newpkg/metafiles")]
            for md in mdirs:
                if not md.exists():
                    continue
                for f in md.iterdir():
                    try:
                        txt = f.read_text(encoding="utf-8", errors="ignore")
                        if query.lower() in txt.lower():
                            # try to extract name/version lines quickly
                            results.append({"name": f.stem, "source": str(f)})
                    except Exception:
                        continue
            return {"ok": True, "report": {"query": query, "results": results}, "error": None}
        except Exception as e:
            return {"ok": False, "report": None, "error": str(e)}

    def _revdep_fallback(self, name: str, opts: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if self.db and hasattr(self.db, "list_reverse_deps"):
                try:
                    revs = list(self.db.list_reverse_deps(name))
                    return {"ok": True, "report": {"package": name, "reverse_deps": revs}, "error": None}
                except Exception:
                    pass
            # fallback: scan all packages and look for dependency mentions
            found = []
            if self.db and hasattr(self.db, "list_packages") and hasattr(self.db, "package_deps"):
                try:
                    for p in self.db.list_packages():
                        pname = p[0] if isinstance(p, (list, tuple)) else (p.get("name") if isinstance(p, dict) else str(p))
                        deps = []
                        try:
                            deps = list(self.db.package_deps(pname))
                        except Exception:
                            deps = []
                        if name in deps:
                            found.append(pname)
                    return {"ok": True, "report": {"package": name, "reverse_deps": found}, "error": None}
                except Exception:
                    pass
            return {"ok": True, "report": {"package": name, "reverse_deps": found}, "error": None}
        except Exception as e:
            return {"ok": False, "report": None, "error": str(e)}

    def _depclean_fallback(self, opts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Identify orphaned packages and produce a plan. Does NOT remove by default.
        """
        try:
            orphans = []
            pkg_map = {}
            if self.db and hasattr(self.db, "list_packages") and hasattr(self.db, "list_reverse_deps"):
                try:
                    for p in self.db.list_packages():
                        name = p[0] if isinstance(p, (list, tuple)) else (p.get("name") if isinstance(p, dict) else str(p))
                        rev = list(self.db.list_reverse_deps(name))
                        if not rev:
                            orphans.append(name)
                    return {"ok": True, "report": {"orphans": orphans, "count": len(orphans)}, "error": None}
                except Exception:
                    pass
            # fallback empty
            return {"ok": True, "report": {"orphans": orphans, "count": len(orphans)}, "error": None}
        except Exception as e:
            return {"ok": False, "report": None, "error": str(e)}

    def _deps_fallback(self, name: str, opts: Dict[str, Any]) -> Dict[str, Any]:
        try:
            # prefer module 'deps' if present
            if self.deps:
                try:
                    if hasattr(self.deps, "deps"):
                        r = self.deps.deps(name, opts=opts)
                        return {"ok": True, "report": r, "error": None}
                except Exception:
                    pass
            # fallback to DB queries for build/runtime separation
            deps_out = {"build": [], "runtime": []}
            if self.db and hasattr(self.db, "package_deps"):
                try:
                    for dep in self.db.package_deps(name, dep_type="build"):
                        deps_out["build"].append(dep)
                except Exception:
                    pass
                try:
                    for dep in self.db.package_deps(name, dep_type="runtime"):
                        deps_out["runtime"].append(dep)
                except Exception:
                    pass
            return {"ok": True, "report": {"package": name, "deps": deps_out}, "error": None}
        except Exception as e:
            return {"ok": False, "report": None, "error": str(e)}

    # --- main run ---
    def run(self, argv: Optional[List[str]] = None) -> int:
        parser = argparse.ArgumentParser(prog="newpkg", description="newpkg unified CLI")
        # globals
        parser.add_argument("--profile", "-P", default=(self.cfg.get("cli.default_profile") if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("cli.default_profile")) else "system"))
        parser.add_argument("--json", action="store_true", help="emit JSON report to stdout")
        parser.add_argument("--quiet", action="store_true", help="minimize terminal output")
        parser.add_argument("--dry-run", action="store_true", help="simulate actions")
        parser.add_argument("--lfs", action="store_true", help="operate inside LFS mount")
        parser.add_argument("--fakeroot", action="store_true", help="use fakeroot where supported")
        parser.add_argument("--destdir", help="DESTDIR for staging/installs")
        parser.add_argument("--jobs", "-j", type=int, help="parallel jobs")
        parser.add_argument("--yes", "-y", action="store_true", help="assume yes/non-interactive")
        # convenient shortcuts that map to subcommands
        parser.add_argument("-i", "--install", nargs="+", help="install package(s)")
        parser.add_argument("-r", "--remove", nargs="+", help="remove package(s)")
        parser.add_argument("-u", "--upgrade", nargs="*", help="upgrade package(s) or all")
        parser.add_argument("-b", "--build", nargs=1, help="build a package")
        # explicit subcommands
        subparsers = parser.add_subparsers(dest="command", help="subcommands")
        # create subparsers for discovered commands so help shows them
        for cmd in sorted(set(list(self.commands.keys()) + ["install", "remove", "upgrade", "build", "audit", "sync", "info", "search", "revdep", "depclean", "deps"])):
            subparsers.add_parser(cmd, help=f"{cmd} command")

        args, extra = parser.parse_known_args(argv)

        # normalize command & targets
        command = args.command
        targets: List[str] = []
        if args.install:
            command = "install"; targets = args.install
        elif args.remove:
            command = "remove"; targets = args.remove
        elif args.upgrade is not None:
            command = "upgrade"; targets = args.upgrade if len(args.upgrade) > 0 else []
        elif args.build:
            command = "build"; targets = args.build
        else:
            if command in ("install", "remove", "upgrade", "build", "audit", "sync", "info", "search", "revdep", "depclean", "deps"):
                targets = extra or []
            else:
                # unknown command: map common long names from extra if present
                if extra:
                    targets = extra

        opts = {
            "profile": args.profile,
            "json": args.json,
            "quiet": args.quiet,
            "dry_run": args.dry_run,
            "lfs": args.lfs,
            "fakeroot": args.fakeroot,
            "destdir": args.destdir,
            "jobs": args.jobs,
            "yes": args.yes,
            "extra": extra,
        }

        # run pre_command hook
        self._run_hook("pre_command", {"command": command, "targets": targets, "opts": opts})

        # dispatch
        start = time.time()
        report_paths: List[str] = []
        overall_ok = True
        error_msg = None
        details = {"subreports": []}

        # get module entry if exists
        entry = self.commands.get(command)
        # fallback mappings
        fallback_map = {
            "info": "info", "search": "search", "revdep": "revdep", "depclean": "depclean", "deps": "deps",
            "install": "install", "remove": "remove", "upgrade": "upgrade", "build": "build",
            "audit": "audit", "sync": "sync"
        }
        if entry is None and command in fallback_map:
            entry = self.commands.get(fallback_map[command])

        if entry is None and command not in ("info","search","revdep","depclean","deps"):
            # critical if basic command missing
            error_msg = f"command '{command}' not implemented (no module)."
            self._run_hook("on_error", {"command": command, "error": error_msg})
            self._run_hook("post_command", {"command": command, "ok": False})
            self._run_hook("on_complete", {"command": command, "ok": False})
            _print(f"[CRITICAL] {error_msg}", args.quiet)
            return DEFAULT_EXIT_CODES["critical"]

        # commands that accept no targets: upgrade (all), audit, sync, depclean (can auto-scan)
        if command in ("upgrade", "audit", "sync", "depclean") and not targets:
            targets = [None]

        # if commands expect a target but none supplied, error (install/remove/build/info/search/deps/revdep)
        if command in ("install","remove","build","info","search","revdep","deps") and not targets:
            _print(f"No target specified for '{command}'. Use package name(s) or --dry-run to preview.", args.quiet)
            return DEFAULT_EXIT_CODES["error"]

        # iterate targets sequentially (preserve order); can be parallelized later when safe
        for t in targets:
            name = t if isinstance(t, str) else None
            # build target-specific opts
            call_opts = dict(opts)
            if name:
                call_opts["name"] = name

            # if module missing but fallback supported, use fallback functions for specific commands
            used_fallback = False
            if entry is None:
                used_fallback = True

            try:
                _print(f">>>> Preparando: {command} {name or ''} <<<<", args.quiet)

                if used_fallback:
                    # dispatch to internal fallbacks
                    if command == "info":
                        res = self._info_fallback(name, call_opts)
                    elif command == "search":
                        # name is query in this case
                        res = self._search_fallback(name or call_opts.get("extra",[None])[0], call_opts)
                    elif command == "revdep":
                        res = self._revdep_fallback(name, call_opts)
                    elif command == "depclean":
                        res = self._depclean_fallback(call_opts)
                    elif command == "deps":
                        res = self._deps_fallback(name, call_opts)
                    else:
                        res = {"ok": False, "report": None, "error": f"no fallback for {command}"}
                else:
                    # call module
                    res = self._invoke(entry, name, call_opts)
                    # if command not implemented in module (callable_not_found), maybe fallbacks apply
                    if not res.get("ok") and res.get("error") and "callable_not_found" in res.get("error"):
                        if command == "info":
                            res = self._info_fallback(name, call_opts)
                        elif command == "search":
                            res = self._search_fallback(name or call_opts.get("extra",[None])[0], call_opts)
                        elif command == "revdep":
                            res = self._revdep_fallback(name, call_opts)
                        elif command == "depclean":
                            res = self._depclean_fallback(call_opts)
                        elif command == "deps":
                            res = self._deps_fallback(name, call_opts)

                ok = bool(res.get("ok"))
                report = res.get("report") or {}
                err = res.get("error")
                # collect subreport paths known in module report
                rep_paths = []
                if isinstance(report, dict):
                    for k in ("report_path","report","reports","path"):
                        if k in report and report[k]:
                            if isinstance(report[k], (list,tuple)):
                                rep_paths.extend([str(x) for x in report[k]])
                            else:
                                rep_paths.append(str(report[k]))
                details["subreports"].append({"target": name, "command": command, "ok": ok, "error": err, "report": report})
                if rep_paths:
                    report_paths.extend(rep_paths)
                if not ok:
                    overall_ok = False
                    error_msg = err or f"{command} failed for {name}"
                    self._run_hook("on_error", {"command": command, "target": name, "error": error_msg})
                    _print(f"[ERROR] {command} {name or ''}: {error_msg}", args.quiet)
                else:
                    _print(f"[OK] {command} {name or ''} ok", args.quiet)

            except Exception as e:
                overall_ok = False
                error_msg = str(e)
                details["subreports"].append({"target": name, "command": command, "ok": False, "error": error_msg})
                self._run_hook("on_error", {"command": command, "target": name, "error": error_msg})
                _print(f"[EXCEPTION] {error_msg}", args.quiet)

        duration = time.time() - start
        exit_code = DEFAULT_EXIT_CODES["success"] if overall_ok else DEFAULT_EXIT_CODES["partial"]
        cli_report = {
            "command": command,
            "targets": targets,
            "ok": overall_ok,
            "exit_code": exit_code,
            "started_at": now_iso(),
            "duration_s": round(duration, 3),
            "report_paths": report_paths,
            "error": error_msg,
            "details": details,
        }

        # persist CLI report
        rp = save_cli_report(cli_report, command or "cli")
        if rp:
            cli_report["cli_report"] = rp
            report_paths.append(rp)

        # run post hooks
        self._run_hook("post_command", {"command": command, "ok": overall_ok, "report": cli_report})
        self._run_hook("on_complete", {"command": command, "ok": overall_ok, "report": cli_report})

        # print or emit JSON
        if args.json:
            print(json.dumps(cli_report, indent=2, ensure_ascii=False))
        else:
            if overall_ok:
                _print(f"[DONE] {command} finished in {round(duration,3)}s", args.quiet)
                if report_paths and not args.quiet:
                    _print(f"Report: {report_paths[-1]}", args.quiet)
            else:
                _print(f"[PARTIAL/ERROR] {command} finished in {round(duration,3)}s - see report", args.quiet)
                if report_paths and not args.quiet:
                    _print(f"Report: {report_paths[-1]}", args.quiet)

        return exit_code

# module-level helpers
_default_cli: Optional[NewpkgCLI] = None

def get_cli() -> NewpkgCLI:
    global _default_cli
    if _default_cli is None:
        _default_cli = NewpkgCLI()
    return _default_cli

def main(argv: Optional[List[str]] = None) -> int:
    cli = get_cli()
    return cli.run(argv)

if __name__ == "__main__":
    raise SystemExit(main())
