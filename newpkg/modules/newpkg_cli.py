#!/usr/bin/env python3
# newpkg_cli.py
"""
newpkg_cli.py -- Unified CLI for the newpkg toolset.

Features:
 - Integrates: newpkg_config, newpkg_logger, newpkg_db, newpkg_hooks, newpkg_core,
   newpkg_upgrade, newpkg_remove, newpkg_sync, newpkg_audit, newpkg_metafile, newpkg_download etc.
 - Subcommands: install, remove, upgrade, sync, audit, build, package, info
 - Global flags: --dry-run, --quiet, --json, --jobs, --no-color, --sandbox
 - Uses `rich` for colored banners and `tqdm` for simple progress bars when available.
 - Respects dry-run and quiet modes. Outputs JSON if requested.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# optional framework modules (project)
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
    from newpkg_core import NewpkgCore
except Exception:
    NewpkgCore = None

try:
    from newpkg_upgrade import NewpkgUpgrade
except Exception:
    NewpkgUpgrade = None

try:
    from newpkg_remove import NewpkgRemover
except Exception:
    NewpkgRemover = None

try:
    from newpkg_sync import NewpkgSync
except Exception:
    NewpkgSync = None

try:
    from newpkg_audit import NewpkgAudit
except Exception:
    NewpkgAudit = None

try:
    from newpkg_metafile import Metafile
except Exception:
    Metafile = None

# UI niceties
_HAS_RICH = False
_HAS_TQDM = False
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    _HAS_RICH = True
    console = Console()
except Exception:
    console = None

try:
    from tqdm import tqdm
    _HAS_TQDM = True
except Exception:
    tqdm = None

# default settings
DEFAULT_JOBS = int(os.environ.get("NEWPKG_JOBS", "1"))

@dataclass
class CLIResult:
    command: str
    package: Optional[str] = None
    status: str = "unknown"
    started_at: str = datetime.utcnow().isoformat() + "Z"
    finished_at: Optional[str] = None
    details: Dict[str, Any] = None

    def finish(self, status: str, details: Optional[Dict[str, Any]] = None):
        self.status = status
        self.finished_at = datetime.utcnow().isoformat() + "Z"
        self.details = details or {}

# CLI utility functions
def _pretty(msg: str, style: str = "cyan", quiet: bool = False):
    if quiet:
        return
    if _HAS_RICH and console:
        console.print(Panel(msg, style=style))
    else:
        print(msg)

def _info(msg: str, quiet: bool = False):
    if quiet:
        return
    if _HAS_RICH and console:
        console.print(f"[bold green][INFO][/bold green] {msg}")
    else:
        print(f"[INFO] {msg}")

def _error(msg: str):
    if _HAS_RICH and console:
        console.print(f"[bold red][ERROR][/bold red] {msg}")
    else:
        print(f"[ERROR] {msg}", file=sys.stderr)

def _maybe_progress(total: int = 0, description: str = ""):
    """Return a context manager that yields an update function. Works with rich or tqdm or noop."""
    if _HAS_RICH and console:
        prog = Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(), TimeRemainingColumn())
        task_id = None
        class Ctx:
            def __enter__(self_inner):
                nonlocal task_id
                prog.start()
                task_id = prog.add_task(description, total=total)
                return lambda n=1, desc=None: prog.update(task_id, advance=n, description=desc or description)
            def __exit__(self_inner, exc_type, exc, tb):
                prog.stop()
        return Ctx()
    if _HAS_TQDM:
        pbar = tqdm(total=total, desc=description)
        class Ctx2:
            def __enter__(self_inner):
                return lambda n=1, desc=None: pbar.update(n)
            def __exit__(self_inner, exc_type, exc, tb):
                pbar.close()
        return Ctx2()
    # noop
    class Noop:
        def __enter__(self_inner):
            return lambda n=1, desc=None: None
        def __exit__(self_inner, exc_type, exc, tb):
            return False
    return Noop()

# Initialize singletons (will be set in main)
CFG = None
LOGGER = None
DB = None
HOOKS = None
CORE = None
UPGRADE = None
REMOVER = None
SYNC = None
AUDIT = None

def init_components(config: Any, use_sandbox: Optional[bool], quiet: bool):
    """Create module instances and wire them globally (best-effort)."""
    global CFG, LOGGER, DB, HOOKS, CORE, UPGRADE, REMOVER, SYNC, AUDIT
    CFG = config
    DB = NewpkgDB(CFG) if NewpkgDB and CFG is not None else None
    # logger from config
    if NewpkgLogger and CFG is not None:
        try:
            LOGGER = NewpkgLogger.from_config(CFG, DB)
        except Exception:
            LOGGER = None
    else:
        LOGGER = None
    HOOKS = HooksManager(CFG, LOGGER, DB) if HooksManager and CFG is not None else None
    CORE = NewpkgCore(CFG, LOGGER, DB) if NewpkgCore and CFG is not None else None
    UPGRADE = NewpkgUpgrade(CFG, LOGGER, DB) if NewpkgUpgrade and CFG is not None else None
    REMOVER = NewpkgRemover(CFG, LOGGER, DB) if NewpkgRemover and CFG is not None else None
    SYNC = NewpkgSync(CFG, LOGGER, DB) if NewpkgSync and CFG is not None else None
    AUDIT = NewpkgAudit(CFG, LOGGER, DB) if NewpkgAudit and CFG is not None else None

def _dispatch_install(pkg: str, metafile: Optional[str], destdir: Optional[str], jobs: int, dry_run: bool, quiet: bool, use_sandbox: Optional[bool], json_out: bool):
    """Top-level install pipeline. Best-effort wiring among Metafile, Core, Downloader, Patcher, Hooks."""
    r = CLIResult(command="install", package=pkg)
    try:
        _pretty(f">>>> Preparando a construção do {pkg} <<<<", quiet=quiet)
        # load config components if not already
        if CORE is None:
            _info("core module not available; falling back to basic operations", quiet=quiet)
        # Load metafile if provided
        mf = None
        if metafile and Metafile:
            try:
                mf = Metafile(cfg=CFG, logger=LOGGER, db=DB)
                mf.load(metafile)
            except Exception as e:
                _error(f"Failed to load metafile: {e}")
                mf = None
        # resolve deps
        if CORE:
            _info("Resolving build deps...", quiet=quiet)
            deps_res = CORE.resolve_build_deps(pkg, operate_on_metafile=mf)
        else:
            deps_res = {"deps": []}
        # prepare (download + patch) - CORE.prepare handles metafile downloads if present
        prep = CORE.prepare(pkg, metafile_path=metafile, profile=None) if CORE else {"workdir": f"/tmp/{pkg}-work", "srcdir": "", "builddir": "", "destdir": destdir or f"/tmp/{pkg}-dest"}
        _info(f"Prepared workdir {prep.get('workdir')}", quiet=quiet)
        if dry_run:
            r.finish("dry-run", {"prep": prep, "deps": deps_res})
            return r
        # build + install + package via full pipeline
        _info("Building and installing...", quiet=quiet)
        fb = CORE.full_build_cycle(pkg, version=None, metafile_path=metafile, profile=None, install_prefix=destdir or "/", do_package=True, do_deploy=False, strip_before_package=True, dry_run=False) if CORE else None
        if fb and getattr(fb, "status", "") == "ok":
            _info(f"Build/install successful for {pkg}", quiet=quiet)
            r.finish("ok", {"full_build": getattr(fb, "__dict__", fb)})
        else:
            # build failed
            r.finish("build-fail", {"result": getattr(fb, "__dict__", fb) if fb else None})
        # post hooks
        if HOOKS:
            try:
                HOOKS.execute_safe("post_install", pkg_dir=prep.get("workdir"))
            except Exception:
                pass
    except Exception as e:
        _error(f"install pipeline failed: {e}")
        r.finish("error", {"error": str(e)})
    # output
    if json_out:
        print(json.dumps(asdict(r), indent=2))
    else:
        if not quiet:
            print(f"Install result: status={r.status}, package={pkg}")
    return r

def _dispatch_remove(pkg: str, purge: bool, simulate: bool, quiet: bool, json_out: bool):
    r = CLIResult(command="remove", package=pkg)
    try:
        _pretty(f">>>> Removendo pacote {pkg} <<<<", quiet=quiet)
        if REMOVER is None:
            _error("remove module not available")
            r.finish("no-remover")
            return r
        if simulate:
            plan = REMOVER.plan_removal(pkg)
            r.finish("simulated", {"plan": plan})
        else:
            res = REMOVER.remove(pkg, purge=purge, simulate=False, backup=True)
            status = "ok" if not res.get("errors") else "partial"
            r.finish(status, res)
    except Exception as e:
        _error(f"remove failed: {e}")
        r.finish("error", {"error": str(e)})
    if json_out:
        print(json.dumps(asdict(r), indent=2))
    else:
        if not quiet:
            print(f"Remove result: {r.status}")
    return r

def _dispatch_upgrade(pkg: str, force: bool, dry_run: bool, quiet: bool, json_out: bool):
    r = CLIResult(command="upgrade", package=pkg)
    try:
        _pretty(f">>>> Upgrade {pkg} <<<<", quiet=quiet)
        if UPGRADE is None:
            _error("upgrade module not available")
            r.finish("no-upgrade")
            return r
        res = UPGRADE.upgrade(pkg, force=force, do_package=True, do_deploy=False, dry_run=dry_run)
        status = getattr(res, "status", "unknown")
        r.finish(status, {"steps": getattr(res, "steps", None), "error": getattr(res, "error", None)})
    except Exception as e:
        _error(f"upgrade failed: {e}")
        r.finish("error", {"error": str(e)})
    if json_out:
        print(json.dumps(asdict(r), indent=2))
    else:
        if not quiet:
            print(f"Upgrade result: {r.status}")
    return r

def _dispatch_sync(names: Optional[List[str]], parallel: int, dry_run: bool, quiet: bool, json_out: bool):
    r = CLIResult(command="sync", package=None)
    try:
        _pretty(">>>> Sincronizando repositórios <<<<", quiet=quiet)
        if SYNC is None:
            _error("sync module not available")
            r.finish("no-sync")
            return r
        res = SYNC.sync_all(dry_run=dry_run, names=names, parallel=parallel)
        r.finish("ok", {"repos": res})
    except Exception as e:
        _error(f"sync failed: {e}")
        r.finish("error", {"error": str(e)})
    if json_out:
        print(json.dumps(asdict(r), indent=2))
    else:
        if not quiet:
            print("Sync finished")
    return r

def _dispatch_audit(include_unmanaged: bool, severity: Optional[float], dry_run: bool, quiet: bool, json_out: bool, fmt: str):
    r = CLIResult(command="audit", package=None)
    try:
        _pretty(">>>> Escaneando sistema <<<<", quiet=quiet)
        if AUDIT is None:
            _error("audit module not available")
            r.finish("no-audit")
            return r
        candidates = AUDIT.scan_system(include_unmanaged=include_unmanaged)
        findings = AUDIT.check_vulnerabilities(candidates, severity_threshold=severity)
        plan = AUDIT.plan_remediation(findings)
        report_text = AUDIT.report(findings, plan_summary=plan.get("summary"), format=fmt)
        r.finish("ok", {"findings": len(findings), "plan": plan.get("summary")})
        if json_out:
            # print structured JSON of findings + plan
            out = {"findings": [ {"package": f.candidate.name, "vulns": [v.cve for v in f.vulns]} for f in findings ], "plan": plan.get("summary")}
            print(json.dumps(out, indent=2))
        else:
            if not quiet:
                if _HAS_RICH and console and fmt != "json":
                    console.print(report_text)
                else:
                    print(report_text)
    except Exception as e:
        _error(f"audit failed: {e}")
        r.finish("error", {"error": str(e)})
    return r

def _dispatch_build(pkg: str, metafile: Optional[str], workdir: Optional[str], dry_run: bool, quiet: bool, json_out: bool):
    r = CLIResult(command="build", package=pkg)
    try:
        _pretty(f">>>> Construindo {pkg} <<<<", quiet=quiet)
        if CORE is None:
            _error("core module not available")
            r.finish("no-core")
            return r
        prep = CORE.prepare(pkg, metafile_path=metafile) if CORE else None
        if dry_run:
            r.finish("dry-run", {"prep": prep})
            return r
        res = CORE.build(pkg, prep.get("workdir") if prep else workdir)
        status = res.get("status", "error")
        r.finish(status, {"build": res})
    except Exception as e:
        _error(f"build failed: {e}")
        r.finish("error", {"error": str(e)})
    if json_out:
        print(json.dumps(asdict(r), indent=2))
    else:
        if not quiet:
            print(f"Build result: {r.status}")
    return r

def _dispatch_package(pkg: str, destdir: Optional[str], version: Optional[str], dry_run: bool, quiet: bool, json_out: bool):
    r = CLIResult(command="package", package=pkg)
    try:
        _pretty(f">>>> Empacotando {pkg} <<<<", quiet=quiet)
        if CORE is None:
            _error("core module not available")
            r.finish("no-core")
            return r
        if dry_run:
            r.finish("dry-run")
            return r
        res = CORE.package(pkg, version or "0", destdir or str(Path.cwd()), strip_before=True)
        status = res.get("status", "error")
        r.finish(status, {"package": res})
    except Exception as e:
        _error(f"package failed: {e}")
        r.finish("error", {"error": str(e)})
    if json_out:
        print(json.dumps(asdict(r), indent=2))
    else:
        if not quiet:
            print(f"Package result: {r.status}")
    return r

def _dispatch_info(pkg: Optional[str], quiet: bool, json_out: bool):
    r = CLIResult(command="info", package=pkg)
    try:
        _pretty(f">>>> Informações {pkg or 'sistema'} <<<<", quiet=quiet)
        data = {}
        if DB and pkg:
            try:
                data = DB.get_package(pkg) if hasattr(DB, "get_package") else {}
            except Exception:
                data = {}
        elif DB:
            try:
                data = {"packages": DB.list_packages() if hasattr(DB, "list_packages") else []}
            except Exception:
                data = {}
        r.finish("ok", {"info": data})
    except Exception as e:
        _error(f"info failed: {e}")
        r.finish("error", {"error": str(e)})
    if json_out:
        print(json.dumps(asdict(r), indent=2))
    else:
        if not quiet:
            print(json.dumps(r.details, indent=2))
    return r

def main(argv: Optional[List[str]] = None):
    # parse CLI
    parser = argparse.ArgumentParser(prog="newpkg", description="newpkg unified CLI")
    parser.add_argument("cmd", choices=["install","remove","upgrade","sync","audit","build","package","info"], help="command")
    parser.add_argument("--pkg", help="package name")
    parser.add_argument("--metafile", help="metafile path (toml/json) to use")
    parser.add_argument("--destdir", help="destination dir (for install/package)")
    parser.add_argument("--jobs", type=int, default=DEFAULT_JOBS, help="parallel jobs or threads")
    parser.add_argument("--dry-run", action="store_true", help="do not perform destructive actions")
    parser.add_argument("--quiet", action="store_true", help="minimal output")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument("--no-color", action="store_true", help="disable color output")
    parser.add_argument("--sandbox", dest="use_sandbox", action="store_true", help="use sandbox if configured")
    parser.add_argument("--no-sandbox", dest="use_sandbox", action="store_false", help="do not use sandbox")
    parser.add_argument("--purge", action="store_true", help="(remove) purge configs and caches")
    parser.add_argument("--simulate", action="store_true", help="(remove) simulate removal")
    parser.add_argument("--force", action="store_true", help="(upgrade) force upgrade")
    parser.add_argument("--include-unmanaged", action="store_true", help="(audit) scan filesystem for unmanaged binaries")
    parser.add_argument("--severity", type=float, help="(audit) minimum severity threshold")
    parser.add_argument("--format", choices=["text","json","markdown"], default="text", help="(audit) report format")
    args = parser.parse_args(argv)

    # config
    cfg = None
    if init_config:
        try:
            cfg = init_config()
        except Exception:
            cfg = None

    init_components(cfg, use_sandbox=getattr(args, "use_sandbox", True), quiet=args.quiet)

    # decide UI settings
    if args.no_color and _HAS_RICH and console:
        console.force_terminal = False

    json_out = args.json
    quiet = args.quiet
    dry_run = args.dry_run
    jobs = args.jobs

    # dispatch commands
    cmd = args.cmd
    if cmd == "install":
        if not args.pkg:
            parser.error("--pkg required for install")
        return _dispatch_install(args.pkg, metafile=args.metafile, destdir=args.destdir, jobs=jobs, dry_run=dry_run, quiet=quiet, use_sandbox=args.use_sandbox, json_out=json_out)

    if cmd == "remove":
        if not args.pkg:
            parser.error("--pkg required for remove")
        return _dispatch_remove(args.pkg, purge=args.purge, simulate=args.simulate, quiet=quiet, json_out=json_out)

    if cmd == "upgrade":
        if not args.pkg:
            parser.error("--pkg required for upgrade")
        return _dispatch_upgrade(args.pkg, force=args.force, dry_run=dry_run, quiet=quiet, json_out=json_out)

    if cmd == "sync":
        # optionally read names from NEWPKG_SYNC_REPOS env or use all configured
        names = None
        if os.environ.get("NEWPKG_SYNC_REPOS"):
            names = [n.strip() for n in os.environ.get("NEWPKG_SYNC_REPOS").split(",") if n.strip()]
        return _dispatch_sync(names=names, parallel=jobs, dry_run=dry_run, quiet=quiet, json_out=json_out)

    if cmd == "audit":
        return _dispatch_audit(include_unmanaged=args.include_unmanaged, severity=args.severity, dry_run=dry_run, quiet=quiet, json_out=json_out, fmt=args.format)

    if cmd == "build":
        if not args.pkg:
            parser.error("--pkg required for build")
        return _dispatch_build(args.pkg, metafile=args.metafile, workdir=None, dry_run=dry_run, quiet=quiet, json_out=json_out)

    if cmd == "package":
        if not args.pkg:
            parser.error("--pkg required for package")
        return _dispatch_package(args.pkg, destdir=args.destdir, version=None, dry_run=dry_run, quiet=quiet, json_out=json_out)

    if cmd == "info":
        return _dispatch_info(args.pkg, quiet=quiet, json_out=json_out)

    parser.print_help()
    return 1

if __name__ == "__main__":
    main()
