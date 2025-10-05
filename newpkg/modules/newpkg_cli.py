#!/usr/bin/env python3
# newpkg_cli.py
"""
Unified CLI for newpkg — integrates modules and provides user-friendly commands,
short aliases, color/progress UI (uses rich when available), logging, JSON output,
and reports.

Short aliases:
 - -i / i      -> install
 - -r / rm     -> remove
 - -u / up     -> upgrade
 - -s / sync   -> sync repositories
 - -a / audit  -> audit
 - -b / build  -> build
 - -p / package-> package
 - -d / deps   -> resolve deps
 - -n / --dry-run -> simulate
"""

from __future__ import annotations

import json
import os
import sys
import time
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional integrations (best-effort imports)
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
    from newpkg_core import NewpkgCore
except Exception:
    NewpkgCore = None

try:
    from newpkg_upgrade import NewpkgUpgrade
except Exception:
    NewpkgUpgrade = None

try:
    from newpkg_remove import NewpkgRemove
except Exception:
    NewpkgRemove = None

try:
    from newpkg_sync import NewpkgSync
except Exception:
    NewpkgSync = None

try:
    from newpkg_audit import NewpkgAudit
except Exception:
    NewpkgAudit = None

try:
    from newpkg_deps import NewpkgDeps
except Exception:
    NewpkgDeps = None

try:
    from newpkg_metafile import NewpkgMetafile
except Exception:
    NewpkgMetafile = None

# Optional UI: rich
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False
    console = None

# Fallback stdlib logger (used only if newpkg_logger not present)
import logging
_logger = logging.getLogger("newpkg.cli")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.cli: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


REPORT_DIR_DEFAULT = "/var/log/newpkg/cli"


@dataclass
class CLIReport:
    cmd: str
    ts: int
    duration: float
    status: str
    details: Dict[str, Any]

    def to_dict(self):
        return asdict(self)


class NewpkgCLI:
    def __init__(self, cfg: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)

        # logger instance
        try:
            self.logger = NewpkgLogger.from_config(self.cfg, NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None) if NewpkgLogger and self.cfg else None
        except Exception:
            self.logger = None

        # DB
        try:
            self.db = NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None
        except Exception:
            self.db = None

        # command modules (initialized lazily)
        self._core = None
        self._upgrade = None
        self._remove = None
        self._sync = None
        self._audit = None
        self._deps = None
        self._metafile = None

        # global flags defaults (read from config)
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))
        self.use_sandbox = bool(self._cfg_get("general.use_sandbox", True))
        cpu = os.cpu_count() or 1
        self.jobs = int(self._cfg_get("core.jobs", max(1, min(4, cpu))))
        self.report_dir = Path(self._cfg_get("cli.report_dir", REPORT_DIR_DEFAULT))
        self.report_dir.mkdir(parents=True, exist_ok=True)

        # UI
        self.rich = RICH_AVAILABLE and bool(self._cfg_get("output.use_rich", True))
        # ensure consistent with quiet/json
        if self.json_out:
            self.rich = False

        # wrapper log function
        self._log = self._make_logger()

    # ---- helpers ----
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
        def fn(level: str, event: str, msg: str = "", **meta):
            try:
                if self.logger:
                    method = getattr(self.logger, level.lower(), None)
                    if method:
                        method(event, msg, **meta)
                        return
            except Exception:
                pass
            getattr(_logger, level.lower(), _logger.info)(f"{event}: {msg} - {meta}")
        return fn

    # lazy module getters
    @property
    def core(self):
        if self._core is None:
            try:
                self._core = NewpkgCore(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=None)
            except Exception:
                self._core = None
        return self._core

    @property
    def upgrade(self):
        if self._upgrade is None:
            try:
                self._upgrade = NewpkgUpgrade(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=None)
            except Exception:
                self._upgrade = None
        return self._upgrade

    @property
    def remover(self):
        if self._remove is None:
            try:
                self._remove = NewpkgRemove(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=None)
            except Exception:
                self._remove = None
        return self._remove

    @property
    def syncer(self):
        if self._sync is None:
            try:
                self._sync = NewpkgSync(cfg=self.cfg, logger=self.logger, db=self.db, hooks=None, sandbox=None)
            except Exception:
                self._sync = None
        return self._sync

    @property
    def auditer(self):
        if self._audit is None:
            try:
                self._audit = NewpkgAudit(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=None)
            except Exception:
                self._audit = None
        return self._audit

    @property
    def deps(self):
        if self._deps is None:
            try:
                self._deps = NewpkgDeps(cfg=self.cfg, logger=self.logger, db=self.db)
            except Exception:
                self._deps = None
        return self._deps

    @property
    def metafile(self):
        if self._metafile is None:
            try:
                self._metafile = NewpkgMetafile(cfg=self.cfg, logger=self.logger, db=self.db)
            except Exception:
                self._metafile = None
        return self._metafile

    # output helpers
    def _print(self, *args, **kwargs):
        if self.quiet:
            return
        if self.rich and console:
            console.print(*args, **kwargs)
        else:
            print(*args, **kwargs)

    def _progress_context(self, description: str):
        if self.rich and console:
            p = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn(), TimeRemainingColumn())
            return p, p.add_task(description, total=None)
        else:
            # fallback context manager that yields a simple object
            class Dummy:
                def __enter__(self_inner):
                    if not self.quiet:
                        print(description + " ...")
                    return None, None

                def __exit__(self_inner, exc_type, exc_val, exc_tb):
                    return False
            return Dummy()

    def _save_report(self, cmd: str, status: str, details: Dict[str, Any]) -> Path:
        ts = int(time.time())
        rpt = CLIReport(cmd=cmd, ts=ts, duration=details.get("duration", 0.0), status=status, details=details)
        fname = f"cli-{cmd.replace(' ', '_')}-{ts}.json"
        p = self.report_dir / fname
        try:
            p.write_text(json.dumps(rpt.to_dict(), indent=2), encoding="utf-8")
            self._log("info", "cli.report.write", f"Wrote CLI report to {p}", path=str(p))
        except Exception:
            pass
        return p

    # ---- command implementations (high-level wrappers) ----
    def cmd_install(self, metafile_path: str, install_full: bool = True, dest: Optional[str] = None, fakeroot: bool = True, jobs: Optional[int] = None) -> Dict[str, Any]:
        start = time.time()
        jobs = jobs or self.jobs
        if not self.metafile:
            self._log("error", "cli.install.nometa", "Metafile handler not available")
            return {"ok": False, "error": "no_metafile_module"}
        # process metafile (downloads, patches)
        try:
            res = self.metafile.process([metafile_path], workdir=None, download_profile=None, apply_patches=True)
        except Exception as e:
            self._log("error", "cli.install.metaprocess", f"Failed processing metafile: {e}", error=str(e))
            return {"ok": False, "error": "metafile_process_failed", "exc": str(e)}
        # if install_full, run core pipeline: prepare/build/install/package/deploy depending on metafile
        if install_full and self.core:
            try:
                # determine stagedir and run core.install etc.
                workdir = res.get("workdir") if isinstance(res, dict) else None
                # run configure/build/install via core
                conf_cmd = res.get("configure_cmd") if isinstance(res, dict) else None
                make_cmd = res.get("make_cmd") if isinstance(res, dict) else None
                if conf_cmd:
                    self._print(f"Running configure: {conf_cmd}")
                    _ = self.core.configure(source_dir=workdir or ".", configure_cmd=conf_cmd)
                if make_cmd:
                    self._print(f"Running build: {make_cmd}")
                    _ = self.core.build(source_dir=workdir or ".", make_cmd=make_cmd)
                inst = self.core.install(source_dir=workdir or ".", destdir=dest, use_fakeroot=fakeroot, use_root_dir=False)
                duration = time.time() - start
                details = {"metafile": metafile_path, "install": inst}
                self._save_report(f"install {metafile_path}", "ok", {"duration": duration, "details": details})
                return {"ok": True, "details": details}
            except Exception as e:
                duration = time.time() - start
                self._save_report(f"install {metafile_path}", "error", {"duration": duration, "error": str(e)})
                return {"ok": False, "error": str(e)}
        else:
            # just prepared, return metadata
            duration = time.time() - start
            details = {"metafile": metafile_path, "prepared": res}
            self._save_report(f"install {metafile_path}", "ok", {"duration": duration, "details": details})
            return {"ok": True, "details": details}

    def cmd_remove(self, package: str, confirm: bool = False, purge: bool = False) -> Dict[str, Any]:
        start = time.time()
        if not self.remover:
            self._log("error", "cli.remove.nomodule", "Remove module not available")
            return {"ok": False, "error": "no_remove_module"}
        res = self.remover.execute_removal(package, confirm=confirm, purge=purge, use_sandbox=self.use_sandbox)
        duration = time.time() - start
        self._save_report(f"remove {package}", "ok" if res.get("ok") else "error", {"duration": duration, "result": res})
        return res

    def cmd_upgrade(self, packages: List[Tuple[str, Optional[str]]], parallel: Optional[int] = None) -> Dict[str, Any]:
        start = time.time()
        if not self.upgrade:
            self._log("error", "cli.upgrade.nomodule", "Upgrade module not available")
            return {"ok": False, "error": "no_upgrade_module"}
        res = self.upgrade.upgrade(packages, parallel=parallel or self.jobs, use_sandbox=self.use_sandbox)
        duration = time.time() - start
        self._save_report("upgrade", "ok", {"duration": duration, "result": res})
        return res

    def cmd_sync(self, names: Optional[List[str]] = None, parallel: Optional[int] = None) -> Dict[str, Any]:
        start = time.time()
        if not self.syncer:
            self._log("error", "cli.sync.nomodule", "Sync module not available")
            return {"ok": False, "error": "no_sync_module"}
        res = self.syncer.sync_all(names, update=True, use_sandbox=self.use_sandbox, parallel=parallel or self.jobs)
        duration = time.time() - start
        self._save_report("sync", "ok", {"duration": duration, "result": res})
        return res

    def cmd_audit(self, packages: Optional[List[str]] = None, execute: bool = False, confirm: bool = False) -> Dict[str, Any]:
        start = time.time()
        if not self.auditer:
            self._log("error", "cli.audit.nomodule", "Audit module not available")
            return {"ok": False, "error": "no_audit_module"}
        findings = self.auditer.scan(packages)
        plan = self.auditer.plan(findings)
        executed = []
        if execute:
            executed = self.auditer.execute_plan(plan, confirm=confirm, parallel=self.jobs, use_sandbox=self.use_sandbox)
        duration = time.time() - start
        report = {"findings": [f.to_dict() for f in findings], "plan": [p.to_dict() for p in plan], "executed": executed}
        self._save_report("audit", "ok", {"duration": duration, "report": report})
        return {"ok": True, "report": report}

    def cmd_deps(self, package: str, action: str = "resolve", dep_type: str = "all") -> Dict[str, Any]:
        start = time.time()
        if not self.deps:
            self._log("error", "cli.deps.nomodule", "Deps module not available")
            return {"ok": False, "error": "no_deps_module"}
        if action == "resolve":
            res = self.deps.resolve(package, dep_type=dep_type)
            out = res.to_dict()
        elif action == "missing":
            out = self.deps.check_missing(package, dep_type=dep_type)
        elif action == "graph":
            result = self.deps.graph(package, dep_type=dep_type, format="json")
            out = result
        else:
            out = {"error": "unknown_action"}
        duration = time.time() - start
        self._save_report(f"deps {package}", "ok", {"duration": duration, "result": out})
        return {"ok": True, "result": out}

    # ---- convenience / aliases ----
    def alias_dispatch(self, argv: List[str]):
        """
        Support quick aliases:
         - i <metafile>  -> install
         - rm <pkg>      -> remove
         - up <pkg>      -> upgrade
         - s             -> sync
         - a             -> audit
         - b <metafile>  -> build (install --package)
        """
        if not argv:
            self.print_help()
            return

        cmd = argv[0]
        rest = argv[1:]

        # map short commands to argparse style
        if cmd in ("i", "install", "-i", "--install"):
            if not rest:
                print("usage: newpkg i <metafile>")
                sys.exit(2)
            mf = rest[0]
            res = self.cmd_install(mf, install_full=True)
            self._emit_result(res)
            return
        if cmd in ("rm", "remove", "-r", "--remove"):
            if not rest:
                print("usage: newpkg rm <package>")
                sys.exit(2)
            pkg = rest[0]
            res = self.cmd_remove(pkg, confirm=True)
            self._emit_result(res)
            return
        if cmd in ("up", "upgrade", "-u", "--upgrade"):
            if not rest:
                print("usage: newpkg up <pkg> or newpkg up --all")
                sys.exit(2)
            # support comma-separated list or single name
            pkgs = []
            for it in rest:
                if it == "--all":
                    if self.db:
                        pkgs = [(p.get("name"), None) for p in (self.db.list_packages() or [])]
                        break
                if "=" in it:
                    name, mf = it.split("=", 1)
                    pkgs.append((name, mf))
                else:
                    pkgs.append((it, None))
            res = self.cmd_upgrade(pkgs)
            self._emit_result(res)
            return
        if cmd in ("s", "sync", "-s", "--sync"):
            res = self.cmd_sync()
            self._emit_result(res)
            return
        if cmd in ("a", "audit", "-a", "--audit"):
            res = self.cmd_audit()
            self._emit_result(res)
            return

        # unknown alias: fallback to help
        self.print_help()
        return

    # ---- output formatting and finalization ----
    def _emit_result(self, res: Dict[str, Any]):
        if self.json_out:
            print(json.dumps(res, indent=2))
            return
        # human readable
        if isinstance(res, dict) and res.get("ok") is False:
            self._print("[red]ERROR[/red] " + str(res.get("error", "<unknown>")))
            return
        # pretty print summary
        if self.rich and console:
            console.rule("[bold cyan]newpkg result")
            console.print(json.dumps(res, indent=2))
            console.rule()
        else:
            print("Result:")
            print(json.dumps(res, indent=2))

    def print_help(self):
        help_text = """
newpkg — package build & management

Quick aliases:
  i <metafile>       install (short)
  rm <package>       remove (short)
  up <pkg>           upgrade (short)
  s                  sync repos
  a                  audit
  b <metafile>       build only
Use --help for full options.
"""
        print(help_text)

    # ---- entrypoint: argument parsing and dispatch ----
    def main(self, argv: Optional[List[str]] = None):
        argv = argv if argv is not None else sys.argv[1:]

        # quick alias detection: if first token is a short alias, use alias_dispatch
        if argv and argv[0] in ("i", "rm", "up", "s", "a", "b"):
            self.alias_dispatch(argv)
            return

        parser = ArgumentParser(prog="newpkg", description="newpkg CLI — build and manage LFS/BLFS components", formatter_class=RawDescriptionHelpFormatter)
        # global flags
        parser.add_argument("-n", "--dry-run", action="store_true", help="simulate (dry-run)")
        parser.add_argument("-q", "--quiet", action="store_true", help="quiet mode")
        parser.add_argument("-j", "--json", action="store_true", help="JSON output")
        parser.add_argument("--no-sandbox", action="store_true", help="disable sandbox usage")
        parser.add_argument("-J", "--jobs", type=int, help="override parallel jobs")
        parser.add_argument("-c", "--config", help="use alternate config file (path)")  # loading not implemented here; pass-through
        # subcommands as flags to keep one-file interface
        parser.add_argument("-i", "--install", metavar="METAFILE", help="install from metafile (metafile path)")
        parser.add_argument("-r", "--remove", metavar="PACKAGE", help="remove package")
        parser.add_argument("-u", "--upgrade", nargs="*", metavar="PKG", help="upgrade packages (provide names or name=metafile)")
        parser.add_argument("-s", "--sync", nargs="*", metavar="NAME", help="sync repositories (names optional)")
        parser.add_argument("-a", "--audit", nargs="*", metavar="PKG", help="audit packages (optional list)")
        parser.add_argument("-b", "--build", metavar="METAFILE", help="build from metafile (no install)")
        parser.add_argument("-p", "--package", metavar="DIR", help="package a staged directory")
        parser.add_argument("-d", "--deps", nargs=2, metavar=("PKG", "ACTION"), help="dependency actions: resolve|missing|graph")
        parser.add_argument("--report-dir", help="override report dir for this run")
        args = parser.parse_args(argv)

        # override global runtime flags
        if args.dry_run:
            self.dry_run = True
        if args.quiet:
            self.quiet = True
        if args.json:
            self.json_out = True
        if args.no_sandbox:
            self.use_sandbox = False
        if args.jobs:
            self.jobs = args.jobs
        if args.report_dir:
            self.report_dir = Path(args.report_dir)

        # initialize modules according to current flags
        # pass config, logger and db so modules can respect same config
        # Note: modules themselves will initialize their own sandbox if needed.
        # Dispatch commands in priority order
        start = time.time()
        status = "ok"
        details: Dict[str, Any] = {}

        try:
            if args.install:
                res = self.cmd_install(args.install, install_full=True)
                details = res
                self._emit_result(res)
            elif args.build:
                # build only: process metafile then run core.build
                if not self.metafile:
                    raise RuntimeError("metafile module not available")
                prep = self.metafile.process([args.build], workdir=None, download_profile=None, apply_patches=True)
                workdir = prep.get("workdir") if isinstance(prep, dict) else None
                if not self.core:
                    raise RuntimeError("core module not available")
                build_res = self.core.build(source_dir=workdir or ".", make_cmd=None)
                details = {"build": build_res}
                self._emit_result({"ok": build_res.get("rc", 1) == 0, "details": details})
            elif args.remove:
                res = self.cmd_remove(args.remove, confirm=True)
                details = res
                self._emit_result(res)
            elif args.upgrade is not None:
                # if empty list => no args but flag present, treat as error or upgrade all?
                pkgs_arg = args.upgrade or []
                pkgs = []
                if not pkgs_arg:
                    # upgrade all if DB present
                    if self.db:
                        pkgs = [(p.get("name"), None) for p in (self.db.list_packages() or [])]
                    else:
                        raise RuntimeError("No packages specified and DB not available")
                else:
                    for it in pkgs_arg:
                        if "=" in it:
                            name, mf = it.split("=", 1)
                            pkgs.append((name, mf))
                        else:
                            pkgs.append((it, None))
                res = self.cmd_upgrade(pkgs, parallel=self.jobs)
                details = res
                self._emit_result(res)
            elif args.sync is not None:
                names = args.sync if args.sync else None
                res = self.cmd_sync(names, parallel=self.jobs)
                details = res
                self._emit_result(res)
            elif args.audit is not None:
                pkgs = args.audit if args.audit else None
                res = self.cmd_audit(packages=pkgs, execute=False)
                details = res
                self._emit_result(res)
            elif args.deps:
                pkg, action = args.deps
                res = self.cmd_deps(pkg, action)
                details = res
                self._emit_result(res)
            elif args.package:
                # package a staged dir via core.package
                if not self.core:
                    raise RuntimeError("core module not available")
                meta = {"name": Path(args.package).name, "version": "0"}
                res = self.core.package(args.package, meta)
                details = res
                self._emit_result(res)
            else:
                # nothing specified -> show help summary
                self.print_help()
                status = "noop"
        except Exception as e:
            status = "error"
            details = {"error": str(e)}
            self._log("error", "cli.run.exception", f"Exception in CLI: {e}", error=str(e))
            if self.json_out:
                print(json.dumps({"ok": False, "error": str(e)}, indent=2))
            else:
                print("ERROR:", str(e))

        duration = time.time() - start
        # save report
        try:
            rep = self._save_report(" ".join(argv) or "help", status, {"duration": duration, "details": details})
            if not self.quiet and not self.json_out:
                self._print(f"Report saved to: {rep}")
        except Exception:
            pass

# Entrypoint
def main():
    cfg = init_config() if init_config else None
    cli = NewpkgCLI(cfg=cfg)
    cli.main()

if __name__ == "__main__":
    main()
