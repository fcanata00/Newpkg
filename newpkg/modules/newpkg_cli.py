#!/usr/bin/env python3
# newpkg_cli.py — revised, integrates newpkg_api autodiscovery and all aliases
"""
Unified CLI for newpkg — autodetects modules (via newpkg_api), supports aliases and subcommands,
uses rich for progress/UI when available, respects newpkg_config flags (dry-run, quiet, json).
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

# attempt to make newpkg_api importable even if this file is inside newpkg/modules/
try:
    # ensure parent package directory is on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[1]))
    from newpkg_api import load_all_modules  # type: ignore
    _HAS_API = True
except Exception:
    _HAS_API = False

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

# fallback stdlib logger (used only if newpkg_logger not present)
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
        # config
        self.cfg = cfg or (init_config() if init_config else None)

        # logger
        try:
            self.logger = NewpkgLogger.from_config(self.cfg, NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None) if NewpkgLogger and self.cfg else None
        except Exception:
            self.logger = None

        # db
        try:
            self.db = NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None
        except Exception:
            self.db = None

        # lazy-initialized modules dict (plugins & instantiated handlers)
        self.modules: Dict[str, Any] = {}

        # global flags default values from config
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
        if self.json_out:
            self.rich = False
        if self.quiet:
            self.rich = False

        # prepare module handlers (lazily)
        self._core = None
        self._upgrade = None
        self._remove = None
        self._sync = None
        self._audit = None
        self._deps = None
        self._metafile = None

        # attempt to auto-load modules via newpkg_api (if available)
        if _HAS_API:
            try:
                start = time.time()
                infos = load_all_modules(self, cfg=self.cfg, logger=self.logger, db=self.db)
                loaded = []
                for info in infos:
                    # skip CLI file itself to avoid self-registration loops
                    try:
                        caller_name = Path(__file__).name
                        if Path(info.path).name == caller_name:
                            continue
                    except Exception:
                        pass
                    loaded.append(Path(info.path).stem)
                self.modules_list = loaded
                # display or log modules loaded
                if self.json_out or (self.cfg and bool(self.cfg.get("output.json", False))):
                    # save JSON metadata into a small report
                    meta = {"modules": loaded, "count": len(loaded), "duration": round(time.time() - start, 3)}
                    self._save_report("modules_loaded", "ok", {"meta": meta})
                else:
                    if not self.quiet:
                        if self.rich and console:
                            console.print(f"[bold cyan]Módulos carregados automaticamente:[/bold cyan] {', '.join(loaded) or '(none)'}")
                        else:
                            print("Módulos carregados:", ", ".join(loaded) or "(none)")
            except Exception as e:
                self._log("warning", "cli.autoload.fail", f"Auto-load modules failed: {e}", error=str(e))
        else:
            # not available — ok
            self.modules_list = []

    # --- helpers ---
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

    def _log(self, level: str, event: str, msg: str = "", **meta):
        try:
            if self.logger:
                meth = getattr(self.logger, level.lower(), None)
                if meth:
                    meth(event, msg, **meta)
                    return
        except Exception:
            pass
        getattr(_logger, level.lower(), _logger.info)(f"{event}: {msg} - {meta}")

    def _print(self, *args, **kwargs):
        if self.quiet:
            return
        if self.rich and console:
            console.print(*args, **kwargs)
        else:
            print(*args, **kwargs)

    def _progress(self, description: str):
        if self.rich and console:
            p = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn(), TimeRemainingColumn())
            return p, p.add_task(description, total=None)
        else:
            # fallback dummy context manager
            class Dummy:
                def __enter__(self_in):
                    if not self.quiet:
                        print(description + " ...")
                    return None, None

                def __exit__(self_in, exc_type, exc_val, exc_tb):
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

    # --- lazy module properties (instantiate when first used) ---
    @property
    def core(self):
        if self._core is None:
            try:
                self._core = NewpkgCore(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=None) if NewpkgCore and self.cfg else None
            except Exception:
                self._core = None
        return self._core

    @property
    def upgrade(self):
        if self._upgrade is None:
            try:
                self._upgrade = NewpkgUpgrade(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=None) if NewpkgUpgrade and self.cfg else None
            except Exception:
                self._upgrade = None
        return self._upgrade

    @property
    def remover(self):
        if self._remove is None:
            try:
                self._remove = NewpkgRemove(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=None) if NewpkgRemove and self.cfg else None
            except Exception:
                self._remove = None
        return self._remove

    @property
    def syncer(self):
        if self._sync is None:
            try:
                self._sync = NewpkgSync(cfg=self.cfg, logger=self.logger, db=self.db, hooks=None, sandbox=None) if NewpkgSync and self.cfg else None
            except Exception:
                self._sync = None
        return self._sync

    @property
    def auditer(self):
        if self._audit is None:
            try:
                self._audit = NewpkgAudit(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=None) if NewpkgAudit and self.cfg else None
            except Exception:
                self._audit = None
        return self._audit

    @property
    def deps(self):
        if self._deps is None:
            try:
                self._deps = NewpkgDeps(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgDeps and self.cfg else None
            except Exception:
                self._deps = None
        return self._deps

    @property
    def metafile(self):
        if self._metafile is None:
            try:
                self._metafile = NewpkgMetafile(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgMetafile and self.cfg else None
            except Exception:
                self._metafile = None
        return self._metafile

    # --- command implementations ---
    def cmd_install(self, metafile_path: str, install_full: bool = True, dest: Optional[str] = None, fakeroot: bool = True, jobs: Optional[int] = None) -> Dict[str, Any]:
        start = time.time()
        jobs = jobs or self.jobs
        if not self.metafile:
            self._log("error", "cli.install.nometa", "Metafile handler not available")
            return {"ok": False, "error": "no_metafile_module"}
        try:
            # process metafile (download & patches)
            proc_res = self.metafile.process([metafile_path], workdir=None, download_profile=None, apply_patches=True)
        except Exception as e:
            self._log("error", "cli.install.metaprocess", f"Failed processing metafile: {e}", error=str(e))
            return {"ok": False, "error": "metafile_process_failed", "exc": str(e)}

        if install_full and self.core:
            try:
                workdir = proc_res.get("workdir") if isinstance(proc_res, dict) else None
                configure_cmd = proc_res.get("configure_cmd") if isinstance(proc_res, dict) else None
                make_cmd = proc_res.get("make_cmd") if isinstance(proc_res, dict) else None
                if configure_cmd:
                    self._print(f">>>> Preparando configuração: {metafile_path} <<<<")
                    self.core.configure(source_dir=workdir or ".", configure_cmd=configure_cmd)
                if make_cmd:
                    self._print(f">>>> Construindo: {metafile_path} <<<<")
                    self.core.build(source_dir=workdir or ".", make_cmd=make_cmd)
                inst = self.core.install(source_dir=workdir or ".", destdir=dest, use_fakeroot=fakeroot, use_root_dir=False)
                dur = time.time() - start
                details = {"metafile": metafile_path, "install": inst}
                self._save_report(f"install {metafile_path}", "ok", {"duration": dur, "details": details})
                return {"ok": True, "details": details}
            except Exception as e:
                dur = time.time() - start
                self._save_report(f"install {metafile_path}", "error", {"duration": dur, "error": str(e)})
                return {"ok": False, "error": str(e)}
        else:
            dur = time.time() - start
            details = {"metafile": metafile_path, "prepared": proc_res}
            self._save_report(f"install {metafile_path}", "ok", {"duration": dur, "details": details})
            return {"ok": True, "details": details}

    def cmd_remove(self, package: str, confirm: bool = False, purge: bool = False) -> Dict[str, Any]:
        start = time.time()
        if not self.remover:
            self._log("error", "cli.remove.nomodule", "Remove module not available")
            return {"ok": False, "error": "no_remove_module"}
        res = self.remover.execute_removal(package, confirm=confirm, purge=purge, use_sandbox=self.use_sandbox)
        dur = time.time() - start
        self._save_report(f"remove {package}", "ok" if res.get("ok") else "error", {"duration": dur, "result": res})
        return res

    def cmd_upgrade(self, packages: List[Tuple[str, Optional[str]]], parallel: Optional[int] = None) -> Dict[str, Any]:
        start = time.time()
        if not self.upgrade:
            self._log("error", "cli.upgrade.nomodule", "Upgrade module not available")
            return {"ok": False, "error": "no_upgrade_module"}
        res = self.upgrade.upgrade(packages, parallel=parallel or self.jobs, use_sandbox=self.use_sandbox)
        dur = time.time() - start
        self._save_report("upgrade", "ok", {"duration": dur, "result": res})
        return res

    def cmd_sync(self, names: Optional[List[str]] = None, parallel: Optional[int] = None) -> Dict[str, Any]:
        start = time.time()
        if not self.syncer:
            self._log("error", "cli.sync.nomodule", "Sync module not available")
            return {"ok": False, "error": "no_sync_module"}
        res = self.syncer.sync_all(names, update=True, use_sandbox=self.use_sandbox, parallel=parallel or self.jobs)
        dur = time.time() - start
        self._save_report("sync", "ok", {"duration": dur, "result": res})
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
        dur = time.time() - start
        report = {"findings": [f.to_dict() for f in findings], "plan": [p.to_dict() for p in plan], "executed": executed}
        self._save_report("audit", "ok", {"duration": dur, "report": report})
        return {"ok": True, "report": report}

    def cmd_deps(self, package: str, action: str = "resolve", dep_type: str = "all") -> Dict[str, Any]:
        start = time.time()
        if not self.deps:
            self._log("error", "cli.deps.nomodule", "Deps module not available")
            return {"ok": False, "error": "no_deps_module"}
        if action == "resolve":
            res = self.deps.resolve(package, dep_type=dep_type)
            out = res.to_dict() if hasattr(res, "to_dict") else res
        elif action == "missing":
            out = self.deps.check_missing(package, dep_type=dep_type)
        elif action == "graph":
            result = self.deps.graph(package, dep_type=dep_type, format="json")
            out = result
        else:
            out = {"error": "unknown_action"}
        dur = time.time() - start
        self._save_report(f"deps {package}", "ok", {"duration": dur, "result": out})
        return {"ok": True, "result": out}

    # ---- aliases / subcommand shortcuts ----
    def alias_dispatch(self, argv: List[str]):
        if not argv:
            self.print_help()
            return

        cmd = argv[0]
        rest = argv[1:]

        # install
        if cmd in ("i", "install", "-i", "--install"):
            if not rest:
                print("usage: newpkg i <metafile>")
                sys.exit(2)
            mf = rest[0]
            res = self.cmd_install(mf, install_full=True)
            self._emit_result(res)
            return

        # remove
        if cmd in ("rm", "remove", "-r", "--remove"):
            if not rest:
                print("usage: newpkg rm <package>")
                sys.exit(2)
            pkg = rest[0]
            res = self.cmd_remove(pkg, confirm=True)
            self._emit_result(res)
            return

        # upgrade
        if cmd in ("up", "upgrade", "-u", "--upgrade"):
            if not rest:
                print("usage: newpkg up <pkg> or newpkg up --all")
                sys.exit(2)
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

        # sync
        if cmd in ("s", "sync", "-s", "--sync"):
            res = self.cmd_sync()
            self._emit_result(res)
            return

        # audit
        if cmd in ("a", "audit", "-a", "--audit"):
            res = self.cmd_audit()
            self._emit_result(res)
            return

        # build
        if cmd in ("b", "build", "-b", "--build"):
            if not rest:
                print("usage: newpkg b <metafile>")
                sys.exit(2)
            mf = rest[0]
            if not self.metafile:
                print("no metafile module")
                sys.exit(2)
            prep = self.metafile.process([mf], workdir=None, download_profile=None, apply_patches=True)
            workdir = prep.get("workdir") if isinstance(prep, dict) else None
            if not self.core:
                print("no core module")
                sys.exit(2)
            build_res = self.core.build(source_dir=workdir or ".", make_cmd=None)
            self._emit_result({"ok": build_res.get("rc", 1) == 0, "details": {"build": build_res}})
            return

        # fallback help
        self.print_help()
        return

    # --- output helpers ---
    def _emit_result(self, res: Dict[str, Any]):
        if self.json_out:
            print(json.dumps(res, indent=2))
            return
        if isinstance(res, dict) and res.get("ok") is False:
            self._print(f"[red]ERROR[/red] {res.get('error','<unknown>')}")
            return
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

Short aliases:
  i <metafile>       install
  rm <package>       remove
  up <pkg>           upgrade
  s                  sync
  a                  audit
  b <metafile>       build only
Full flags:
  -i/--install METAFILE
  -r/--remove PACKAGE
  -u/--upgrade PKG...
  -s/--sync [NAMES...]
  -a/--audit [PKG...]
Global flags:
  -n/--dry-run  -q/--quiet  -j/--json  --no-sandbox  -J/--jobs
"""
        print(help_text)

    # ---- main entrypoint: argparse & dispatch ----
    def main(self, argv: Optional[List[str]] = None):
        argv = argv if argv is not None else sys.argv[1:]

        # quick alias detection: if first token is a short alias, do alias_dispatch
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
        parser.add_argument("-c", "--config", help="use alternate config file (path)")
        # subcommands as flags (short + long)
        parser.add_argument("-i", "--install", metavar="METAFILE", help="install from metafile")
        parser.add_argument("-r", "--remove", metavar="PACKAGE", help="remove package")
        parser.add_argument("-u", "--upgrade", nargs="*", metavar="PKG", help="upgrade packages (name or name=metafile)")
        parser.add_argument("-s", "--sync", nargs="*", metavar="NAME", help="sync repositories")
        parser.add_argument("-a", "--audit", nargs="*", metavar="PKG", help="audit packages")
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

        start = time.time()
        status = "ok"
        details: Dict[str, Any] = {}

        try:
            if args.install:
                res = self.cmd_install(args.install, install_full=True)
                details = res
                self._emit_result(res)
            elif args.build:
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
                pkgs_arg = args.upgrade or []
                pkgs = []
                if not pkgs_arg:
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
                if not self.core:
                    raise RuntimeError("core module not available")
                meta = {"name": Path(args.package).name, "version": "0"}
                res = self.core.package(args.package, meta)
                details = res
                self._emit_result(res)
            else:
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
