#!/usr/bin/env python3
# newpkg_cli.py
"""
newpkg CLI — revised integration

Features:
 - single CLI front-end integrating all newpkg modules
 - abbreviations and aliases (short + long)
 - --install / -i, --remove / -r (alias rm), --upgrade / -u (alias up), --sync / -s, --audit / -a
 - --bootstrap mode: sync -> resolve deps -> build -> package -> install
 - --quiet, --json, --dry-run, --jobs, --profile
 - hooks: pre_command / post_command
 - uses newpkg_api.call(command, args) if available (best-effort)
 - progress UI via logger.progress() (Rich when available), falls back to simple prints
 - consolidated JSON report saved in report_dir
 - audit.scan() after install/remove/upgrade when available
 - graceful degradation when optional modules are missing
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import shlex
import shutil
import sys
import tempfile
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try to import optional helpers (best-effort)
try:
    from newpkg_config import init_config  # type: ignore
except Exception:
    init_config = None

try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

# module getters (best-effort)
try:
    from newpkg_upgrade import get_upgrade  # type: ignore
except Exception:
    get_upgrade = None

try:
    from newpkg_remove import get_remove  # type: ignore
except Exception:
    get_remove = None

try:
    from newpkg_sync import get_sync  # type: ignore
except Exception:
    get_sync = None

try:
    from newpkg_deps import get_deps  # type: ignore
except Exception:
    get_deps = None

try:
    from newpkg_core import get_core  # type: ignore
except Exception:
    get_core = None

try:
    from newpkg_metafile import get_metafile_manager  # type: ignore
except Exception:
    get_metafile_manager = None

try:
    from newpkg_audit import get_audit  # type: ignore
except Exception:
    get_audit = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

# optional API layer
try:
    import newpkg_api as newpkg_api_module  # type: ignore
    get_api = getattr(newpkg_api_module, "get_api", None) or (lambda cfg=None: None)
except Exception:
    get_api = None

# rich support for nicer UI (best-effort)
try:
    from rich.console import Console
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn
    from rich.table import Table
    RICH = True
    _console = Console()
except Exception:
    RICH = False
    _console = None

# fallback logger (text)
import logging
_logger = logging.getLogger("newpkg.cli")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.cli: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# ---------------- utilities ----------------
def now_ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def save_cli_report(report_dir: Path, name_prefix: str, report: Dict[str, Any], compress: bool = True) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"{name_prefix}-{now_ts()}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(str(tmp), str(path))
    if compress:
        try:
            import lzma
            comp_path = path.with_suffix(path.suffix + ".xz")
            with open(path, "rb") as fin:
                comp = lzma.compress(fin.read())
            with open(comp_path, "wb") as fout:
                fout.write(comp)
            path.unlink()
            path = comp_path
        except Exception:
            pass
    return path

def shlex_quote(s: str) -> str:
    return shlex.quote(s)

# ---------------- CLI class ----------------
class NewpkgCLI:
    DEFAULT_REPORT_DIR = "/var/log/newpkg/cli"
    DEFAULT_PROFILE = "system"
    PROFILES = {
        "system": {"jobs": None, "quiet": False},
        "developer": {"jobs": None, "quiet": False},
        "minimal": {"jobs": 1, "quiet": True},
    }

    def __init__(self, cfg: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        # logger from newpkg_logger if available (it may implement .progress())
        self.logger = None
        if get_logger:
            try:
                self.logger = get_logger(self.cfg)
            except Exception:
                self.logger = None

        # modules (best-effort)
        self.upgrade = get_upgrade(self.cfg, self.logger) if get_upgrade else None
        self.remover = get_remove(self.cfg, self.logger) if get_remove else None
        self.sync = get_sync(self.cfg, self.logger) if get_sync else None
        self.deps = get_deps(self.cfg, self.logger) if get_deps else None
        self.core = get_core(self.cfg, self.logger) if get_core else None
        self.metafile = get_metafile_manager(self.cfg) if get_metafile_manager else None
        self.audit = get_audit(self.cfg, self.logger) if get_audit else None
        self.hooks = get_hooks_manager(self.cfg) if get_hooks_manager else None
        self.api = get_api(self.cfg) if get_api else None

        # report dir
        self.report_dir = Path(self._cfg_get("cli.report_dir", self.DEFAULT_REPORT_DIR)).expanduser()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.compress_reports = bool(self._cfg_get("cli.compress_reports", True))

        # defaults / flags
        self.quiet = False
        self.json_out = False
        self.dry_run = False
        self.jobs = int(self._cfg_get("general.jobs", os.cpu_count() or 1))
        self.profile = self._cfg_get("cli.profile", self.DEFAULT_PROFILE)
        if self.profile in self.PROFILES:
            prof = self.PROFILES[self.profile]
            if prof.get("jobs") is not None:
                self.jobs = prof["jobs"]

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        envk = key.upper().replace(".", "_")
        return os.environ.get(envk, default)

    # ---------------- helpers for UI ----------------
    def _print_phase(self, text: str):
        if self.json_out:
            return
        if self.quiet:
            # show only high-level
            print(text)
            return
        if RICH and _console:
            _console.print(f"[bold cyan]{text}[/bold cyan]")
        else:
            print(text)

    def _progress_context(self, description: str, total: Optional[int] = None):
        """
        Return a progress context manager. If self.logger provides progress(), uses that; otherwise
        uses rich Progress if available; else a dummy context manager.
        Usage:
            with cli._progress_context("Baixando", total=1) as prog:
                task = prog.add_task(...)
                prog.update(task, advance=...)
        The returned object tries to expose .add_task and .update to be similar to rich.progress.
        """
        # best-effort: if logger offers .progress use it
        if self.logger and hasattr(self.logger, "progress"):
            try:
                return self.logger.progress(description, total=total)
            except Exception:
                pass
        if RICH and _console:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=_console,
            )
            return progress
        # fallback dummy
        class Dummy:
            def __enter__(self_inner):
                class Task:
                    def __init__(self):
                        pass
                self_inner.task = Task()
                return self_inner
            def __exit__(self_inner, exc_type, exc, tb):
                return False
            def add_task(self_inner, *args, **kwargs):
                return 0
            def update(self_inner, *args, **kwargs):
                return None
        return Dummy()

    # ---------------- central dispatcher w/ api & hooks ----------------
    def _dispatch(self, command: str, func, *args, **kwargs):
        """
        Dispatch a command. If API layer present, prefer api.call(command, args).
        Always run pre_command and post_command hooks when available.
        Collect stdout/stderr (if produced) and measure timing.
        """
        # CLI-level hook
        if self.hooks:
            try:
                self.hooks.run("pre_command", {"command": command, "args": args, "kwargs": kwargs})
            except Exception:
                pass

        # start time
        t0 = time.time()
        out = None
        err = None
        exc = None
        res = None
        used_api = False
        if self.api and hasattr(self.api, "call"):
            try:
                # api.call should return a dict-like result; best-effort wrapper
                res = self.api.call(command, {"args": args, **kwargs})
                used_api = True
            except Exception as e:
                exc = e
                res = None

        if not used_api:
            try:
                res = func(*args, **kwargs)
            except Exception as e:
                exc = e
                res = None

        duration = time.time() - t0

        # post hook
        if self.hooks:
            try:
                self.hooks.run("post_command", {"command": command, "result": res, "error": str(exc) if exc else None, "duration": duration})
            except Exception:
                pass

        # audit integration for certain commands
        try:
            if command in ("install", "remove", "upgrade") and self.audit:
                try:
                    # best-effort incremental scan after operation (non-blocking could be preferred)
                    self.audit.scan_system()
                except Exception:
                    pass
        except Exception:
            pass

        # build consolidated report structure
        report = {
            "command": command,
            "args": args,
            "kwargs": kwargs,
            "used_api": used_api,
            "result": res,
            "error": str(exc) if exc else None,
            "duration": round(duration, 3),
            "ts": now_ts(),
        }
        return report

    # ---------------- command implementations ----------------
    def cmd_sync(self, repos: Optional[List[str]] = None, parallel: Optional[int] = None, dry_run: bool = False):
        if not self.sync:
            raise RuntimeError("sync module not available")
        parallel = parallel or self.jobs
        self._print_phase(f">>>> Sincronizando repositórios ({len(repos) if repos else 'all'}) <<<<")
        # sync module may expose sync_all() or sync_repos(list)
        if repos:
            return self.sync.sync_repos(repos, jobs=parallel, dry_run=dry_run)
        if hasattr(self.sync, "sync_all"):
            return self.sync.sync_all(jobs=parallel, dry_run=dry_run)
        raise RuntimeError("sync module does not expose sync_all or sync_repos")

    def cmd_deps_resolve(self, package: str, types: Optional[List[str]] = None, install_missing: bool = False, jobs: Optional[int] = None):
        if not self.deps:
            raise RuntimeError("deps module not available")
        types = types or ["build", "runtime", "optional"]
        self._print_phase(f">>>> Resolvendo dependências para {package} <<<<")
        report = self.deps.resolve(package, include_types=types)
        if install_missing and report.missing:
            self._print_phase(f">>>> Instalando dependências faltantes: {len(report.missing)} <<<<")
            summary = self.deps.install_missing(report, parallel=jobs or self.jobs)
            return {"resolve": report, "install_summary": summary}
        return {"resolve": report}

    def cmd_install(self, metafile_path: str, install_all: bool = False, jobs: Optional[int] = None, dry_run: bool = False):
        """
        Install command: given a metafile (toml/json) path or package name, run the full install workflow:
         - parse metafile or use metafile manager
         - resolve deps (if configured)
         - fetch, build, package and install via core/upgrade
        """
        # prefer metafile manager if available
        self._print_phase(f">>>> Preparando a instalação de {metafile_path} <<<<")
        mf = None
        if Path(metafile_path).exists():
            try:
                import tomllib  # Python 3.11+; if not available, use toml fallback
                with open(metafile_path, "rb") as fh:
                    mf = tomllib.load(fh)
            except Exception:
                try:
                    import toml as _toml  # type: ignore
                    mf = _toml.load(metafile_path)
                except Exception:
                    mf = None
        else:
            if self.metafile and hasattr(self.metafile, "load_metafile_for"):
                try:
                    mf = self.metafile.load_metafile_for(metafile_path)
                except Exception:
                    mf = None

        # if metafile contains multiple packages, process accordingly
        pkgs = []
        if mf and isinstance(mf, dict) and mf.get("packages"):
            pkgs = mf.get("packages")
        elif mf and isinstance(mf, dict) and mf.get("package"):
            pkgs = [mf.get("package")]
        else:
            # treat metafile_path as package name
            pkgs = [metafile_path]

        results = []
        # pipeline per package: deps -> fetch -> build -> package -> install
        for pkg in pkgs:
            stage_report = {"package": pkg, "stages": []}
            # resolve
            try:
                if self.deps:
                    stage_report["stages"].append(("resolve_start", now_ts()))
                    rep = self.deps.resolve(pkg)
                    stage_report["stages"].append(("resolve_done", {"missing": rep.missing}))
                    # optionally install missing
                    if rep.missing:
                        if dry_run or self.dry_run:
                            stage_report["stages"].append(("install_missing", "dry-run"))
                        else:
                            inst_summary = self.deps.install_missing(rep, parallel=jobs or self.jobs)
                            stage_report["stages"].append(("install_missing", inst_summary))
            except Exception as e:
                stage_report["stages"].append(("resolve_error", str(e)))
            # delegate to upgrade pipeline (prefer upgrade.upgrade_package)
            try:
                if self.upgrade and hasattr(self.upgrade, "upgrade_package"):
                    stage_report["stages"].append(("upgrade_start", now_ts()))
                    if dry_run or self.dry_run:
                        res = {"ok": True, "message": "dry-run"}
                    else:
                        res = self.upgrade.upgrade_package(pkg)
                    stage_report["stages"].append(("upgrade_done", asdict(res) if hasattr(res, "__dict__") else res))
                else:
                    # fallback: use core.build + core.package_and_install
                    if self.core and hasattr(self.core, "build_package"):
                        if dry_run or self.dry_run:
                            stage_report["stages"].append(("build", "dry-run"))
                        else:
                            ok, msg = self.core.build_package(pkg)
                            stage_report["stages"].append(("build", {"ok": ok, "msg": msg}))
                            if ok and hasattr(self.core, "package_and_install"):
                                ok2, msg2 = self.core.package_and_install(pkg)
                                stage_report["stages"].append(("package_install", {"ok": ok2, "msg": msg2}))
                    else:
                        stage_report["stages"].append(("no_build_backend", None))
            except Exception as e:
                stage_report["stages"].append(("upgrade_error", str(e)))
            results.append(stage_report)
            # audit after install
            if self.audit:
                try:
                    self.audit.scan_system()
                except Exception:
                    pass
        return {"install_results": results}

    def cmd_remove(self, packages: List[str], purge: bool = False, jobs: Optional[int] = None, dry_run: bool = False):
        if not self.remover:
            raise RuntimeError("remove module not available")
        self._print_phase(f">>>> Preparando remoção de {len(packages)} pacotes <<<<")
        report = self.remover.remove_packages(packages, confirm=(not self.quiet), purge=purge, parallel=jobs or self.jobs, use_sandbox=None, fakeroot=False)
        # audit
        if self.audit:
            try:
                self.audit.scan_system()
            except Exception:
                pass
        return report

    def cmd_upgrade(self, packages: Optional[List[str]] = None, all_pkgs: bool = False, jobs: Optional[int] = None, dry_run: bool = False):
        if not self.upgrade:
            raise RuntimeError("upgrade module not available")
        # prepare list
        target = packages or []
        if all_pkgs:
            # try metafile manager or db
            if self.metafile and hasattr(self.metafile, "list_all_packages"):
                try:
                    target = self.metafile.list_all_packages()
                except Exception:
                    target = []
            elif self.db and hasattr(self.db, "list_available_packages"):
                try:
                    target = [p.get("name") for p in self.db.list_available_packages()]
                except Exception:
                    target = []
            else:
                raise RuntimeError("no source for --all packages")
        if not target:
            raise RuntimeError("no packages specified for upgrade")
        self._print_phase(f">>>> Iniciando upgrade de {len(target)} pacotes <<<<")
        if dry_run or self.dry_run:
            # call upgrade.upgrade_all with dry-run flag if supported
            try:
                if hasattr(self.upgrade, "upgrade_all"):
                    return self.upgrade.upgrade_all(target, parallel=jobs or self.jobs)
                else:
                    # fallback per-package dry-run simulation
                    return [{"package": p, "ok": True, "stage": "dry-run"} for p in target]
            except Exception as e:
                raise
        else:
            if hasattr(self.upgrade, "upgrade_all"):
                return self.upgrade.upgrade_all(target, parallel=jobs or self.jobs)
            else:
                # call per package
                res = []
                for p in target:
                    try:
                        r = self.upgrade.upgrade_package(p)
                    except Exception as e:
                        r = {"package": p, "ok": False, "error": str(e)}
                    res.append(r)
                return res

    def cmd_audit(self, quick: bool = False):
        if not self.audit:
            raise RuntimeError("audit module not available")
        self._print_phase(">>>> Executando auditoria do sistema <<<<")
        rep = self.audit.run_audit()
        return rep

    def cmd_sync_and_bootstrap(self, pkgs: List[str], jobs: Optional[int] = None, dry_run: bool = False):
        """
        High-level bootstrap for list of packages (default base set):
         sync -> deps.resolve -> upgrade/install
        """
        jobs = jobs or self.jobs
        report_summary = {"bootstrap": {"packages": pkgs, "stages": []}}
        # 1) sync
        try:
            if self.sync:
                report_summary["bootstrap"]["stages"].append({"stage": "sync_start", "ts": now_ts()})
                self.cmd_sync(None, parallel=jobs, dry_run=dry_run)
                report_summary["bootstrap"]["stages"].append({"stage": "sync_done", "ts": now_ts()})
        except Exception as e:
            report_summary["bootstrap"]["stages"].append({"stage": "sync_error", "error": str(e)})
            return report_summary
        # 2) for each package run deps.resolve -> upgrade pipeline
        pkgs_to_upgrade = pkgs
        for pkg in pkgs_to_upgrade:
            try:
                report_summary["bootstrap"]["stages"].append({"stage": "resolve_start", "pkg": pkg, "ts": now_ts()})
                rep = None
                if self.deps:
                    rep = self.deps.resolve(pkg)
                report_summary["bootstrap"]["stages"].append({"stage": "resolve_done", "pkg": pkg, "missing": rep.missing if rep else []})
                # install missing
                if rep and rep.missing:
                    if not dry_run:
                        self.deps.install_missing(rep, parallel=jobs)
                # upgrade package
                report_summary["bootstrap"]["stages"].append({"stage": "upgrade_start", "pkg": pkg, "ts": now_ts()})
                upres = self.cmd_upgrade([pkg], all_pkgs=False, jobs=jobs, dry_run=dry_run)
                report_summary["bootstrap"]["stages"].append({"stage": "upgrade_done", "pkg": pkg, "result": upres})
            except Exception as e:
                report_summary["bootstrap"]["stages"].append({"stage": "bootstrap_error", "pkg": pkg, "error": str(e)})
        # final audit
        if self.audit and not dry_run:
            try:
                report_summary["bootstrap"]["stages"].append({"stage": "audit_start", "ts": now_ts()})
                self.audit.scan_system()
                report_summary["bootstrap"]["stages"].append({"stage": "audit_done", "ts": now_ts()})
            except Exception:
                pass
        return report_summary

    # ---------------- CLI entrypoint ----------------
    def run(self, argv: Optional[List[str]] = None) -> int:
        parser = argparse.ArgumentParser(prog="newpkg", description="newpkg unified CLI")
        sub = parser.add_subparsers(dest="cmd", required=False)

        # install
        p_install = sub.add_parser("install", aliases=["i"], help="install from metafile or package name")
        p_install.add_argument("metafile", help="metafile path or package name")
        p_install.add_argument("--jobs", type=int)
        p_install.add_argument("--dry-run", action="store_true")
        p_install.add_argument("--json", action="store_true")

        # remove
        p_remove = sub.add_parser("remove", aliases=["rm", "r"], help="remove package(s)")
        p_remove.add_argument("packages", nargs="+")
        p_remove.add_argument("--purge", action="store_true")
        p_remove.add_argument("--jobs", type=int)
        p_remove.add_argument("--dry-run", action="store_true")
        p_remove.add_argument("--json", action="store_true")

        # upgrade
        p_upgrade = sub.add_parser("upgrade", aliases=["up", "u"], help="upgrade package(s)")
        p_upgrade.add_argument("packages", nargs="*", help="package names (omit if --all)")
        p_upgrade.add_argument("--all", action="store_true")
        p_upgrade.add_argument("--jobs", type=int)
        p_upgrade.add_argument("--dry-run", action="store_true")
        p_upgrade.add_argument("--json", action="store_true")

        # sync
        p_sync = sub.add_parser("sync", aliases=["s"], help="sync repositories")
        p_sync.add_argument("repos", nargs="*", help="optional list of repos to sync")
        p_sync.add_argument("--jobs", type=int)
        p_sync.add_argument("--dry-run", action="store_true")
        p_sync.add_argument("--json", action="store_true")

        # deps resolve
        p_deps = sub.add_parser("deps", aliases=["d"], help="resolve dependencies")
        p_deps.add_argument("package", help="package name")
        p_deps.add_argument("--install-missing", action="store_true")
        p_deps.add_argument("--json", action="store_true")

        # audit
        p_audit = sub.add_parser("audit", aliases=["a"], help="run audit")
        p_audit.add_argument("--quick", action="store_true")
        p_audit.add_argument("--json", action="store_true")

        # bootstrap
        p_boot = sub.add_parser("bootstrap", help="bootstrap a list of base packages (sync -> deps -> build -> install)")
        p_boot.add_argument("packages", nargs="+", help="packages to bootstrap")
        p_boot.add_argument("--jobs", type=int)
        p_boot.add_argument("--dry-run", action="store_true")
        p_boot.add_argument("--json", action="store_true")

        # global flags
        parser.add_argument("--quiet", action="store_true", help="quiet mode (less output)")
        parser.add_argument("--json", action="store_true", help="output JSON")
        parser.add_argument("--dry-run", action="store_true", help="dry run")
        parser.add_argument("--jobs", type=int, help="number of parallel jobs")
        parser.add_argument("--profile", choices=list(self.PROFILES.keys()), help="preset profile")
        parser.add_argument("--report-dir", help="override CLI report dir")
        parser.add_argument("--version", action="store_true", help="show version")

        args = parser.parse_args(argv or sys.argv[1:])

        # global options
        if args.profile:
            self.profile = args.profile
            prof = self.PROFILES.get(self.profile, {})
            if prof.get("jobs") is not None:
                self.jobs = prof["jobs"]
        if args.jobs:
            self.jobs = args.jobs
        if args.report_dir:
            self.report_dir = Path(args.report_dir)
            self.report_dir.mkdir(parents=True, exist_ok=True)
        if args.quiet:
            self.quiet = True
        if args.json:
            self.json_out = True
        if args.dry_run:
            self.dry_run = True

        # version shortcut
        if args.version:
            print("newpkg CLI (revision)")
            return 0

        # dispatch chosen command
        cmd = args.cmd or "help"
        try:
            if cmd in ("install", "i"):
                report = self._dispatch("install", self.cmd_install, args.metafile, False, args.jobs, args.dry_run or self.dry_run)
            elif cmd in ("remove", "rm", "r"):
                report = self._dispatch("remove", self.cmd_remove, args.packages, args.purge, args.jobs, args.dry_run or self.dry_run)
            elif cmd in ("upgrade", "up", "u"):
                report = self._dispatch("upgrade", self.cmd_upgrade, args.packages, args.all, args.jobs, args.dry_run or self.dry_run)
            elif cmd in ("sync", "s"):
                repos = args.repos if hasattr(args, "repos") else None
                report = self._dispatch("sync", self.cmd_sync, repos, args.jobs, args.dry_run or self.dry_run)
            elif cmd in ("deps", "d"):
                report = self._dispatch("deps.resolve", self.cmd_deps_resolve, args.package, None, args.install_missing, self.jobs)
            elif cmd in ("audit", "a"):
                report = self._dispatch("audit", self.cmd_audit, args.quick)
            elif cmd == "bootstrap":
                report = self._dispatch("bootstrap", self.cmd_sync_and_bootstrap, args.packages, args.jobs, args.dry_run or self.dry_run)
            else:
                parser.print_help()
                return 1
        except Exception as e:
            # consolidate error into report
            report = {"command": cmd, "error": str(e), "ts": now_ts()}
            if not self.json_out:
                if RICH and _console:
                    _console.print(f"[red]Error:[/red] {e}")
                else:
                    print("Error:", e)

        # output
        # if the dispatched function already returned a structured report (dict/list), use it
        out_report = report if isinstance(report, dict) else {"result": report}
        # attach meta
        out_report["_meta"] = {"cmd": cmd, "profile": self.profile, "jobs": self.jobs, "ts": now_ts(), "dry_run": self.dry_run or getattr(args, "dry_run", False)}
        # save report to disk
        try:
            saved_path = save_cli_report(self.report_dir, f"cli-{cmd}", out_report, compress=self.compress_reports)
            out_report["_meta"]["report_path"] = str(saved_path)
        except Exception:
            pass

        # show to user according to modes
        if self.json_out or getattr(args, "json", False):
            # print JSON
            print(json.dumps(out_report, indent=2, ensure_ascii=False))
        else:
            # human readable summary
            if isinstance(out_report.get("result"), dict) and out_report["result"].get("install_results"):
                # pretty print install summary
                if RICH and _console:
                    table = Table(title="Install Summary")
                    table.add_column("package")
                    table.add_column("stages")
                    for r in out_report["result"]["install_results"]:
                        pk = r.get("package")
                        stages = "\n".join(str(s) for s in r.get("stages", []))
                        table.add_row(pk, stages)
                    _console.print(table)
                else:
                    print("Install results:")
                    print(json.dumps(out_report["result"], indent=2))
            else:
                # generic print
                if RICH and _console:
                    _console.print(f"[green]Command[/green]: {cmd} — report: {out_report['_meta'].get('report_path')}")
                else:
                    print(f"Command: {cmd} — report: {out_report['_meta'].get('report_path')}")

        # exit code: 0 if no 'error' key and ok flags; else 2
        if out_report.get("error"):
            return 2
        # some modules return success flags; try to detect failures
        ok_flag = True
        # check typical locations in report for failures
        if isinstance(out_report.get("result"), dict):
            if out_report["result"].get("failed") or out_report["result"].get("failed_items"):
                ok_flag = False
        return 0 if ok_flag else 2

# ---------------- CLI runner ----------------
def main(argv: Optional[List[str]] = None) -> int:
    cli = NewpkgCLI()
    return cli.run(argv)

if __name__ == "__main__":
    sys.exit(main())
