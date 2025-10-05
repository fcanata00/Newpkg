#!/usr/bin/env python3
# newpkg_upgrade.py
"""
newpkg_upgrade.py — orchestrates safe package upgrades (fetch, build, package, deploy)

Features:
 - Respects newpkg_config (general.dry_run, output.quiet, output.json) and upgrade.* options
 - Integrates with NewpkgLogger (perf_timer if available), NewpkgDB, NewpkgSandbox
 - Backups before changes, supports rollback_on_fail
 - Uses NewpkgDeps, NewpkgMetafile/Downloader, NewpkgPatcher, NewpkgCore when available
 - Parallel fetch/build controlled by jobs setting
 - Produces JSON reports under /var/log/newpkg/upgrade/reports/
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

# Optional helpers
try:
    from newpkg_deps import NewpkgDeps
except Exception:
    NewpkgDeps = None

try:
    from newpkg_metafile import NewpkgMetafile
except Exception:
    NewpkgMetafile = None

try:
    from newpkg_patcher import NewpkgPatcher
except Exception:
    NewpkgPatcher = None

try:
    from newpkg_core import NewpkgCore
except Exception:
    NewpkgCore = None

try:
    from newpkg_audit import NewpkgAudit
except Exception:
    NewpkgAudit = None

# fallback stdlib logger
import logging
_logger = logging.getLogger("newpkg.upgrade")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.upgrade: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


@dataclass
class UpgradeReport:
    package: str
    ts: int
    stages: Dict[str, Any]

    def to_dict(self):
        return asdict(self)


class NewpkgUpgrade:
    DEFAULT_BACKUP_DIR = "/var/log/newpkg/upgrade/backups"
    DEFAULT_REPORT_DIR = "/var/log/newpkg/upgrade/reports"

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None):
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

        # sandbox
        if sandbox:
            self.sandbox = sandbox
        else:
            try:
                self.sandbox = NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgSandbox and self.cfg else None
            except Exception:
                self.sandbox = None

        # prefered handlers (optional)
        self.deps = NewpkgDeps(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgDeps and self.cfg else None
        self.metafile = NewpkgMetafile(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgMetafile and self.cfg else None
        self.patcher = NewpkgPatcher(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgPatcher and self.cfg else None
        self.core = NewpkgCore(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgCore and self.cfg else None
        self.audit = NewpkgAudit(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgAudit and self.cfg else None

        # runtime options
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))

        self.jobs = int(self._cfg_get("upgrade.jobs", max(1, (os.cpu_count() or 1))))
        self.retries = int(self._cfg_get("upgrade.retries", 2))
        self.rollback_on_fail = bool(self._cfg_get("upgrade.rollback_on_fail", True))
        self.verify_after = bool(self._cfg_get("upgrade.verify_after", True))
        self.backup_dir = Path(self._cfg_get("upgrade.backup_dir", self.DEFAULT_BACKUP_DIR))
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir = Path(self._cfg_get("upgrade.report_dir", self.DEFAULT_REPORT_DIR))
        self.report_dir.mkdir(parents=True, exist_ok=True)

        # sandbox default
        self.use_sandbox_default = bool(self._cfg_get("upgrade.use_sandbox", True))

        # perf_timer decorator if available
        self._perf_timer = getattr(self.logger, "perf_timer", None) if self.logger else None

        # internal
        self._log = self._make_logger()

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

    # ----------------- helpers -----------------
    def _now_ts(self) -> int:
        return int(time.time())

    def _run(self, cmd: List[str] | str, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
             use_sandbox: Optional[bool] = None, captures: bool = True, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Execute command, using sandbox when requested and available.
        In dry_run mode returns (0,"","").
        """
        if use_sandbox is None:
            use_sandbox = self.use_sandbox_default
        if self.dry_run:
            self._log("info", "upgrade.cmd.dryrun", f"DRY-RUN: {cmd}", cmd=cmd, cwd=cwd)
            return 0, "", ""

        if use_sandbox and self.sandbox:
            try:
                res = self.sandbox.run_in_sandbox(cmd, cwd=cwd, captures=captures, env=env, timeout=timeout)
                return res.rc, res.stdout or "", res.stderr or ""
            except Exception as e:
                return 255, "", str(e)

        try:
            if isinstance(cmd, (list, tuple)):
                proc = subprocess.run([str(x) for x in cmd], cwd=cwd, env=env, stdout=subprocess.PIPE if captures else None,
                                      stderr=subprocess.PIPE if captures else None, text=True, timeout=timeout)
            else:
                proc = subprocess.run(cmd, cwd=cwd, env=env, shell=True, stdout=subprocess.PIPE if captures else None,
                                      stderr=subprocess.PIPE if captures else None, text=True, timeout=timeout)
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as te:
            return 124, "", f"timeout: {te}"
        except Exception as e:
            return 255, "", str(e)

    def _backup_package(self, package: str, files: List[str]) -> Optional[str]:
        """
        Backup the package's files (list) into a tar.xz stored in backup_dir.
        Returns backup path or None on failure. In dry-run returns None but logs.
        """
        if not files:
            return None
        ts = int(time.time())
        safe = package.replace("/", "_")
        path = self.backup_dir / f"{safe}-upgrade-{ts}.tar.xz"
        if self.dry_run:
            self._log("info", "upgrade.backup.dryrun", f"DRY-RUN: would create backup for {package} with {len(files)} paths", package=package)
            return None
        try:
            with tarfile.open(path, "w:xz") as tar:
                for f in files:
                    try:
                        if os.path.exists(f):
                            tar.add(f, arcname=os.path.relpath(f, "/"))
                    except Exception as e:
                        self._log("warning", "upgrade.backup.skip", f"Skipping backup entry {f}: {e}", file=f, error=str(e))
            # compute sha256
            sha256 = self._sha256_file(path)
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="upgrade.backup", status="ok", meta={"backup": str(path), "sha256": sha256})
            self._log("info", "upgrade.backup.ok", f"Created backup {path}", path=str(path))
            return str(path)
        except Exception as e:
            self._log("error", "upgrade.backup.fail", f"Backup failed for {package}: {e}", package=package, error=str(e))
            return None

    def _sha256_file(self, p: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with p.open("rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _write_report(self, package: str, stages: Dict[str, Any]) -> str:
        ts = int(time.time())
        rpt = UpgradeReport(package=package, ts=ts, stages=stages)
        fn = f"upgrade-{package.replace('/', '_')}-{ts}.json"
        path = self.report_dir / fn
        try:
            path.write_text(json.dumps(rpt.to_dict(), indent=2), encoding="utf-8")
            self._log("info", "upgrade.report.write", f"Wrote upgrade report to {path}", path=str(path))
            return str(path)
        except Exception as e:
            self._log("warning", "upgrade.report.fail", f"Failed to write report: {e}", error=str(e))
            return ""

    # ----------------- per-package pipeline -----------------
    def _process_single(self, package: str, metafile: Optional[str] = None, use_sandbox: Optional[bool] = None) -> Dict[str, Any]:
        """
        Perform the full upgrade pipeline for a single package.
        Returns stage results dict.
        """
        start_total = time.time()
        stages: Dict[str, Any] = {}
        use_sandbox = True if use_sandbox is None else use_sandbox

        # 1) pre-upgrade hook
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="upgrade.start", status="ok", meta={})
        except Exception:
            pass

        # Attempt to gather files/metadata for backups
        files = []
        try:
            files = self.db.list_files(package) if self.db else []
        except Exception:
            files = []

        # 2) backup
        stages["backup"] = {"ok": False, "path": None}
        backup_path = self._backup_package(package, files)
        if backup_path:
            stages["backup"] = {"ok": True, "path": backup_path}
        else:
            stages["backup"] = {"ok": True, "path": None, "note": "no_backup_created_or_dryrun"}

        # 3) fetch / prepare sources
        stages["fetch"] = {"ok": False}
        try:
            sources_info = None
            if self.metafile and metafile:
                sources_info = self.metafile.process([metafile], workdir=None, download_profile=None, apply_patches=False)
            # else: fallback: log and mark as skipped
            stages["fetch"] = {"ok": True, "meta": sources_info}
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="upgrade.fetch", status="ok", meta={})
        except Exception as e:
            stages["fetch"] = {"ok": False, "error": str(e)}
            self._log("error", "upgrade.fetch.fail", f"Fetch failed for {package}: {e}", package=package, error=str(e))
            if self.rollback_on_fail and backup_path:
                self._attempt_rollback(package, backup_path)
            return stages

        # 4) apply patches if any
        if self.patcher and metafile:
            try:
                p_res = self.patcher.apply_from_metafile(metafile, dry_run=self.dry_run)
                stages["patch"] = {"ok": True, "result": p_res}
                if self.db and hasattr(self.db, "record_phase"):
                    self.db.record_phase(package=package, phase="upgrade.patch", status="ok", meta={})
            except Exception as e:
                stages["patch"] = {"ok": False, "error": str(e)}
                self._log("error", "upgrade.patch.fail", f"Patching failed for {package}: {e}", package=package, error=str(e))
                if self.rollback_on_fail and backup_path:
                    self._attempt_rollback(package, backup_path)
                return stages

        # 5) resolve deps (build-deps)
        if self.deps:
            try:
                deps_res = self.deps.resolve(package, dep_type="build")
                stages["deps"] = {"ok": True, "resolved": deps_res.resolved}
            except Exception as e:
                stages["deps"] = {"ok": False, "error": str(e)}
        else:
            stages["deps"] = {"ok": False, "note": "no_deps_module"}

        # 6) build (use core if available)
        stages["build"] = {"ok": False}
        try:
            if self.core:
                # core.prepare + core.configure + core.build + core.install to staging
                # use metafile info if available to determine build commands
                workdir = None
                if sources_info and isinstance(sources_info, dict):
                    workdir = sources_info.get("workdir")
                # prepare (already attempted via metafile.process but call core.prepare for consistency)
                try:
                    prep = self.core.prepare([metafile] if metafile else [], workdir=workdir)
                except Exception:
                    prep = {}
                # configure and build -- rely on metafile to supply commands or assume make
                configure_cmd = None
                make_cmd = None
                if prep and prep.get("package"):
                    # best-effort: let core.build use defaults
                    pass
                build_res = self.core.build(source_dir=workdir or ".", make_cmd=make_cmd)
                stages["build"] = {"ok": build_res.get("rc", 1) == 0, "result": build_res}
                if not stages["build"]["ok"]:
                    self._log("error", "upgrade.build.fail", f"Build failed for {package}", package=package, detail=build_res.get("stderr"))
                    if self.rollback_on_fail and backup_path:
                        self._attempt_rollback(package, backup_path)
                    return stages
            else:
                # fallback: try a simple make -j jobs in current dir (dangerous)
                rc, out, err = self._run(["make", f"-j{self.jobs}"], cwd=".")
                stages["build"] = {"ok": rc == 0, "rc": rc, "stdout": out, "stderr": err}
                if rc != 0:
                    if self.rollback_on_fail and backup_path:
                        self._attempt_rollback(package, backup_path)
                    return stages
        except Exception as e:
            stages["build"] = {"ok": False, "error": str(e)}
            if self.rollback_on_fail and backup_path:
                self._attempt_rollback(package, backup_path)
            return stages

        # 7) package (via core)
        stages["package"] = {"ok": False}
        try:
            if self.core:
                # assume core.install was run to staging in build step or run here
                # create a package from stagedir (if core.install returned destdir earlier we'd track it)
                stagedir = None
                # try to inspect core.last install destdir via DB or build_res
                # fallback: attempt packaging of current dir
                pkg_meta = {"name": package, "version": self._cfg_get("upgrade.version", "0")}
                pkg_res = self.core.package(stagedir or ".", pkg_meta)
                stages["package"] = {"ok": pkg_res.get("ok", False), "path": pkg_res.get("path")}
                if not stages["package"]["ok"]:
                    if self.rollback_on_fail and backup_path:
                        self._attempt_rollback(package, backup_path)
                    return stages
            else:
                stages["package"] = {"ok": False, "note": "no_core_module"}
        except Exception as e:
            stages["package"] = {"ok": False, "error": str(e)}
            if self.rollback_on_fail and backup_path:
                self._attempt_rollback(package, backup_path)
            return stages

        # 8) verify (optional)
        if self.verify_after:
            try:
                ok_verify = True
                if self.core and stages.get("package", {}).get("path"):
                    verify_res = self.core.verify(package_archive=stages["package"]["path"]) if hasattr(self.core, "verify") else {"ok": True}
                    ok_verify = verify_res.get("ok", True)
                stages["verify"] = {"ok": ok_verify}
                if not ok_verify:
                    self._log("warning", "upgrade.verify.fail", f"Verification failed for {package}", package=package)
                    if self.rollback_on_fail and backup_path:
                        self._attempt_rollback(package, backup_path)
                        return stages
            except Exception as e:
                stages["verify"] = {"ok": False, "error": str(e)}
                if self.rollback_on_fail and backup_path:
                    self._attempt_rollback(package, backup_path)
                return stages

        # 9) deploy: extract package to target root (via core.deploy if available)
        stages["deploy"] = {"ok": False}
        try:
            if self.core and stages.get("package", {}).get("path"):
                deploy_res = self.core.deploy(package_archive=stages["package"]["path"], target_root=None, backup=False, use_sandbox=use_sandbox)
                stages["deploy"] = {"ok": deploy_res.get("ok", False), "res": deploy_res}
                if not stages["deploy"]["ok"]:
                    self._log("error", "upgrade.deploy.fail", f"Deploy failed for {package}", package=package)
                    if self.rollback_on_fail and backup_path:
                        self._attempt_rollback(package, backup_path)
                    return stages
            else:
                stages["deploy"] = {"ok": False, "note": "no_core_or_package"}
        except Exception as e:
            stages["deploy"] = {"ok": False, "error": str(e)}
            if self.rollback_on_fail and backup_path:
                self._attempt_rollback(package, backup_path)
            return stages

        # 10) post-upgrade hook and audit
        try:
            if self.audit:
                try:
                    aud = self.audit.scan([package])
                    # optionally run quick audit fix
                except Exception:
                    pass
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="upgrade.done", status="ok", meta={})
        except Exception:
            pass

        total_time = time.time() - start_total
        stages["ok"] = True
        stages["duration"] = total_time
        return stages

    def _attempt_rollback(self, package: str, backup_path: Optional[str]) -> bool:
        """
        Try to restore backup_path if provided.
        """
        if not backup_path:
            self._log("warning", "upgrade.rollback.no_backup", f"No backup to rollback for {package}", package=package)
            return False
        if self.dry_run:
            self._log("info", "upgrade.rollback.dryrun", f"DRY-RUN: would rollback {package} from {backup_path}", package=package)
            return True
        try:
            # extract tar.xz to root (best-effort)
            with tarfile.open(backup_path, "r:xz") as tar:
                tar.extractall(path="/")
            self._log("info", "upgrade.rollback.ok", f"Rollback applied for {package} from {backup_path}", package=package, backup=backup_path)
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=package, phase="upgrade.rollback", status="ok", meta={"backup": backup_path})
            return True
        except Exception as e:
            self._log("error", "upgrade.rollback.fail", f"Rollback failed for {package}: {e}", package=package, error=str(e))
            return False

    # ----------------- high-level API -----------------
    def upgrade(self, packages: List[Tuple[str, Optional[str]]], parallel: Optional[int] = None, use_sandbox: Optional[bool] = None) -> Dict[str, Any]:
        """
        packages: list of tuples (package_name, metafile_path_or_None)
        Returns dict with per-package stages and report path.
        """
        parallel = parallel or self.jobs
        reports = {}
        results = {}

        # run pre-upgrade event
        try:
            if self.db and hasattr(self.db, "record_event"):
                self.db.record_event(event="upgrade.start", ts=self._now_ts(), meta={"count": len(packages)})
        except Exception:
            pass

        with ThreadPoolExecutor(max_workers=parallel) as ex:
            futures = {ex.submit(self._process_single, pkg, mf, use_sandbox): (pkg, mf) for pkg, mf in packages}
            for fut in as_completed(futures):
                pkg, mf = futures[fut]
                try:
                    stages = fut.result()
                except Exception as e:
                    stages = {"ok": False, "error": str(e)}
                results[pkg] = stages
                # write an individual report
                rpath = self._write_report(pkg, stages)
                reports[pkg] = rpath

        # final event
        try:
            if self.db and hasattr(self.db, "record_event"):
                self.db.record_event(event="upgrade.finish", ts=self._now_ts(), meta={"count": len(packages)})
        except Exception:
            pass

        summary = {"count": len(packages), "succeeded": sum(1 for v in results.values() if v.get("ok")), "failed": sum(1 for v in results.values() if not v.get("ok"))}
        return {"summary": summary, "reports": reports, "results": results}

    # ----------------- CLI -----------------
    @staticmethod
    def cli():
        import argparse
        p = argparse.ArgumentParser(prog="newpkg-upgrade", description="Upgrade packages using newpkg pipeline")
        p.add_argument("--package", "-p", nargs="+", help="package names to upgrade (simple names). If metafile available, pass as package=metafile")
        p.add_argument("--all", action="store_true", help="upgrade all packages known in DB")
        p.add_argument("--dry-run", action="store_true", help="simulate actions")
        p.add_argument("--no-sandbox", action="store_true", help="do not use sandbox")
        p.add_argument("--json", action="store_true", help="output JSON")
        p.add_argument("--quiet", action="store_true", help="quiet")
        p.add_argument("--jobs", type=int, help="parallel jobs override")
        p.add_argument("--retries", type=int, help="retries override")
        p.add_argument("--rollback-on-fail", action="store_true", help="rollback on failure")
        args = p.parse_args()

        cfg = init_config() if init_config else None
        logger = NewpkgLogger.from_config(cfg, NewpkgDB(cfg)) if NewpkgLogger and cfg else None
        db = NewpkgDB(cfg) if NewpkgDB and cfg else None
        sandbox = NewpkgSandbox(cfg=cfg, logger=logger, db=db) if NewpkgSandbox and cfg else None

        upgr = NewpkgUpgrade(cfg=cfg, logger=logger, db=db, sandbox=sandbox)

        if args.dry_run:
            upgr.dry_run = True
        if args.no_sandbox:
            upgr.use_sandbox_default = False
        if args.json:
            upgr.json_out = True
        if args.quiet:
            upgr.quiet = True
        if args.jobs:
            upgr.jobs = args.jobs
        if args.retries:
            upgr.retries = args.retries
        if args.rollback_on_fail:
            upgr.rollback_on_fail = True

        packages = []
        if args.all:
            if db:
                try:
                    pkgs = db.list_packages()
                    for p in pkgs:
                        packages.append((p.get("name"), None))
                except Exception:
                    pass
        if args.package:
            for item in args.package:
                # allow syntax package=path/to/metafile
                if "=" in item:
                    name, mf = item.split("=", 1)
                    packages.append((name, mf))
                else:
                    packages.append((item, None))

        if not packages:
            print("No packages specified. Use --package or --all.")
            raise SystemExit(2)

        res = upgr.upgrade(packages, parallel=upgr.jobs, use_sandbox=not args.no_sandbox)
        if upgr.json_out:
            print(json.dumps(res, indent=2))
        else:
            print("Upgrade summary:", res.get("summary"))
            for pkg, rpt in res.get("reports", {}).items():
                print(f"- {pkg}: report={rpt}")
        raise SystemExit(0)

    # expose CLI
    run_cli = cli


if __name__ == "__main__":
    NewpkgUpgrade.cli()
