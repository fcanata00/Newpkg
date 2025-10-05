#!/usr/bin/env python3
# newpkg_core.py
"""
newpkg_core.py — core pipeline for newpkg builds (prepare, build, install, strip, package, deploy)

Features:
 - Respects newpkg_config: general.dry_run, output.quiet, output.json, core.root_dir, core.jobs, core.strip_*
 - Integrates with NewpkgLogger, NewpkgDB, NewpkgHooks, NewpkgSandbox
 - Uses fakeroot/destdir for installation and supports alternative root_dir (e.g. /mnt/lfs)
 - Records phases in DB and uses logger.perf_timer when available
 - Produces JSON report to /var/log/newpkg/core/
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
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
    from newpkg_hooks import NewpkgHooks
except Exception:
    NewpkgHooks = None

try:
    from newpkg_sandbox import NewpkgSandbox
except Exception:
    NewpkgSandbox = None

# fallback stdlib logger
import logging
_logger = logging.getLogger("newpkg.core")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.core: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


@dataclass
class CoreReport:
    package: Dict[str, Any]
    phases: Dict[str, Any]
    timestamps: Dict[str, float]

    def to_dict(self):
        return asdict(self)


class NewpkgCore:
    REPORT_DIR_DEFAULT = "/var/log/newpkg/core"

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)

        # logger
        if logger:
            self.logger = logger
        else:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, db) if NewpkgLogger and self.cfg else None
            except Exception:
                self.logger = None

        # DB
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)

        # hooks
        if hooks:
            self.hooks = hooks
        else:
            try:
                self.hooks = NewpkgHooks.from_config(self.cfg, self.logger, self.db) if NewpkgHooks and self.cfg else None
            except Exception:
                self.hooks = None

        # sandbox
        if sandbox:
            self.sandbox = sandbox
        else:
            try:
                self.sandbox = NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgSandbox and self.cfg else None
            except Exception:
                self.sandbox = None

        # config-driven options
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))
        self.root_dir = os.path.expanduser(str(self._cfg_get("core.root_dir", "/")))
        self.jobs = int(self._cfg_get("core.jobs", max(1, (os.cpu_count() or 1))))
        self.strip_binaries = bool(self._cfg_get("core.strip_binaries", True))
        self.strip_exclude = list(self._cfg_get("core.strip_exclude", [])) or []
        self.report_dir = Path(self._cfg_get("core.report_dir", self.REPORT_DIR_DEFAULT))
        self.report_dir.mkdir(parents=True, exist_ok=True)

        # prefer perf_timer decorator from logger if available
        self._perf_timer = getattr(self.logger, "perf_timer", None) if self.logger else None

        # wrapper
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

    # ----------------- env helpers -----------------
    def _env(self) -> Dict[str, str]:
        env = dict(os.environ)
        try:
            if self.cfg and hasattr(self.cfg, "as_env"):
                env.update(self.cfg.as_env())
        except Exception:
            pass
        return env

    # ----------------- run wrapper -----------------
    def _run(self, cmd: List[str] | str, cwd: Optional[str] = None, env_extra: Optional[Dict[str, str]] = None,
             use_sandbox: bool = True, captures: bool = True, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Execute a command with sandbox support and dry-run awareness.
        Returns (rc, stdout, stderr).
        """
        env = self._env()
        if env_extra:
            env.update({k: str(v) for k, v in env_extra.items()})

        # stringify for logging
        cmd_display = cmd if isinstance(cmd, str) else " ".join(map(str, cmd))
        if self.dry_run:
            self._log("info", "core.cmd.dryrun", f"DRY-RUN: {cmd_display}", cmd=cmd_display, cwd=cwd)
            return 0, "", ""

        # use sandbox delegate
        if use_sandbox and self.sandbox:
            try:
                res = self.sandbox.run_in_sandbox(cmd, cwd=cwd, captures=captures, env=env, timeout=timeout)
                return res.rc, res.stdout or "", res.stderr or ""
            except Exception as e:
                return 255, "", str(e)

        # run locally
        try:
            if isinstance(cmd, (list, tuple)):
                proc = subprocess.run([str(x) for x in cmd], cwd=cwd, env=env, stdout=subprocess.PIPE if captures else None,
                                      stderr=subprocess.PIPE if captures else None, text=True, timeout=timeout)
            else:
                proc = subprocess.run(cmd, cwd=cwd, env=env, shell=True, stdout=subprocess.PIPE if captures else None,
                                      stderr=subprocess.PIPE if captures else None, text=True, timeout=timeout)
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as e:
            return 124, "", f"timeout: {e}"
        except Exception as e:
            return 255, "", str(e)

    # ---------------- hook helper ----------------
    def _run_hooks(self, phase: str, names: List[str], cwd: Optional[str] = None, json_output: bool = False):
        if not self.hooks:
            return
        try:
            self.hooks.execute_safe(phase, names, cwd=cwd, json_output=json_output)
        except Exception as e:
            self._log("warning", f"core.hooks.{phase}.fail", f"Hooks failed for {phase}: {e}", phase=phase, error=str(e))

    # ---------------- phases ----------------
    def prepare(self, metafile_paths: List[str], workdir: Optional[str] = None) -> Dict[str, Any]:
        """
        Prepare sources: merge metafiles and resolve sources/patches into workdir.
        Returns resolved metadata.
        """
        # perf timing decorator if available
        decorator = self._perf_timer("core.prepare") if self._perf_timer else None
        if decorator:
            return decorator(self._prepare_impl)(metafile_paths, workdir)
        else:
            start = time.time()
            res = self._prepare_impl(metafile_paths, workdir)
            duration = time.time() - start
            try:
                if self.db and hasattr(self.db, "record_phase"):
                    self.db.record_phase(package=res.get("package", {}).get("name", "unknown"), phase="core.prepare", status="ok", meta={"duration": duration})
            except Exception:
                pass
            return res

    def _prepare_impl(self, metafile_paths: List[str], workdir: Optional[str] = None) -> Dict[str, Any]:
        from newpkg_metafile import NewpkgMetafile  # local import to avoid circulars
        mf = NewpkgMetafile(cfg=self.cfg, logger=self.logger, db=self.db)
        res = mf.process(metafile_paths, workdir=workdir, download_profile=None, apply_patches=True)
        # run hooks
        self._run_hooks("pre_prepare", [])
        self._run_hooks("post_prepare", [])
        return res

    def configure(self, source_dir: str, configure_cmd: Optional[List[str]] = None, cwd: Optional[str] = None, env_extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        decorator = self._perf_timer("core.configure") if self._perf_timer else None
        if decorator:
            return decorator(self._configure_impl)(source_dir, configure_cmd, cwd, env_extra)
        else:
            start = time.time()
            res = self._configure_impl(source_dir, configure_cmd, cwd, env_extra)
            duration = time.time() - start
            try:
                if self.db:
                    self.db.record_phase(package=source_dir, phase="core.configure", status="ok" if res.get("rc", 0) == 0 else "error", meta={"duration": duration})
            except Exception:
                pass
            return res

    def _configure_impl(self, source_dir: str, configure_cmd: Optional[List[str]] = None, cwd: Optional[str] = None, env_extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        # hooks
        self._run_hooks("pre_configure", [])
        cmd = configure_cmd or ["./configure", f"--prefix=/usr"]
        rc, out, err = self._run(cmd, cwd=cwd or source_dir, env_extra=env_extra, use_sandbox=True)
        self._run_hooks("post_configure", [])
        return {"rc": rc, "stdout": out, "stderr": err}

    def build(self, source_dir: str, make_cmd: Optional[List[str]] = None, cwd: Optional[str] = None, env_extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        decorator = self._perf_timer("core.build") if self._perf_timer else None
        if decorator:
            return decorator(self._build_impl)(source_dir, make_cmd, cwd, env_extra)
        else:
            start = time.time()
            res = self._build_impl(source_dir, make_cmd, cwd, env_extra)
            duration = time.time() - start
            try:
                if self.db:
                    self.db.record_phase(package=source_dir, phase="core.build", status="ok" if res.get("rc", 0) == 0 else "error", meta={"duration": duration})
            except Exception:
                pass
            return res

    def _build_impl(self, source_dir: str, make_cmd: Optional[List[str]] = None, cwd: Optional[str] = None, env_extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        self._run_hooks("pre_build", [])
        cmd = make_cmd or ["make", f"-j{self.jobs}"]
        rc, out, err = self._run(cmd, cwd=cwd or source_dir, env_extra=env_extra, use_sandbox=True)
        self._run_hooks("post_build", [])
        return {"rc": rc, "stdout": out, "stderr": err}

    def install(self, source_dir: str, destdir: Optional[str] = None, use_fakeroot: bool = True, use_root_dir: bool = False, env_extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Install step: runs `make install` to destdir. Supports fakeroot and alternative root_dir.
        - destdir: explicit path (will be created)
        - use_root_dir: if True, interpret destdir relative to self.root_dir
        """
        decorator = self._perf_timer("core.install") if self._perf_timer else None
        if decorator:
            return decorator(self._install_impl)(source_dir, destdir, use_fakeroot, use_root_dir, env_extra)
        else:
            start = time.time()
            res = self._install_impl(source_dir, destdir, use_fakeroot, use_root_dir, env_extra)
            duration = time.time() - start
            try:
                if self.db:
                    self.db.record_phase(package=source_dir, phase="core.install", status="ok" if res.get("rc", 0) == 0 else "error", meta={"duration": duration})
            except Exception:
                pass
            return res

    def _install_impl(self, source_dir: str, destdir: Optional[str], use_fakeroot: bool, use_root_dir: bool, env_extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        self._run_hooks("pre_install", [])
        # determine final destdir
        if destdir:
            if use_root_dir and self.root_dir != "/":
                final_dest = os.path.join(self.root_dir, destdir.lstrip("/"))
            else:
                final_dest = destdir
        else:
            # default destdir is a temporary staging
            tmp = tempfile.mkdtemp(prefix="newpkg-install-")
            final_dest = tmp

        Path(final_dest).mkdir(parents=True, exist_ok=True)
        # install command typically: make DESTDIR=<final_dest> install
        cmd = ["make", f"DESTDIR={final_dest}", "install"]
        if use_fakeroot:
            # try fakeroot if available
            fakeroot = shutil.which("fakeroot")
            if fakeroot:
                cmd = [fakeroot, "--"] + cmd
        rc, out, err = self._run(cmd, cwd=source_dir, env_extra=env_extra, use_sandbox=True)
        self._run_hooks("post_install", [])
        return {"rc": rc, "stdout": out, "stderr": err, "destdir": final_dest}

    def strip(self, stagedir: str, exclude: Optional[List[str]] = None) -> Dict[str, Any]:
        decorator = self._perf_timer("core.strip") if self._perf_timer else None
        if decorator:
            return decorator(self._strip_impl)(stagedir, exclude)
        else:
            start = time.time()
            res = self._strip_impl(stagedir, exclude)
            duration = time.time() - start
            try:
                if self.db:
                    self.db.record_phase(package=stagedir, phase="core.strip", status="ok", meta={"duration": duration})
            except Exception:
                pass
            return res

    def _strip_impl(self, stagedir: str, exclude: Optional[List[str]] = None) -> Dict[str, Any]:
        self._run_hooks("pre_strip", [])
        exclude = exclude or self.strip_exclude
        modified = []
        errors = []
        if not self.strip_binaries:
            self._log("info", "core.strip.disabled", "Binary stripping disabled by config")
            return {"modified": modified, "errors": errors}
        # walk stagedir and strip ELF executables & shared objects
        for root, dirs, files in os.walk(stagedir):
            for fn in files:
                path = os.path.join(root, fn)
                rel = os.path.relpath(path, stagedir)
                if any(rel.startswith(e) for e in exclude):
                    continue
                try:
                    # quick binary detection: check executable flag or .so/.a/.so.* suffix
                    if os.access(path, os.X_OK) or fn.endswith((".so", ".so.0", ".a")):
                        # run strip if available
                        strip_bin = shutil.which("strip")
                        if strip_bin:
                            rc, out, err = self._run([strip_bin, "--strip-unneeded", path], use_sandbox=True)
                            if rc == 0:
                                modified.append(path)
                            else:
                                errors.append({"path": path, "err": err})
                        else:
                            # no strip tool: skip
                            self._log("warning", "core.strip.nostrip", f"No strip tool found; skipping {path}")
                except Exception as e:
                    errors.append({"path": path, "err": str(e)})
        self._run_hooks("post_strip", [])
        return {"modified": modified, "errors": errors}

    def package(self, stagedir: str, package_meta: Dict[str, Any], outdir: Optional[str] = None, format: str = "tar.xz") -> Dict[str, Any]:
        """
        Package stagedir into tar.xz and include metadata file .newpkg-meta.json
        Returns {"ok": True, "path": ...}
        """
        decorator = self._perf_timer("core.package") if self._perf_timer else None
        if decorator:
            return decorator(self._package_impl)(stagedir, package_meta, outdir, format)
        else:
            start = time.time()
            res = self._package_impl(stagedir, package_meta, outdir, format)
            duration = time.time() - start
            try:
                if self.db:
                    self.db.record_phase(package=package_meta.get("name", "unknown"), phase="core.package", status="ok", meta={"duration": duration})
            except Exception:
                pass
            return res

    def _package_impl(self, stagedir: str, package_meta: Dict[str, Any], outdir: Optional[str], format: str) -> Dict[str, Any]:
        self._run_hooks("pre_package", [])
        timestamp = int(time.time())
        outdir = outdir or str(self.report_dir)
        Path(outdir).mkdir(parents=True, exist_ok=True)
        name = package_meta.get("name", "package")
        version = package_meta.get("version", "0")
        fname = f"{name}-{version}-{timestamp}.tar.xz"
        dest = Path(outdir) / fname
        meta_fname = ".newpkg-meta.json"
        # write meta inside stagedir temporarily
        meta_path = Path(stagedir) / meta_fname
        try:
            meta_path.write_text(json.dumps({"meta": package_meta, "ts": timestamp}, indent=2), encoding="utf-8")
        except Exception:
            pass

        if self.dry_run:
            self._log("info", "core.package.dryrun", f"DRY-RUN: would create {dest}", dest=str(dest))
            return {"ok": True, "path": str(dest)}

        try:
            # create tar.xz archive
            with tarfile.open(str(dest), "w:xz") as tar:
                tar.add(stagedir, arcname=".")
            # remove temporary meta file
            try:
                meta_path.unlink()
            except Exception:
                pass
            self._run_hooks("post_package", [])
            return {"ok": True, "path": str(dest)}
        except Exception as e:
            self._log("error", "core.package.fail", f"Packaging failed: {e}", error=str(e))
            return {"ok": False, "error": str(e)}

    def deploy(self, package_archive: str, target_root: Optional[str] = None, backup: bool = True, use_sandbox: bool = True) -> Dict[str, Any]:
        """
        Deploy package archive to target_root (defaults to self.root_dir).
        If backup=True, create a timestamped backup of affected paths (best-effort) before extraction.
        Returns dict with status and rollback info.
        """
        decorator = self._perf_timer("core.deploy") if self._perf_timer else None
        if decorator:
            return decorator(self._deploy_impl)(package_archive, target_root, backup, use_sandbox)
        else:
            start = time.time()
            res = self._deploy_impl(package_archive, target_root, backup, use_sandbox)
            duration = time.time() - start
            try:
                if self.db:
                    pkgname = "unknown"
                    try:
                        # attempt to get package name from archive meta if present
                        pkgname = Path(package_archive).stem
                    except Exception:
                        pass
                    self.db.record_phase(package=pkgname, phase="core.deploy", status="ok" if res.get("ok") else "error", meta={"duration": duration})
            except Exception:
                pass
            return res

    def _deploy_impl(self, package_archive: str, target_root: Optional[str], backup: bool, use_sandbox: bool) -> Dict[str, Any]:
        self._run_hooks("pre_deploy", [])
        if not target_root:
            target_root = self.root_dir
        if not Path(package_archive).exists():
            return {"ok": False, "error": "archive_missing"}

        if self.dry_run:
            self._log("info", "core.deploy.dryrun", f"DRY-RUN: would deploy {package_archive} to {target_root}", archive=package_archive, target=target_root)
            return {"ok": True, "simulated": True}

        # optional backup (best-effort: backup whole root? dangerous — keep conservative)
        backup_path = None
        if backup:
            try:
                ts = int(time.time())
                backup_fname = f"deploy-backup-{ts}.tar.xz"
                backup_dir = Path(self.report_dir) / "backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_path = str(backup_dir / backup_fname)
                # create archive of target_root contents (dangerous for large roots) — limit to package's top-level entries by extracting archive list first
                with tarfile.open(package_archive, "r:*") as tar:
                    top_entries = sorted({member.name.split("/", 1)[0] for member in tar.getmembers() if member.name and not member.name.startswith(".newpkg-meta.json")})
                # archive only those entries if they exist
                with tarfile.open(backup_path, "w:xz") as btar:
                    for entry in top_entries:
                        path = Path(target_root) / entry
                        if path.exists():
                            btar.add(str(path), arcname=entry)
                self._log("info", "core.deploy.backup", f"Created backup {backup_path}", backup=backup_path)
            except Exception as e:
                self._log("warning", "core.deploy.backup_fail", f"Backup failed: {e}", error=str(e))
                backup_path = None

        # extract archive into target_root
        try:
            if use_sandbox and self.sandbox:
                cmd = ["tar", "-xJf", package_archive, "-C", target_root]
                res = self.sandbox.run_in_sandbox(cmd, cwd=target_root, captures=True)
                rc = res.rc
                stderr = res.stderr or ""
                stdout = res.stdout or ""
            else:
                with tarfile.open(package_archive, "r:xz") as tar:
                    tar.extractall(path=target_root)
                rc = 0
                stdout = ""
                stderr = ""
            ok = rc == 0
            self._run_hooks("post_deploy", [])
            return {"ok": ok, "rc": rc, "stdout": stdout, "stderr": stderr, "backup": backup_path}
        except Exception as e:
            self._log("error", "core.deploy.fail", f"Deploy failed: {e}", error=str(e))
            return {"ok": False, "error": str(e), "backup": backup_path}

    # ---------------- reporting ----------------
    def write_report(self, package_meta: Dict[str, Any], phases: Dict[str, Any], timestamps: Dict[str, float]) -> Path:
        rpt = CoreReport(package=package_meta, phases=phases, timestamps=timestamps)
        ts = int(time.time())
        fname = f"{package_meta.get('name','package')}-{package_meta.get('version','0')}-{ts}.json"
        path = self.report_dir / fname
        try:
            path.write_text(json.dumps(rpt.to_dict(), indent=2), encoding="utf-8")
            self._log("info", "core.report.write", f"Wrote core report {path}", path=str(path))
        except Exception as e:
            self._log("warning", "core.report.fail", f"Failed writing core report: {e}", error=str(e))
        return path

    # ---------------- CLI ----------------
    @staticmethod
    def cli():
        import argparse
        p = argparse.ArgumentParser(prog="newpkg-core", description="Newpkg core build pipeline")
        p.add_argument("--metafiles", nargs="+", help="metafile TOML paths to prepare from")
        p.add_argument("--workdir", help="workdir for sources and build")
        p.add_argument("--configure-cmd", nargs="+", help="configure command (e.g. ./configure --option)")
        p.add_argument("--make-cmd", nargs="+", help="make command (e.g. make -j4)")
        p.add_argument("--install-dest", help="install destdir (staging area) or final path")
        p.add_argument("--use-root-dir", action="store_true", help="interpret install-dest relative to core.root_dir (e.g. /mnt/lfs)")
        p.add_argument("--no-sandbox", action="store_true", help="do not use sandbox")
        p.add_argument("--dry-run", action="store_true", help="simulate actions")
        p.add_argument("--json", action="store_true", help="output JSON report instead of human")
        p.add_argument("--strip", action="store_true", help="run strip phase")
        p.add_argument("--package", action="store_true", help="create package archive from stagedir")
        p.add_argument("--deploy", metavar="ARCHIVE", help="deploy package archive to target root")
        p.add_argument("--jobs", type=int, help="override jobs")
        args = p.parse_args()

        cfg = init_config() if init_config else None
        logger = NewpkgLogger.from_config(cfg, NewpkgDB(cfg)) if NewpkgLogger and cfg else None
        db = NewpkgDB(cfg) if NewpkgDB and cfg else None
        hooks = NewpkgHooks.from_config(cfg, logger, db) if NewpkgHooks and cfg else None
        sandbox = NewpkgSandbox(cfg=cfg, logger=logger, db=db) if NewpkgSandbox and cfg else None

        core = NewpkgCore(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)

        if args.dry_run:
            core.dry_run = True
        if args.no_sandbox:
            core.sandbox = None
        if args.jobs:
            core.jobs = args.jobs
        if args.json:
            core.json_out = True

        # minimal orchestration: prepare -> configure -> build -> install -> strip -> package -> deploy
        report_phases = {}
        timestamps = {}
        package_meta = {"name": "unknown", "version": "0"}

        # prepare
        if args.metafiles:
            prep = core.prepare(args.metafiles, workdir=args.workdir)
            report_phases["prepare"] = prep
            timestamps["prepare"] = time.time()
            # try to collect package_meta
            try:
                package_meta = prep.get("package") or package_meta
            except Exception:
                pass
            if core.json_out:
                print(json.dumps({"phase": "prepare", "result": prep}, indent=2))

        # configure
        if args.configure_cmd:
            conf = core.configure(source_dir=args.workdir or ".", configure_cmd=args.configure_cmd)
            report_phases["configure"] = conf
            timestamps["configure"] = time.time()
            if core.json_out:
                print(json.dumps({"phase": "configure", "result": conf}, indent=2))

        # build
        if args.make_cmd:
            build = core.build(source_dir=args.workdir or ".", make_cmd=args.make_cmd)
            report_phases["build"] = build
            timestamps["build"] = time.time()
            if core.json_out:
                print(json.dumps({"phase": "build", "result": build}, indent=2))

        # install
        if args.install_dest:
            inst = core.install(source_dir=args.workdir or ".", destdir=args.install_dest, use_fakeroot=True, use_root_dir=args.use_root_dir)
            report_phases["install"] = inst
            stagedir = inst.get("destdir")
            timestamps["install"] = time.time()
            if core.json_out:
                print(json.dumps({"phase": "install", "result": inst}, indent=2))
        else:
            stagedir = None

        # strip
        if args.strip and stagedir:
            st = core.strip(stagedir)
            report_phases["strip"] = st
            timestamps["strip"] = time.time()
            if core.json_out:
                print(json.dumps({"phase": "strip", "result": st}, indent=2))

        # package
        package_path = None
        if args.package and stagedir:
            pkg = core.package(stagedir, package_meta)
            report_phases["package"] = pkg
            timestamps["package"] = time.time()
            package_path = pkg.get("path")
            if core.json_out:
                print(json.dumps({"phase": "package", "result": pkg}, indent=2))

        # deploy
        if args.deploy:
            dp = core.deploy(args.deploy, target_root=None, backup=True, use_sandbox=(not args.no_sandbox))
            report_phases["deploy"] = dp
            timestamps["deploy"] = time.time()
            if core.json_out:
                print(json.dumps({"phase": "deploy", "result": dp}, indent=2))

        # final report
        report_path = core.write_report(package_meta, report_phases, timestamps)
        if core.json_out:
            print(json.dumps({"report": str(report_path)}, indent=2))
        else:
            print(f"Core run finished; report: {report_path}")

    # expose CLI callable
    run_cli = cli


if __name__ == "__main__":
    NewpkgCore.cli()
