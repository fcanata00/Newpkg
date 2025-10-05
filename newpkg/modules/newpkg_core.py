#!/usr/bin/env python3
# newpkg_core.py
"""
newpkg_core.py

Core build pipeline for Newpkg.

Features:
 - Integrates with newpkg_config, newpkg_logger, newpkg_db, newpkg_hooks, newpkg_sandbox, newpkg_deps, newpkg_download, newpkg_patcher, newpkg_metafile
 - Full pipeline methods:
     prepare() -> build() -> install() -> strip_binaries() -> package() -> deploy()
 - Supports fakeroot install in DESTDIR, option to install to / or /mnt/lfs
 - Records phases to DB (record_phase) when available
 - Logs progress via NewpkgLogger when available, fallback to stderr prints
 - Safe sandboxed execution using Sandbox.run() when available
 - Resource/time metrics collected (best-effort)
 - Options for stripping binaries and controlling which files to strip
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try to import optional project modules
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
    from newpkg_sandbox import Sandbox
except Exception:
    Sandbox = None

try:
    from newpkg_deps import NewpkgDeps
except Exception:
    NewpkgDeps = None

try:
    from newpkg_download import NewpkgDownloader
except Exception:
    NewpkgDownloader = None

try:
    from newpkg_patcher import NewpkgPatcher
except Exception:
    NewpkgPatcher = None

try:
    from newpkg_metafile import Metafile
except Exception:
    Metafile = None

# constants
WORK_ROOT = Path(os.environ.get("NEWPKG_WORK_ROOT", "/var/tmp/newpkg_builds"))
PACKAGE_OUTPUT = Path(os.environ.get("NEWPKG_PACKAGE_OUTPUT", "./packages"))
ROLLBACK_DIR = Path(os.environ.get("NEWPKG_ROLLBACK_DIR", "/var/tmp/newpkg_rollbacks"))

# ensure directories
WORK_ROOT.mkdir(parents=True, exist_ok=True)
PACKAGE_OUTPUT.mkdir(parents=True, exist_ok=True)
ROLLBACK_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class BuildResult:
    package: str
    version: Optional[str] = None
    status: str = "unknown"
    phases: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)


class CoreError(Exception):
    pass


class NewpkgCore:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.logger = logger or (NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None)
        self.db = db or (NewpkgDB(cfg) if NewpkgDB and cfg is not None else None)
        self.hooks = HooksManager(cfg, self.logger, self.db) if HooksManager and cfg is not None else None
        self.sandbox = sandbox or (Sandbox(cfg, self.logger, self.db) if Sandbox and cfg is not None else None)
        self.deps = NewpkgDeps(cfg, self.logger, self.db) if NewpkgDeps and cfg is not None else None
        self.downloader = NewpkgDownloader(cfg, self.logger, self.db) if NewpkgDownloader and cfg is not None else None
        self.patcher = NewpkgPatcher(cfg, self.logger, self.db) if NewpkgPatcher and cfg is not None else None

        # config defaults
        self.work_root = Path(self._cfg_get("core.work_root", str(WORK_ROOT)))
        self.package_output = Path(self._cfg_get("core.package_output", str(PACKAGE_OUTPUT)))
        self.rollback_dir = Path(self._cfg_get("core.rollback_dir", str(ROLLBACK_DIR)))
        self.use_sandbox = bool(self._cfg_get("core.use_sandbox", True))
        self.fakeroot_cmd = self._cfg_get("core.fakeroot_cmd", "fakeroot")
        # strip options
        self.strip_binaries_enabled = bool(self._cfg_get("core.strip_binaries", True))
        self.strip_paths = self._cfg_get("core.strip_paths", ["/usr/bin", "/usr/lib"])  # relative inside destdir
        self.strip_exclude = self._cfg_get("core.strip_exclude", [])  # list of globs to skip
        # build defaults
        self.jobs = int(self._cfg_get("core.jobs", os.environ.get("MAKEFLAGS_JOBS", "1")))
        self.work_root.mkdir(parents=True, exist_ok=True)
        self.package_output.mkdir(parents=True, exist_ok=True)
        self.rollback_dir.mkdir(parents=True, exist_ok=True)

    # ---------------- helpers ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return os.environ.get(key.upper().replace(".", "_"), default)

    def _log(self, level: str, event: str, message: str = "", **meta):
        if self.logger:
            try:
                fn = getattr(self.logger, level.lower(), None)
                if fn:
                    fn(event, message, **meta)
                    return
            except Exception:
                pass
        print(f"[{level}] {event}: {message}", file=sys.stderr)

    def _record(self, pkg: str, phase: str, status: str, meta: Optional[Dict[str, Any]] = None):
        if self.db and hasattr(self.db, "record_phase"):
            try:
                self.db.record_phase(pkg, phase, status, meta or {})
            except Exception:
                pass

    def _run(self, cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None, use_sandbox: Optional[bool] = None) -> Tuple[int, str, str]:
        """
        Run a command in sandbox if available and configured. Returns (rc, stdout, stderr).
        """
        use_sandbox = self.use_sandbox if use_sandbox is None else bool(use_sandbox)
        if use_sandbox and self.sandbox:
            try:
                res = self.sandbox.run(cmd, cwd=cwd, env=env, timeout=timeout)
                return int(res.rc), res.out or "", res.err or ""
            except Exception as e:
                # fallback to local
                self._log("warning", "core.run.sandbox_fail", f"sandbox.run failed, falling back: {e}", cmd=cmd)
        # fallback local subprocess
        try:
            proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as e:
            return 124, "", f"timeout: {e}"
        except Exception as e:
            return 1, "", str(e)

    # ---------------- prepare ----------------
    def prepare(self, package_name: str, metafile_path: Optional[str] = None, profile: Optional[str] = None, workdir: Optional[str] = None) -> Dict[str, Any]:
        """
        Prepare working directories, fetch sources (via Metafile or downloader), apply patches.
        Returns dict with keys: workdir, srcdir, builddir, destdir
        """
        start = time.time()
        wd = Path(workdir) if workdir else (self.work_root / f"{package_name}-{int(time.time())}")
        srcdir = wd / "sources"
        builddir = wd / "build"
        destdir = wd / "destdir"
        wd.mkdir(parents=True, exist_ok=True)
        srcdir.mkdir(parents=True, exist_ok=True)
        builddir.mkdir(parents=True, exist_ok=True)
        destdir.mkdir(parents=True, exist_ok=True)

        self._log("info", "core.prepare.start", f"Preparing build for {package_name}", package=package_name, workdir=str(wd))
        self._record(package_name, "prepare", "start", {"workdir": str(wd)})

        # load metafile if provided
        metafile = None
        sources_res = []
        if metafile_path and Metafile:
            try:
                mf = Metafile(cfg=self.cfg, logger=self.logger, db=self.db)
                mf.load(metafile_path)
                metafile = mf
                # expand env from profile if present
                if profile:
                    mf.expand_env({"PROFILE": profile})
                # resolve sources into srcdir
                try:
                    sources_res = mf.resolve_sources(download_dir=str(srcdir))
                except Exception as e:
                    self._log("warning", "core.prepare.download_fail", f"Metafile resolve_sources failed: {e}", error=str(e))
                    sources_res = []
                # apply patches if any
                try:
                    if self.patcher:
                        mf.apply_patches(workdir=str(builddir))
                except Exception as e:
                    self._log("warning", "core.prepare.patch_fail", f"Patcher failed: {e}", error=str(e))
            except Exception as e:
                self._log("warning", "core.prepare.metafile_fail", f"Failed to load metafile {metafile_path}: {e}", error=str(e))
        else:
            # no metafile: nothing to download
            self._log("info", "core.prepare.nometa", f"No metafile provided for {package_name}")

        duration = time.time() - start
        self._record(package_name, "prepare", "ok", {"duration": duration})
        self._log("info", "core.prepare.done", f"Prepared {package_name}", duration=duration, workdir=str(wd))
        return {"workdir": str(wd), "srcdir": str(srcdir), "builddir": str(builddir), "destdir": str(destdir), "metafile": metafile, "sources": sources_res}

    # ---------------- resolve deps ----------------
    def resolve_build_deps(self, package_name: str, operate_on_metafile: Optional[Metafile] = None) -> Dict[str, Any]:
        """
        Resolve build and runtime dependencies as needed.
        """
        self._log("info", "core.deps.start", f"Resolving build deps for {package_name}", package=package_name)
        self._record(package_name, "deps.resolve", "start")
        deps_list = []
        try:
            if operate_on_metafile and hasattr(operate_on_metafile, "raw"):
                # try to resolve using metafile or db
                # metafile may contain explicit build deps under 'build-deps' or similar
                raw = operate_on_metafile.raw
                explicit = raw.get("build-deps") or raw.get("build_deps") or raw.get("build_deps", [])
                if explicit:
                    for d in explicit:
                        deps_list.append(d if isinstance(d, str) else d.get("name"))
                # fallback to deps module
            if self.deps:
                resolved = self.deps.resolve(package_name, dep_type='build', include_optional=False)
                deps_list.extend(resolved)
        except Exception as e:
            self._log("warning", "core.deps.fail", f"Failed to resolve build deps: {e}", error=str(e))
        # uniq preserve order
        seen = set()
        uniq = []
        for d in deps_list:
            if d and d not in seen:
                seen.add(d)
                uniq.append(d)
        self._record(package_name, "deps.resolve", "ok", {"count": len(uniq)})
        self._log("info", "core.deps.done", f"Resolved {len(uniq)} build deps for {package_name}", deps=uniq)
        return {"deps": uniq}

    # ---------------- build ----------------
    def build(self, package_name: str, workdir: str, build_cmds: Optional[List[List[str]]] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Run build commands inside the builddir. build_cmds is list of argv lists.
        If omitted, attempt to run './configure && make' if present.
        """
        builddir = Path(workdir) / "build"
        start = time.time()
        phases = []
        self._log("info", "core.build.start", f"Building {package_name}", package=package_name, builddir=str(builddir))
        self._record(package_name, "build", "start")

        if not build_cmds:
            # auto-detect common build commands
            # prefer configure script
            cfg_script = Path(workdir) / "sources"
            # naive: detect top-level configure in builddir/sources unpacked
            # user should supply explicit build_cmds for complex packages
            if (cfg_script / "configure").exists():
                build_cmds = [["/bin/sh", "./configure", f"--prefix=/usr"], ["make", f"-j{self.jobs}"]]
            else:
                # try running 'make'
                build_cmds = [["make", f"-j{self.jobs}"]]

        for cmd in build_cmds:
            t0 = time.time()
            rc, out, err = self._run(cmd, cwd=str(builddir), env=env, timeout=timeout)
            dur = time.time() - t0
            phases.append({"cmd": cmd, "rc": rc, "duration": dur})
            if rc != 0:
                self._log("error", "core.build.fail", f"Build command failed: {cmd}", cmd=cmd, rc=rc, stderr=err)
                self._record(package_name, "build", "error", {"cmd": cmd, "rc": rc, "stderr": err})
                return {"status": "error", "failed_cmd": cmd, "stderr": err, "phases": phases}
            else:
                self._log("info", "core.build.step", f"Build command succeeded: {cmd}", cmd=cmd, rc=rc, duration=dur)
        total = time.time() - start
        self._record(package_name, "build", "ok", {"duration": total})
        self._log("info", "core.build.done", f"Build finished for {package_name}", duration=total)
        return {"status": "ok", "phases": phases, "duration": total}

    # ---------------- install (fakeroot & destdir) ----------------
    def install(self, package_name: str, workdir: str, destdir: Optional[str] = None, install_cmds: Optional[List[List[str]]] = None, use_fakeroot: bool = True, fakeroot_install_prefix: Optional[str] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Install built files into destdir (fakeroot supported).
        install_cmds: list of argv lists to run to perform install; if None, runs 'make install DESTDIR=<destdir>'
        fakeroot_install_prefix: if provided, allows changing the root where package intended to be installed (e.g. / or /mnt/lfs)
        """
        destdir = destdir or str(Path(workdir) / "destdir")
        destdir_path = Path(destdir)
        destdir_path.mkdir(parents=True, exist_ok=True)

        self._log("info", "core.install.start", f"Installing {package_name} into {destdir}", package=package_name, destdir=destdir)
        self._record(package_name, "install", "start", {"destdir": destdir})

        if not install_cmds:
            install_cmds = [["make", f"DESTDIR={destdir}", "install"]]

        # Build wrapper to execute install commands. If use_fakeroot, wrap via fakeroot if available.
        results = []
        for cmd in install_cmds:
            if use_fakeroot and shutil.which(self.fakeroot_cmd):
                full_cmd = [self.fakeroot_cmd] + cmd
            else:
                full_cmd = cmd
            rc, out, err = self._run(full_cmd, cwd=str(Path(workdir) / "build"), timeout=timeout)
            results.append({"cmd": full_cmd, "rc": rc, "stderr": err})
            if rc != 0:
                self._log("error", "core.install.fail", f"Install command failed: {full_cmd}", cmd=full_cmd, rc=rc, stderr=err)
                self._record(package_name, "install", "error", {"cmd": full_cmd, "rc": rc})
                return {"status": "error", "failed_cmd": full_cmd, "stderr": err}
            else:
                self._log("info", "core.install.step", f"Install step ok: {full_cmd}", cmd=full_cmd)

        # optionally, if fakeroot_install_prefix provided, we'll move contents to the prefix when deploying
        self._record(package_name, "install", "ok", {"destdir": destdir})
        return {"status": "ok", "destdir": destdir, "results": results}

    # ---------------- strip binaries ----------------
    def strip_binaries(self, package_name: str, destdir: str, strip_paths: Optional[List[str]] = None, exclude: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Walk destdir and run 'strip' on executable object files under strip_paths.
        exclude: list of glob patterns to skip.
        """
        if not self.strip_binaries_enabled:
            return {"status": "skipped", "reason": "strip_disabled"}

        strip_paths = strip_paths or self.strip_paths
        exclude = exclude or self.strip_exclude

        dest = Path(destdir)
        if not dest.exists():
            return {"status": "error", "reason": "destdir_missing"}

        stripped = []
        errors = []

        # helper to decide file is a candidate: ELF and executable or .so
        def is_candidate(p: Path) -> bool:
            try:
                if not p.is_file():
                    return False
                # skip by exclude globs
                for pat in exclude:
                    if p.match(pat):
                        return False
                # quick heuristic: check suffix or 'file' output
                if p.suffix in (".so", ".so.*"):
                    return True
                # executable bit or ELF header
                if os.access(str(p), os.X_OK):
                    # check ELF magic
                    with p.open("rb") as fh:
                        hdr = fh.read(4)
                        return hdr == b"\x7fELF"
                return False
            except Exception:
                return False

        for rel in strip_paths:
            base = dest / rel.lstrip("/")
            if not base.exists():
                continue
            for p in base.rglob("*"):
                try:
                    if is_candidate(p):
                        # run strip in sandbox if available
                        cmd = ["strip", "--strip-unneeded", str(p)]
                        rc, out, err = self._run(cmd, cwd=str(dest))
                        if rc == 0:
                            stripped.append(str(p))
                        else:
                            errors.append({"file": str(p), "err": err})
                except Exception as e:
                    errors.append({"file": str(p), "err": str(e)})

        self._log("info", "core.strip.done", f"Stripped {len(stripped)} files for {package_name}", stripped=len(stripped), errors=len(errors))
        self._record(package_name, "strip", "ok" if not errors else "partial", {"stripped": len(stripped), "errors": len(errors)})
        return {"status": "ok" if not errors else "partial", "stripped": stripped, "errors": errors}

    # ---------------- package ----------------
    def package(self, package_name: str, version: Optional[str], destdir: str, pkg_format: str = "tar.xz", strip_before: bool = True) -> Dict[str, Any]:
        """
        Create an archive from destdir. Optionally run strip_binaries before packaging.
        Returns path to created package.
        """
        if strip_before:
            try:
                self.strip_binaries(package_name, destdir)
            except Exception as e:
                self._log("warning", "core.package.strip_fail", f"Strip failed: {e}", error=str(e))

        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        name = f"{package_name}-{version or '0'}-{ts}"
        out_path = self.package_output / f"{name}.{pkg_format}"
        try:
            # support tar.xz only for now
            if pkg_format in ("tar.xz", "tar.gz", "tar.bz2"):
                mode = "w:xz" if pkg_format == "tar.xz" else ("w:gz" if pkg_format == "tar.gz" else "w:bz2")
                with tarfile.open(out_path, mode) as tar:
                    tar.add(destdir, arcname=f"{package_name}-{version or '0'}")
            else:
                # fallback to plain tar.xz
                with tarfile.open(out_path, "w:xz") as tar:
                    tar.add(destdir, arcname=f"{package_name}-{version or '0'}")
            self._log("info", "core.package.ok", f"Packaged {package_name} -> {out_path}", package=package_name, path=str(out_path))
            self._record(package_name, "package", "ok", {"out": str(out_path)})
            return {"status": "ok", "package": str(out_path)}
        except Exception as e:
            self._log("error", "core.package.fail", f"Packaging failed: {e}", error=str(e))
            self._record(package_name, "package", "error", {"error": str(e)})
            return {"status": "error", "error": str(e)}

    # ---------------- deploy ----------------
    def deploy(self, package_name: str, package_archive: str, install_prefix: str = "/", use_fakeroot: bool = True, rollback_on_fail: bool = True) -> Dict[str, Any]:
        """
        Deploy package archive to target root (e.g. / or /mnt/lfs).
        Creates a rollback snapshot before applying changes.
        """
        target_root = Path(install_prefix)
        if not target_root.exists():
            raise CoreError(f"Target root {install_prefix} does not exist")

        # backup current layout (simple: backup target if non-empty)
        backup_path = None
        try:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            backup_name = f"{package_name}-predeploy-{ts}.tar.xz"
            backup_path = self.rollback_dir / backup_name
            # tar-add only files under target root that will be affected: for simplicity, backup entire root copy under prefix path if small
            # WARNING: user must configure this responsibly (not recommended to backup '/')
            with tarfile.open(backup_path, "w:xz") as tar:
                # Add top-level paths from the archive: read archive members to determine top-level dirs
                with tarfile.open(package_archive, "r:*") as pa:
                    top_dirs = set()
                    for m in pa.getmembers():
                        parts = Path(m.name).parts
                        if parts:
                            top_dirs.add(parts[0])
                    # backup these from target_root if exist
                    for td in top_dirs:
                        p = target_root / td
                        if p.exists():
                            tar.add(str(p), arcname=str(td))
            self._log("info", "core.deploy.backup", f"Backup created: {backup_path}", backup=str(backup_path))
        except Exception as e:
            self._log("warning", "core.deploy.backup_fail", f"Backup failed: {e}", error=str(e))
            backup_path = None

        # extract archive into target (use fakeroot if needed)
        try:
            # prefer using sandbox.run to extract safely
            if self.sandbox:
                # copy archive into temp under sandbox root and run tar -xf
                tmp = Path(tempfile.mkdtemp(prefix="newpkg_deploy_"))
                local_archive = tmp / Path(package_archive).name
                shutil.copyfile(package_archive, str(local_archive))
                cmd = ["tar", "-C", str(target_root), "-xpf", str(local_archive)]
                if use_fakeroot and shutil.which(self.fakeroot_cmd):
                    cmd = [self.fakeroot_cmd] + cmd
                rc, out, err = self._run(cmd, cwd=str(target_root))
                shutil.rmtree(tmp)
            else:
                # direct extraction
                with tarfile.open(package_archive, "r:*") as tar:
                    tar.extractall(path=str(target_root))
                rc, out, err = 0, "", ""
            if rc == 0:
                self._log("info", "core.deploy.ok", f"Deployed {package_name} to {install_prefix}", package=package_name, prefix=install_prefix)
                self._record(package_name, "deploy", "ok", {"target": install_prefix, "backup": str(backup_path) if backup_path else None})
                return {"status": "ok", "backup": str(backup_path) if backup_path else None}
            else:
                raise CoreError(f"deploy command failed: {err}")
        except Exception as e:
            self._log("error", "core.deploy.fail", f"Deploy failed: {e}", error=str(e))
            self._record(package_name, "deploy", "error", {"error": str(e)})
            # rollback if requested and backup available
            if rollback_on_fail and backup_path and backup_path.exists():
                try:
                    self._log("info", "core.deploy.rollback", f"Attempting rollback using {backup_path}", backup=str(backup_path))
                    with tarfile.open(backup_path, "r:*") as tar:
                        tar.extractall(path=str(target_root))
                    self._log("info", "core.deploy.rollback_ok", "Rollback successful")
                except Exception as re:
                    self._log("error", "core.deploy.rollback_fail", f"Rollback failed: {re}", error=str(re))
            return {"status": "error", "error": str(e)}

    # ---------------- full pipeline ----------------
    def full_build_cycle(self, package_name: str, version: Optional[str] = None, metafile_path: Optional[str] = None, profile: Optional[str] = None, install_prefix: str = "/", do_package: bool = True, do_deploy: bool = False, strip_before_package: bool = True, dry_run: bool = False) -> BuildResult:
        """
        Orchestrates the full build: prepare -> resolve_deps -> build -> install -> strip -> package -> deploy
        """
        result = BuildResult(package=package_name, version=version)
        try:
            # prepare
            prep = self.prepare(package_name, metafile_path=metafile_path, profile=profile)
            workdir = prep["workdir"]
            destdir = prep["destdir"]
            builddir = prep["builddir"]

            result.phases.append({"phase": "prepare", "ok": True, "meta": prep})

            # resolve deps
            deps_res = self.resolve_build_deps(package_name, operate_on_metafile=prep.get("metafile"))
            result.phases.append({"phase": "deps", "deps": deps_res.get("deps", [])})

            if dry_run:
                result.status = "dry-run"
                return result

            # pre-build hook
            try:
                if self.hooks and hasattr(self.hooks, "execute_safe"):
                    self.hooks.execute_safe("pre_build", pkg_dir=workdir)
            except Exception:
                pass

            # build
            build_res = self.build(package_name, workdir, build_cmds=None)
            result.phases.append({"phase": "build", "result": build_res})
            if build_res.get("status") != "ok":
                result.status = "build-fail"
                return result

            # post-build hook
            try:
                if self.hooks and hasattr(self.hooks, "execute_safe"):
                    self.hooks.execute_safe("post_build", pkg_dir=workdir)
            except Exception:
                pass

            # install (fakeroot into destdir)
            install_res = self.install(package_name, workdir, destdir=destdir, use_fakeroot=True)
            result.phases.append({"phase": "install", "result": install_res})
            if install_res.get("status") != "ok":
                result.status = "install-fail"
                return result

            # strip
            if self.strip_binaries_enabled and strip_before_package:
                strip_res = self.strip_binaries(package_name, destdir)
                result.phases.append({"phase": "strip", "result": strip_res})

            # package
            pkg_res = {"status": "skipped"}
            if do_package:
                pkg_res = self.package(package_name, version, destdir, strip_before=False)
                result.phases.append({"phase": "package", "result": pkg_res})
                if pkg_res.get("status") != "ok":
                    result.status = "package-fail"
                    return result

            # deploy
            if do_deploy and pkg_res.get("status") == "ok":
                deploy_res = self.deploy(package_name, pkg_res["package"], install_prefix, use_fakeroot=True)
                result.phases.append({"phase": "deploy", "result": deploy_res})
                if deploy_res.get("status") != "ok":
                    result.status = "deploy-fail"
                    return result

            # success
            result.status = "ok"
            self._record(package_name, "full_build", "ok", {"pkg": str(pkg_res.get("package")) if isinstance(pkg_res, dict) else None})
            return result
        except Exception as e:
            self._log("error", "core.full.fail", f"Full build failed: {e}", error=str(e))
            self._record(package_name, "full_build", "error", {"error": str(e)})
            result.status = "error"
            return result

    # ---------------- CLI convenience ----------------
    @classmethod
    def cli_main(cls, argv: Optional[List[str]] = None):
        import argparse

        p = argparse.ArgumentParser(prog="newpkg-core", description="Newpkg core build pipeline")
        p.add_argument("cmd", choices=["prepare", "build", "install", "strip", "package", "deploy", "full"], help="command")
        p.add_argument("--pkg", required=True, help="package name")
        p.add_argument("--meta", help="metafile path")
        p.add_argument("--workdir", help="workdir override")
        p.add_argument("--version", help="package version")
        p.add_argument("--profile", help="build profile")
        p.add_argument("--destdir", help="destdir for install")
        p.add_argument("--prefix", default="/", help="install prefix for deploy (default: / )")
        p.add_argument("--no-sandbox", action="store_true", help="do not use sandbox")
        p.add_argument("--dry-run", action="store_true", help="dry run")
        p.add_argument("--json", action="store_true", help="output JSON")
        args = p.parse_args(argv)

        cfg = None
        if init_config:
            try:
                cfg = init_config()
            except Exception:
                cfg = None

        db = NewpkgDB(cfg) if NewpkgDB and cfg is not None else None
        logger = NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None
        sandbox = Sandbox(cfg, logger, db) if Sandbox and cfg is not None else None

        core = cls(cfg=cfg, logger=logger, db=db, sandbox=sandbox)
        if args.no_sandbox:
            core.use_sandbox = False

        if args.cmd == "prepare":
            res = core.prepare(args.pkg, metafile_path=args.meta, profile=args.profile, workdir=args.workdir)
            print(json.dumps(res, indent=2) if args.json else res)
            return 0
        if args.cmd == "build":
            res = core.build(args.pkg, args.workdir or str(core.work_root / args.pkg))
            print(json.dumps(res, indent=2) if args.json else res)
            return 0
        if args.cmd == "install":
            res = core.install(args.pkg, args.workdir or str(core.work_root / args.pkg), destdir=args.destdir)
            print(json.dumps(res, indent=2) if args.json else res)
            return 0
        if args.cmd == "strip":
            res = core.strip_binaries(args.pkg, args.destdir or str(core.work_root / args.pkg / "destdir"))
            print(json.dumps(res, indent=2) if args.json else res)
            return 0
        if args.cmd == "package":
            res = core.package(args.pkg, args.version, args.destdir or str(core.work_root / args.pkg / "destdir"))
            print(json.dumps(res, indent=2) if args.json else res)
            return 0
        if args.cmd == "deploy":
            # expect an archive path
            if not args.meta:
                print("deploy requires --meta to point to package archive path (or use --meta=archive_path)")
                return 2
            res = core.deploy(args.pkg, args.meta, install_prefix=args.prefix)
            print(json.dumps(res, indent=2) if args.json else res)
            return 0
        if args.cmd == "full":
            res = core.full_build_cycle(args.pkg, version=args.version, metafile_path=args.meta, profile=args.profile, install_prefix=args.prefix, do_package=True, do_deploy=False, dry_run=args.dry_run)
            # BuildResult is dataclass; convert
            out = {"package": res.package, "version": res.version, "status": res.status, "phases": res.phases, "metrics": res.metrics}
            print(json.dumps(out, indent=2) if args.json else out)
            return 0
        return 1


if __name__ == "__main__":
    NewpkgCore.cli_main()
