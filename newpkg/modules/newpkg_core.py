"""
newpkg_core.py

Core orchestration for newpkg builds: prepares sandboxed build environments,
resolves deps, runs builds, installs via fakeroot into DESTDIR, packages artifacts
(tar.xz / tar.gz / tar.zst placeholder), deploys to target (/, /mnt/lfs) with rollback,
records metadata in NewpkgDB and emits structured logs via NewpkgLogger.

This implementation is opinionated but modular: it relies on provided helper
objects `cfg`, `db`, `logger`, `sandbox`, `deps` implementing the APIs
described in the other modules created earlier.

Notes:
- It uses `sandbox.run()` to execute commands inside a bwrap environment.
- It attempts to use `fakeroot` when available. If not present, it will run
  install steps without fakeroot and log a warning.
- Packaging supports 'tar.xz', 'tar.gz', and 'tar.bz2' via shutil.make_archive.
  Zstd (tar.zst) is only supported if additional tooling is present (placeholder).

This file is intended as a high-level orchestrator. Lower-level build logic
(specific configure flags, complex packaging formats) should be implemented
in package-specific modules and invoked through hooks.
"""
from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
import subprocess
import hashlib
import json
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from contextlib import contextmanager


class CoreError(Exception):
    pass


class NewpkgCore:
    def __init__(self, cfg: Any, db: Any, logger: Any, sandbox: Any, deps: Any):
        self.cfg = cfg
        self.db = db
        self.logger = logger
        self.sandbox = sandbox
        self.deps = deps

        # config defaults
        self.build_root = Path(self.cfg.get("NEWPKG_BUILD_ROOT") if self.cfg else ("/var/tmp/newpkg"))
        self.destdir_base = Path(self.cfg.get("NEWPKG_DESTDIR") if self.cfg else (self.build_root / "dest"))
        self.package_root = Path(self.cfg.get("NEWPKG_PACKAGE_ROOT") if self.cfg else (self.build_root / "packages"))
        self.compress_format = (self.cfg.get("NEWPKG_COMPRESS_FORMAT") if self.cfg else "tar.xz")
        self.profiles = {}
        try:
            self.profiles = self.cfg.get("profiles") or {}
        except Exception:
            self.profiles = {}

        # ensure directories
        for d in (self.build_root, self.destdir_base, self.package_root):
            try:
                Path(d).mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

    # ---------------- utilities ----------------
    def _log(self, event: str, level: str = "INFO", message: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        if self.logger:
            self.logger.log_event(event, level=level, message=message or event, metadata=metadata or {})

    def _now(self) -> str:
        return datetime.utcnow().isoformat() + "Z"

    def _pkg_build_dir(self, pkg_name: str, version: Optional[str] = None) -> Path:
        if version:
            name = f"{pkg_name}-{version}"
        else:
            name = pkg_name
        return self.build_root / name

    def _pkg_destdir(self, pkg_name: str, version: Optional[str] = None) -> Path:
        return self.destdir_base / (f"{pkg_name}-{version}" if version else pkg_name)

    def _pkg_package_dir(self, pkg_name: str, version: Optional[str] = None) -> Path:
        return self.package_root / (f"{pkg_name}-{version}" if version else pkg_name)

    def _safe_run_in_sandbox(self, cmd: List[str], cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        # wrapper to call sandbox.run and normalize output
        if not self.sandbox:
            raise CoreError("Sandbox not configured for core operations")
        res = self.sandbox.run(cmd, cwd=cwd, env=env, timeout=timeout)
        return res.returncode, res.stdout, res.stderr

    def _use_fakeroot(self) -> bool:
        return shutil.which("fakeroot") is not None

    def _fakeroot_wrap(self, inner_cmd: str) -> List[str]:
        # returns a command list that runs inner_cmd under fakeroot
        if self._use_fakeroot():
            return ["fakeroot", "--", "/bin/sh", "-lc", inner_cmd]
        # fallback: run with /bin/sh -c (no fakeroot)
        self._log("core.fakeroot_missing", level="WARNING", message="fakeroot not found, install step will run without fakeroot")
        return ["/bin/sh", "-lc", inner_cmd]

    # ---------------- prepare ----------------
    def prepare(self, pkg_name: str, version: Optional[str] = None, profile: str = "default", src_dir: Optional[Path] = None) -> Path:
        """Prepare build workspace and copy sources into sandboxable build dir.

        Returns the build_dir Path.
        """
        build_dir = self._pkg_build_dir(pkg_name, version)
        destdir = self._pkg_destdir(pkg_name, version)
        pkg_dir = self._pkg_package_dir(pkg_name, version)

        # create dirs
        for d in (build_dir, destdir, pkg_dir):
            Path(d).mkdir(parents=True, exist_ok=True)

        # copy sources if provided
        if src_dir:
            src_dir = Path(src_dir)
            if not src_dir.exists():
                raise CoreError(f"src_dir not found: {src_dir}")
            # copy tree to build_dir/sources
            target_src = build_dir / 'sources'
            if target_src.exists():
                shutil.rmtree(target_src)
            shutil.copytree(src_dir, target_src)

        # create build script placeholder if not exists
        build_sh = build_dir / 'build.sh'
        if not build_sh.exists():
            build_sh.write_text("#!/bin/sh\necho 'No build script provided'\n", encoding='utf-8')
            build_sh.chmod(build_sh.stat().st_mode | stat.S_IXUSR)

        # log
        self._log("build_prepare", level="INFO", message=f"Prepared build for {pkg_name}", metadata={"pkg": pkg_name, "build_dir": str(build_dir)})
        return build_dir

    # ---------------- hooks ----------------
    def _run_hook(self, hook_path: Path, build_dir: Path, destdir: Path, profile_vars: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
        if not hook_path.exists():
            return 0, "", ""
        # ensure executable
        try:
            hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR)
        except Exception:
            pass
        cmd = ["/bin/sh", str(hook_path)]
        env = os.environ.copy()
        if profile_vars:
            env.update({k: str(v) for k, v in profile_vars.items()})
        return self._safe_run_in_sandbox(cmd, cwd=build_dir, env=env)

    # ---------------- build ----------------
    def build(self, pkg_name: str, version: Optional[str] = None, profile: str = "default", src_dir: Optional[Path] = None, timeout: Optional[int] = None) -> None:
        build_dir = self.prepare(pkg_name, version, profile, src_dir=src_dir)
        destdir = self._pkg_destdir(pkg_name, version)

        # resolve build deps
        try:
            build_deps = self.deps.resolve(pkg_name, dep_type='build')
            if build_deps:
                self._log('deps_resolve', level='INFO', message='Resolved build deps', metadata={'pkg': pkg_name, 'deps': build_deps})
        except Exception:
            build_deps = []

        profile_vars = {}
        if profile and self.profiles and profile in self.profiles:
            profile_vars = self.profiles[profile]

        # run pre_build hook
        pre_hook = build_dir / 'hooks' / 'pre_build.sh'
        rc, out, err = self._run_hook(pre_hook, build_dir, destdir, profile_vars=profile_vars)
        if rc != 0:
            self._log('hook.pre_build.fail', level='ERROR', message='pre_build hook failed', metadata={'pkg': pkg_name, 'rc': rc, 'stderr': err})
            raise CoreError(f'pre_build hook failed for {pkg_name}: {err}')

        # execute build.sh inside sandbox
        build_sh = build_dir / 'build.sh'
        if not build_sh.exists():
            raise CoreError(f'No build.sh found for {pkg_name} in {build_dir}')

        self._log('build_start', level='INFO', message=f'Starting build {pkg_name}', metadata={'pkg': pkg_name, 'build_dir': str(build_dir)})
        rc, out, err = self._safe_run_in_sandbox(['/bin/sh', str(build_sh)], cwd=build_dir, env=profile_vars, timeout=timeout)
        if rc != 0:
            self._log('build_fail', level='ERROR', message=f'Build failed for {pkg_name}', metadata={'pkg': pkg_name, 'rc': rc, 'stderr': err})
            raise CoreError(f'Build failed for {pkg_name}: {err}')

        self._log('build_end', level='INFO', message=f'Build finished for {pkg_name}', metadata={'pkg': pkg_name})

    # ---------------- install ----------------
    def install(self, pkg_name: str, version: Optional[str] = None, fakeroot: bool = True, make_install_cmd: Optional[str] = None, timeout: Optional[int] = None) -> None:
        build_dir = self._pkg_build_dir(pkg_name, version)
        destdir = self._pkg_destdir(pkg_name, version)
        destdir.mkdir(parents=True, exist_ok=True)

        # run pre_install hook
        pre_hook = build_dir / 'hooks' / 'pre_install.sh'
        rc, out, err = self._run_hook(pre_hook, build_dir, destdir)
        if rc != 0:
            raise CoreError(f'pre_install hook failed: {err}')

        # determine install command
        if make_install_cmd:
            inner = make_install_cmd
        else:
            inner = f"make install DESTDIR={destdir}"

        full_cmd = self._fakeroot_wrap(inner) if fakeroot else ["/bin/sh", "-lc", inner]

        # run inside sandbox: we run fakeroot wrapper command under shell; sandbox.run accepts array
        rc, out, err = self._safe_run_in_sandbox(full_cmd, cwd=build_dir, timeout=timeout)
        if rc != 0:
            self._log('install_fail', level='ERROR', message=f'Install failed for {pkg_name}', metadata={'pkg': pkg_name, 'stderr': err})
            raise CoreError(f'Install failed for {pkg_name}: {err}')

        # post_install hook
        post_hook = build_dir / 'hooks' / 'post_install.sh'
        rc2, out2, err2 = self._run_hook(post_hook, build_dir, destdir)
        if rc2 != 0:
            self._log('hook.post_install.fail', level='WARNING', message='post_install hook failed', metadata={'pkg': pkg_name, 'stderr': err2})

        self._log('install_end', level='INFO', message=f'Installed {pkg_name} into destdir', metadata={'pkg': pkg_name, 'destdir': str(destdir)})

    # ---------------- package ----------------
    def package(self, pkg_name: str, version: Optional[str] = None, compress: Optional[str] = None) -> Path:
        if compress is None:
            compress = self.compress_format or 'tar.xz'
        destdir = self._pkg_destdir(pkg_name, version)
        pkgdir = self._pkg_package_dir(pkg_name, version)
        pkgdir.mkdir(parents=True, exist_ok=True)

        # generate files list and pkginfo
        files_list = []
        for p in sorted(destdir.rglob('*')):
            if p.is_file():
                rel = p.relative_to(destdir)
                files_list.append(str(rel))
        (pkgdir / 'files.list').write_text('\n'.join(files_list), encoding='utf-8')

        pkginfo = {'name': pkg_name, 'version': version, 'build_time': self._now(), 'profile': None}
        (pkgdir / 'pkginfo.json').write_text(json.dumps(pkginfo, indent=2), encoding='utf-8')

        # produce an archive of destdir
        base_name = str(pkgdir / f"{pkg_name}-{version}" if version else pkgdir / pkg_name)
        fmt = None
        if compress in ('tar.xz', 'xztar'):
            fmt = 'xztar'
        elif compress in ('tar.gz', 'gztar'):
            fmt = 'gztar'
        elif compress in ('tar.bz2', 'bztar'):
            fmt = 'bztar'
        else:
            # fallback to xz
            fmt = 'xztar'

        try:
            archive_path = shutil.make_archive(base_name=base_name, format=fmt, root_dir=destdir)
        except Exception as e:
            raise CoreError(f'Failed to create package archive: {e}')

        # compute hash
        h = hashlib.sha256()
        with open(archive_path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        digest = h.hexdigest()

        # write pkginfo with hash
        pkginfo['hash'] = f'sha256:{digest}'
        (pkgdir / 'pkginfo.json').write_text(json.dumps(pkginfo, indent=2), encoding='utf-8')

        self._log('package_created', level='INFO', message='Package created', metadata={'pkg': pkg_name, 'archive': archive_path, 'hash': digest})
        return Path(archive_path)

    # ---------------- deploy with rollback ----------------
    def deploy(self, pkg_name: str, version: Optional[str] = None, archive: Optional[Path] = None, target: str = '/', rollback: bool = True) -> None:
        # ensure archive
        if archive is None:
            pkgdir = self._pkg_package_dir(pkg_name, version)
            archive_glob = list(pkgdir.glob(f"{pkg_name}-{version}*"))
            if not archive_glob:
                raise CoreError('No package archive found to deploy')
            archive = archive_glob[0]

        target_path = Path(target)
        if not target_path.exists():
            raise CoreError(f'Target path not found: {target}')

        snapshot = None
        if rollback:
            # create a lightweight snapshot by copying tree to temp dir
            snapshot = tempfile.mkdtemp(prefix='newpkg-snap-')
            try:
                # careful: copying entire / can be huge; user must ensure target is appropriate (/ or /mnt/lfs)
                shutil.copytree(target_path, snapshot, dirs_exist_ok=True)
            except Exception as e:
                # if snapshot fails, we continue but mark that rollback may not work
                self._log('deploy_snapshot_fail', level='WARNING', message='Snapshot failed', metadata={'error': str(e)})
                snapshot = None

        # extract archive into target (use tar via system to preserve permissions) inside sandbox
        # using sandbox.run to restrict scope
        extract_cmd = ["/bin/sh", "-lc", f"tar -C {str(target_path)} -xf {str(archive)}"]
        rc, out, err = self._safe_run_in_sandbox(extract_cmd, cwd=None)
        if rc != 0:
            self._log('deploy_fail', level='ERROR', message='Deploy failed', metadata={'pkg': pkg_name, 'err': err})
            # attempt rollback
            if snapshot:
                try:
                    # restore snapshot
                    shutil.rmtree(target_path)
                    shutil.copytree(snapshot, target_path)
                    self._log('deploy_rollback', level='INFO', message='Rollback applied', metadata={'pkg': pkg_name})
                except Exception as e:
                    self._log('deploy_rollback_fail', level='ERROR', message='Rollback failed', metadata={'pkg': pkg_name, 'error': str(e)})
            raise CoreError(f'Deploy failed: {err}')

        self._log('deploy_success', level='INFO', message='Deploy finished', metadata={'pkg': pkg_name, 'target': target})

        # cleanup snapshot
        if snapshot:
            try:
                shutil.rmtree(snapshot)
            except Exception:
                pass

    # ---------------- record ----------------
    def record(self, pkg_name: str, version: Optional[str] = None) -> None:
        destdir = self._pkg_destdir(pkg_name, version)
        if not destdir.exists():
            raise CoreError('Destdir missing for record')

        # register package
        try:
            pkg_id = self.db.add_package(pkg_name, version, 1, origin='newpkg', status='built', build_dir=str(self._pkg_build_dir(pkg_name, version)), install_dir=str(destdir))
        except Exception:
            pkg_id = None

        # walk files and register
        for p in sorted(destdir.rglob('*')):
            if p.is_file():
                try:
                    st = p.stat()
                    size = st.st_size
                    h = hashlib.sha256()
                    with p.open('rb') as fh:
                        for chunk in iter(lambda: fh.read(65536), b''):
                            h.update(chunk)
                    digest = h.hexdigest()
                    owner = None
                    group = None
                    try:
                        owner = str(st.st_uid)
                        group = str(st.st_gid)
                    except Exception:
                        pass
                    if pkg_id:
                        try:
                            self.db.record_file(pkg_name, str(p), size=size, hash=digest, mode=st.st_mode, owner=owner, groupname=group)
                        except Exception:
                            pass
                except Exception:
                    continue

        self._log('record_done', level='INFO', message='Recorded package files in DB', metadata={'pkg': pkg_name})

    # ---------------- clean ----------------
    def clean(self, pkg_name: str, version: Optional[str] = None, keep_logs: bool = True) -> None:
        build_dir = self._pkg_build_dir(pkg_name, version)
        pkgdir = self._pkg_package_dir(pkg_name, version)
        if build_dir.exists():
            shutil.rmtree(build_dir, ignore_errors=True)
        if not keep_logs and pkgdir.exists():
            shutil.rmtree(pkgdir, ignore_errors=True)
        self._log('clean', level='INFO', message=f'Cleaned build artifacts for {pkg_name}', metadata={'pkg': pkg_name})

    # ---------------- integrity ----------------
    def verify_integrity(self, pkg_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        pkgdir = self._pkg_package_dir(pkg_name, version)
        files_list_file = pkgdir / 'files.list'
        result = {'pkg': pkg_name, 'ok': True, 'missing': [], 'mismatched': []}
        if not files_list_file.exists():
            result['ok'] = False
            return result
        destdir = self._pkg_destdir(pkg_name, version)
        for line in files_list_file.read_text(encoding='utf-8').splitlines():
            p = destdir / line
            if not p.exists():
                result['missing'].append(str(p))
                result['ok'] = False
            else:
                # optionally verify hashes if stored in pkginfo
                pass
        return result

    # ---------------- run arbitrary stage ----------------
    def run_stage(self, pkg_name: str, stage: str, version: Optional[str] = None) -> None:
        build_dir = self._pkg_build_dir(pkg_name, version)
        script = build_dir / 'hooks' / f"{stage}.sh"
        if not script.exists():
            raise CoreError(f'Stage script not found: {script}')
        rc, out, err = self._safe_run_in_sandbox(['/bin/sh', str(script)], cwd=build_dir)
        if rc != 0:
            raise CoreError(f'Stage {stage} failed: {err}')

    # ---------------- auto rebuild on dependency change ----------------
    def rebuild_if_changed(self, pkg_name: str) -> None:
        # trivial hook: if any build deps have updated version in DB, rebuild
        # (domain specific; here we simply log the check)
        self._log('rebuild_check', level='INFO', message=f'Checking rebuild need for {pkg_name}', metadata={'pkg': pkg_name})
        # could implement version comparisons using db.get_package
        return


# ---------------- CLI demo ----------------
if __name__ == '__main__':
    import argparse

    ap = argparse.ArgumentParser(prog='newpkg-core')
    ap.add_argument('--pkg', '-p', required=True)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--install', action='store_true')
    ap.add_argument('--package', action='store_true')
    ap.add_argument('--deploy', action='store_true')
    ap.add_argument('--record', action='store_true')
    ap.add_argument('--clean', action='store_true')
    args = ap.parse_args()

    # minimal bootstrap for demo
    try:
        from newpkg_db import NewpkgDB
    except Exception:
        NewpkgDB = None
    cfg = None
    try:
        class CfgShim:
            def get(self, k):
                return None
        cfg = CfgShim()
    except Exception:
        cfg = None

    db = None
    if NewpkgDB is not None:
        dbp = os.environ.get('NEWPKG_DB_PATH')
        if dbp:
            db = NewpkgDB(db_path=dbp)
            db.init_db()

    core = NewpkgCore(cfg, db, logger=None, sandbox=None, deps=None)
    if args.build:
        core.build(args.pkg)
    if args.install:
        core.install(args.pkg)
    if args.package:
        core.package(args.pkg)
    if args.deploy:
        core.deploy(args.pkg)
    if args.record:
        core.record(args.pkg)
    if args.clean:
        core.clean(args.pkg)
