#!/usr/bin/env python3
"""
newpkg_upgrade.py

Upgrade manager for newpkg — safe, sandboxed, and integrated with the newpkg ecosystem.

Features implemented:
 - check_updates(pkg): check remote for newer versions (git tags or configured source in DB/metafile)
 - fetch_new_source(pkg): download/clone new source (uses newpkg_download / newpkg_sync if available)
 - upgrade(pkg, force=False): perform full upgrade: fetch -> build -> install -> package -> deploy (optionally) with backup+rollback
 - batch_upgrade(pkgs, parallel): run upgrades in parallel with structured results
 - rebuild(pkg): rebuild current version using core.full_build_cycle
 - rollback(pkg, archive): restore backup and re-register package in DB
 - verify_integrity(pkg): run basic integrity checks after upgrade
 - clean_old_versions(pkg, keep=1): keep latest N packages, remove old archives/backups

Design notes:
 - Integrates with newpkg_config, newpkg_logger, newpkg_db, newpkg_hooks, newpkg_sandbox, newpkg_core, newpkg_remove, newpkg_deps when available
 - Uses thread pool for parallel upgrades
 - Records phases via db.record_phase if available
 - Uses sandbox.run for executing external commands
 - Creates backups in upgrade.backup_dir prior to destructive operations

This module is defensive: missing optional modules will be gracefully skipped with warnings.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# optional internal imports
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
    from newpkg_core import NewpkgCore
except Exception:
    NewpkgCore = None

try:
    from newpkg_remove import NewpkgRemover
except Exception:
    NewpkgRemover = None

try:
    from newpkg_deps import NewpkgDeps
except Exception:
    NewpkgDeps = None

try:
    from newpkg_download import NewpkgDownloader
except Exception:
    NewpkgDownloader = None

# defaults
DEFAULT_BACKUP_DIR = Path(os.environ.get("NEWPKG_UPGRADE_BACKUP", "/var/tmp/newpkg_upgrades"))
DEFAULT_PARALLEL = int(os.environ.get("NEWPKG_UPGRADE_PARALLEL", "4"))

DEFAULT_PACKAGE_OUTPUT = Path(os.environ.get("NEWPKG_PACKAGE_OUTPUT", "./packages"))

DEFAULT_FAKERROOT = os.environ.get("NEWPKG_FAKEROOT_CMD", "fakeroot")


@dataclass
class UpgradeResult:
    package: str
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    status: str = "unknown"
    steps: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    backup: Optional[str] = None


class UpgradeError(Exception):
    pass


class NewpkgUpgrade:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.logger = logger or (NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None)
        self.db = db or (NewpkgDB(cfg) if NewpkgDB and cfg is not None else None)
        self.hooks = hooks or (HooksManager(cfg, self.logger, self.db) if HooksManager and cfg is not None else None)
        self.sandbox = sandbox or (Sandbox(cfg, self.logger, self.db) if Sandbox and cfg is not None else None)
        self.core = NewpkgCore(cfg, self.logger, self.db) if NewpkgCore and cfg is not None else None
        self.remover = NewpkgRemover(cfg, self.logger, self.db) if NewpkgRemover and cfg is not None else None
        self.deps = NewpkgDeps(cfg, self.logger, self.db) if NewpkgDeps and cfg is not None else None
        self.downloader = NewpkgDownloader(cfg, self.logger, self.db) if NewpkgDownloader and cfg is not None else None

        self.backup_dir = Path(self._cfg_get("upgrade.backup_dir", str(DEFAULT_BACKUP_DIR)))
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.parallel = int(self._cfg_get("upgrade.parallel", DEFAULT_PARALLEL))
        self.package_output = Path(self._cfg_get("core.package_output", str(DEFAULT_PACKAGE_OUTPUT)))
        self.fakeroot_cmd = self._cfg_get("core.fakeroot_cmd", DEFAULT_FAKERROOT)
        self.verify_after = bool(self._cfg_get("upgrade.verify_after", True))
        self.allow_force = bool(self._cfg_get("upgrade.allow_force", False))

    # ---------------- helpers ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return os.environ.get(key.upper().replace('.', '_'), default)

    def _log(self, level: str, event: str, message: str = "", **meta):
        if self.logger:
            try:
                fn = getattr(self.logger, level.lower(), None)
                if fn:
                    fn(event, message, **meta)
                    return
            except Exception:
                pass
        print(f"[{level}] {event}: {message}")

    def _record(self, pkg: str, phase: str, status: str, meta: Optional[Dict[str, Any]] = None):
        if self.db and hasattr(self.db, 'record_phase'):
            try:
                self.db.record_phase(pkg, phase, status, meta or {})
            except Exception:
                pass

    def _repo_info_from_db(self, pkg: str) -> Dict[str, Any]:
        """Return package metadata from DB if available."""
        try:
            if self.db and hasattr(self.db, 'get_package'):
                return self.db.get_package(pkg) or {}
        except Exception:
            pass
        return {}

    # ---------------- backup / rollback ----------------
    def _create_backup(self, pkg: str) -> Optional[str]:
        """Create a backup archive (.tar.xz) of installed files for pkg using DB list_files or heuristics."""
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        out = self.backup_dir / f"{pkg}-upgrade-{ts}.tar.xz"
        targets = []
        try:
            if self.db and hasattr(self.db, 'list_files'):
                targets = self.db.list_files(pkg)
        except Exception:
            targets = []
        # fallback heuristics
        if not targets:
            heur = [f"/usr/lib/{pkg}", f"/usr/share/{pkg}", f"/etc/{pkg}", f"/opt/{pkg}"]
            for h in heur:
                if Path(h).exists():
                    targets.append(h)
        if not targets:
            self._log('warning', 'upgrade.backup.skip', f'No targets found to backup for {pkg}')
            return None
        try:
            with tarfile.open(out, 'w:xz') as tar:
                for t in targets:
                    try:
                        tar.add(t, arcname=str(Path(t).relative_to('/')))
                    except Exception:
                        # best-effort: add by name
                        try:
                            tar.add(t)
                        except Exception:
                            continue
            self._log('info', 'upgrade.backup.ok', f'Backup created for {pkg}: {out}', backup=str(out))
            return str(out)
        except Exception as e:
            self._log('error', 'upgrade.backup.fail', f'Backup failed for {pkg}: {e}', error=str(e))
            return None

    def rollback(self, pkg: str, archive: str) -> bool:
        """Restore package files from archive and register in DB if possible."""
        try:
            arch = Path(archive)
            if not arch.exists():
                raise UpgradeError(f'archive {archive} not found')
            # extract to temporary dir and move into place
            tmp = Path(tempfile.mkdtemp(prefix=f'newpkg_rollback_{pkg}_'))
            with tarfile.open(arch, 'r:*') as tar:
                tar.extractall(path=str(tmp))
            # copy back
            for item in tmp.iterdir():
                dest = Path('/') / item.name
                if dest.exists():
                    if dest.is_dir():
                        shutil.rmtree(dest)
                    else:
                        dest.unlink()
                shutil.move(str(item), str(dest))
            shutil.rmtree(tmp)
            # record
            self._record(pkg, 'rollback', 'ok', {'archive': str(archive)})
            self._log('info', 'upgrade.rollback.ok', f'Rollback completed for {pkg}', archive=str(archive))
            return True
        except Exception as e:
            self._record(pkg, 'rollback', 'error', {'error': str(e)})
            self._log('error', 'upgrade.rollback.fail', f'Rollback failed for {pkg}: {e}', error=str(e))
            return False

    # ---------------- checking updates ----------------
    def check_updates(self, pkg: str) -> Optional[Dict[str, Any]]:
        """Check for available updates for a package.
        Strategies:
         - If DB/metafile contains source/git url: check git tags or remote version
         - Otherwise return None
        Returns dict with keys: pkg, current_version, candidate_version, source
        """
        info = self._repo_info_from_db(pkg)
        current = info.get('version')
        source = info.get('origin') or info.get('source')
        candidate = None
        try:
            # if source is git repo, try to fetch tags
            if source and isinstance(source, str) and source.startswith('git+'):
                giturl = source.split('+', 1)[1]
                # shallow clone to temp and get latest tag
                tmp = Path(tempfile.mkdtemp(prefix=f'newpkg_check_{pkg}_'))
                try:
                    cmd = ['git', 'clone', '--bare', '--depth', '1', giturl, str(tmp)]
                    rc = 1
                    if self.sandbox:
                        r = self.sandbox.run(cmd, cwd=None)
                        rc = int(r.rc)
                    else:
                        p = subprocess.run(cmd, capture_output=True)
                        rc = p.returncode
                    if rc == 0:
                        # list tags
                        cmd2 = ['git', '--git-dir', str(tmp), 'tag', '--sort=-creatordate']
                        out = subprocess.check_output(cmd2, text=True)
                        tags = [t.strip() for t in out.splitlines() if t.strip()]
                        if tags:
                            candidate = tags[0]
                finally:
                    try:
                        shutil.rmtree(tmp)
                    except Exception:
                        pass
            # else if source lists a version field in DB, use remote mirrors (not implemented)
        except Exception as e:
            self._log('warning', 'upgrade.check.fail', f'Failed to check updates for {pkg}: {e}')
        if candidate and candidate != current:
            res = {'pkg': pkg, 'current': current, 'candidate': candidate, 'source': source}
            self._log('info', 'upgrade.check.found', f'Candidate found for {pkg}: {candidate}', **res)
            return res
        self._log('info', 'upgrade.check.none', f'No update found for {pkg}', package=pkg)
        return None

    # ---------------- fetch new source ----------------
    def fetch_new_source(self, pkg: str, dest: Optional[str] = None) -> Optional[str]:
        """Fetch/clone the new source into a temp directory and return path. Uses NewpkgDownloader if available."""
        info = self._repo_info_from_db(pkg)
        source = info.get('origin') or info.get('source')
        if not source:
            self._log('warning', 'upgrade.fetch.no_source', f'No source for {pkg} in DB')
            return None
        tmp = Path(tempfile.mkdtemp(prefix=f'newpkg_source_{pkg}_'))
        try:
            # if git url
            if isinstance(source, str) and source.startswith('git+'):
                giturl = source.split('+', 1)[1]
                cmd = ['git', 'clone', giturl, str(tmp)]
                rc, out, err = (1, '', '')
                if self.sandbox:
                    res = self.sandbox.run(cmd)
                    rc, out, err = int(res.rc), res.out or '', res.err or ''
                else:
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    rc, out, err = proc.returncode, proc.stdout, proc.stderr
                if rc == 0:
                    self._log('info', 'upgrade.fetch.ok', f'Cloned source for {pkg} to {tmp}', path=str(tmp))
                    return str(tmp)
                else:
                    self._log('error', 'upgrade.fetch.fail', f'Git clone failed for {pkg}: {err}')
                    shutil.rmtree(tmp)
                    return None
            # otherwise, if Download helper available and source is URL, use it
            if self.downloader and isinstance(source, str):
                # dest path
                dest = dest or str(tmp)
                try:
                    out = self.downloader.download_sync(source, dest=dest)
                    self._log('info', 'upgrade.fetch.ok', f'Downloaded source for {pkg} to {dest}', path=str(dest))
                    return str(dest)
                except Exception as e:
                    self._log('error', 'upgrade.fetch.fail', f'Download failed: {e}')
                    shutil.rmtree(tmp)
                    return None
        except Exception as e:
            self._log('error', 'upgrade.fetch.error', f'Error fetching source for {pkg}: {e}')
        return None

    # ---------------- upgrade flow ----------------
    def upgrade(self, pkg: str, force: bool = False, do_package: bool = True, do_deploy: bool = False, dry_run: bool = False) -> UpgradeResult:
        """Perform an upgrade for a single package.
        Steps:
          - check current metadata
          - create backup (best-effort)
          - fetch new source (if available)
          - build/install/package via core.full_build_cycle
          - verify and deploy
          - cleanup and register new version in DB
        """
        result = UpgradeResult(package=pkg)
        try:
            info = self._repo_info_from_db(pkg)
            old_version = info.get('version')
            result.old_version = old_version

            self._log('info', 'upgrade.start', f'Starting upgrade for {pkg}', package=pkg, old_version=old_version)
            self._record(pkg, 'upgrade', 'start', {'old_version': old_version})

            # pre-upgrade hook
            try:
                if self.hooks and hasattr(self.hooks, 'execute_safe'):
                    self.hooks.execute_safe('pre_upgrade', pkg_dir=None)
            except Exception:
                pass

            # backup
            backup = self._create_backup(pkg)
            result.backup = backup
            if backup:
                result.steps.append({'phase': 'backup', 'status': 'ok', 'path': backup})
            else:
                result.steps.append({'phase': 'backup', 'status': 'skipped'})

            # check for updates/candidate
            check = self.check_updates(pkg)
            candidate_tag = None
            if check:
                candidate_tag = check.get('candidate')
                result.new_version = candidate_tag
                result.steps.append({'phase': 'check', 'status': 'found', 'candidate': candidate_tag})
            else:
                if not force:
                    result.steps.append({'phase': 'check', 'status': 'none'})
                    result.status = 'no-update'
                    self._record(pkg, 'upgrade', 'no-update')
                    return result
                result.steps.append({'phase': 'check', 'status': 'force'})

            if dry_run:
                result.status = 'dry-run'
                self._record(pkg, 'upgrade', 'dry-run')
                return result

            # fetch source
            srcpath = self.fetch_new_source(pkg)
            if not srcpath and not force:
                result.status = 'fetch-fail'
                self._record(pkg, 'upgrade', 'fetch-fail')
                return result
            result.steps.append({'phase': 'fetch', 'status': 'ok' if srcpath else 'skipped', 'path': srcpath})

            # attempt full build cycle using core; prefer to pass metafile if available in DB
            metafile = info.get('metafile') if isinstance(info, dict) else None

            if self.core:
                # use a unique workdir under work_root
                workdir = None
                try:
                    workdir = None
                    prep = self.core.prepare(pkg, metafile_path=metafile, profile=None)
                    workdir = prep.get('workdir')
                except Exception:
                    workdir = None
                # if we have fetched source, copy into workdir/sources
                if srcpath and workdir:
                    try:
                        srcdest = Path(workdir) / 'sources'
                        # remove any existing and copy new
                        if srcdest.exists():
                            shutil.rmtree(srcdest)
                        shutil.copytree(srcpath, srcdest)
                        self._log('info', 'upgrade.copy_source', f'Copied source into workdir for {pkg}', src=srcpath, dest=str(srcdest))
                    except Exception as e:
                        self._log('warning', 'upgrade.copy_source_fail', f'Copying source failed: {e}')
                # build
                self._log('info', 'upgrade.build.start', f'Building {pkg} in sandbox', package=pkg)
                build_res = self.core.full_build_cycle(pkg, version=result.new_version, metafile_path=metafile, profile=None, install_prefix='/', do_package=do_package, do_deploy=False, dry_run=False)
                result.steps.append({'phase': 'build', 'result': build_res.__dict__ if hasattr(build_res, '__dict__') else build_res})
                if build_res.status != 'ok':
                    result.status = 'build-fail'
                    self._record(pkg, 'upgrade', 'build-fail')
                    # attempt rollback
                    if backup:
                        self.rollback(pkg, backup)
                    return result
            else:
                self._log('warning', 'upgrade.no_core', 'No core module; cannot build')
                result.steps.append({'phase': 'build', 'status': 'skipped', 'note': 'no-core'})

            # package path determination
            package_archive = None
            if do_package and self.package_output.exists():
                # pick most recent archive for pkg in output dir
                candidates = sorted(self.package_output.glob(f"{pkg}*.tar.*"), key=lambda p: p.stat().st_mtime, reverse=True)
                if candidates:
                    package_archive = str(candidates[0])
            result.steps.append({'phase': 'package', 'archive': package_archive})

            # optional verification
            if self.verify_after and package_archive:
                ok = self.verify_integrity(pkg, package_archive)
                result.steps.append({'phase': 'verify', 'ok': ok})
                if not ok:
                    result.status = 'verify-fail'
                    self._record(pkg, 'upgrade', 'verify-fail')
                    if backup:
                        self.rollback(pkg, backup)
                    return result

            # deploy (if requested)
            if do_deploy and package_archive:
                dep = self.core.deploy(pkg, package_archive, install_prefix='/', use_fakeroot=True, rollback_on_fail=True)
                result.steps.append({'phase': 'deploy', 'result': dep})
                if dep.get('status') != 'ok':
                    result.status = 'deploy-fail'
                    self._record(pkg, 'upgrade', 'deploy-fail')
                    if backup:
                        self.rollback(pkg, backup)
                    return result

            # update DB record to new version if possible
            try:
                if self.db and hasattr(self.db, 'update_package'):
                    newv = result.new_version or info.get('version')
                    self.db.update_package(pkg, version=newv)
                    self._log('info', 'upgrade.db.update', f'Updated DB version for {pkg} -> {newv}')
            except Exception:
                pass

            result.status = 'ok'
            self._record(pkg, 'upgrade', 'ok', {'new_version': result.new_version})

            # post-upgrade hook
            try:
                if self.hooks and hasattr(self.hooks, 'execute_safe'):
                    self.hooks.execute_safe('post_upgrade', pkg_dir=None)
            except Exception:
                pass

            self._log('info', 'upgrade.done', f'Upgrade completed for {pkg}', package=pkg)
            return result
        except Exception as e:
            result.status = 'error'
            result.error = str(e)
            self._record(pkg, 'upgrade', 'error', {'error': str(e)})
            self._log('error', 'upgrade.fail', f'Upgrade failed for {pkg}: {e}', error=str(e))
            # try rollback if backup exists
            if result.backup:
                try:
                    self.rollback(pkg, result.backup)
                except Exception:
                    pass
            return result

    # ---------------- rebuild ----------------
    def rebuild(self, pkg: str, dry_run: bool = True) -> UpgradeResult:
        """Rebuild the currently installed package using core pipeline."""
        res = UpgradeResult(package=pkg)
        try:
            info = self._repo_info_from_db(pkg)
            metafile = info.get('metafile') if isinstance(info, dict) else None
            if not self.core:
                res.status = 'no-core'
                return res
            if dry_run:
                res.status = 'dry-run'
                return res
            build_res = self.core.full_build_cycle(pkg, version=info.get('version'), metafile_path=metafile, do_package=False, do_deploy=False, dry_run=False)
            res.steps.append({'phase': 'rebuild', 'result': build_res})
            res.status = 'ok' if build_res.status == 'ok' else 'build-fail'
            return res
        except Exception as e:
            res.status = 'error'
            res.error = str(e)
            return res

    # ---------------- verify integrity ----------------
    def verify_integrity(self, pkg: str, archive: str) -> bool:
        """Basic sanity checks on packaged archive (size > 0 and can be opened)."""
        try:
            p = Path(archive)
            if not p.exists() or p.stat().st_size == 0:
                return False
            with tarfile.open(p, 'r:*') as tar:
                members = tar.getmembers()
                return len(members) > 0
        except Exception:
            return False

    # ---------------- batch upgrade ----------------
    def batch_upgrade(self, pkgs: List[str], parallel: Optional[int] = None, dry_run: bool = False) -> List[UpgradeResult]:
        parallel = int(parallel or self.parallel or DEFAULT_PARALLEL)
        results: List[UpgradeResult] = []
        self._log('info', 'upgrade.batch.start', f'Starting batch upgrade for {len(pkgs)} packages', total=len(pkgs), parallel=parallel)

        def worker(pkg_name: str) -> UpgradeResult:
            try:
                return self.upgrade(pkg_name, force=False, do_package=True, do_deploy=False, dry_run=dry_run)
            except Exception as e:
                r = UpgradeResult(package=pkg_name, status='error', error=str(e))
                return r

        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
            futs = {ex.submit(worker, p): p for p in pkgs}
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                results.append(r)

        self._log('info', 'upgrade.batch.done', f'Batch upgrade completed', count=len(results))
        return results

    # ---------------- cleanup old versions ----------------
    def clean_old_versions(self, pkg: str, keep: int = 1) -> Dict[str, Any]:
        """Remove old package archives / backups keeping `keep` newest ones."""
        removed = []
        archives = sorted(self.package_output.glob(f"{pkg}*"), key=lambda p: p.stat().st_mtime, reverse=True)
        for a in archives[keep:]:
            try:
                a.unlink()
                removed.append(str(a))
            except Exception:
                continue
        backups = sorted(self.backup_dir.glob(f"{pkg}-upgrade-*.tar.xz"), key=lambda p: p.stat().st_mtime, reverse=True)
        for b in backups[keep:]:
            try:
                b.unlink()
                removed.append(str(b))
            except Exception:
                continue
        self._log('info', 'upgrade.clean', f'Cleaned {len(removed)} old files for {pkg}', package=pkg)
        return {'removed': removed}

    # ---------------- CLI convenience ----------------
    @classmethod
    def cli_main(cls, argv: Optional[List[str]] = None):
        import argparse
        import sys

        p = argparse.ArgumentParser(prog='newpkg-upgrade', description='Upgrade manager for newpkg')
        p.add_argument('cmd', choices=['check', 'fetch', 'upgrade', 'batch', 'rebuild', 'rollback', 'clean'])
        p.add_argument('--pkg', help='package name')
        p.add_argument('--archive', help='archive path for rollback')
        p.add_argument('--parallel', type=int, help='parallel workers for batch')
        p.add_argument('--dry-run', action='store_true', help='do not perform changes')
        p.add_argument('--force', action='store_true', help='force upgrade even if no candidate found')
        args = p.parse_args(argv)

        cfg = None
        if init_config:
            try:
                cfg = init_config()
            except Exception:
                cfg = None

        db = NewpkgDB(cfg) if NewpkgDB and cfg is not None else None
        logger = NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None
        hooks = HooksManager(cfg, logger, db) if HooksManager and cfg is not None else None
        sandbox = Sandbox(cfg, logger, db) if Sandbox and cfg is not None else None

        upgr = cls(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)

        if args.cmd == 'check':
            if not args.pkg:
                print('specify --pkg')
                return 2
            res = upgr.check_updates(args.pkg)
            print(json.dumps(res, indent=2) if res else 'no update')
            return 0

        if args.cmd == 'fetch':
            if not args.pkg:
                print('specify --pkg')
                return 2
            res = upgr.fetch_new_source(args.pkg)
            print(res or 'fetch failed')
            return 0

        if args.cmd == 'upgrade':
            if not args.pkg:
                print('specify --pkg')
                return 2
            res = upgr.upgrade(args.pkg, force=args.force, do_package=True, do_deploy=False, dry_run=args.dry_run)
            print(json.dumps(res.__dict__, indent=2) if isinstance(res, UpgradeResult) else res)
            return 0

        if args.cmd == 'batch':
            # read packages from stdin or environment NEWPKG_UPGRADE_PKGS
            pkgs = []
            envpkgs = os.environ.get('NEWPKG_UPGRADE_PKGS')
            if envpkgs:
                pkgs = [p.strip() for p in envpkgs.split(',') if p.strip()]
            else:
                print('provide package names via NEWPKG_UPGRADE_PKGS env or pipe list to stdin')
                return 2
            res = upgr.batch_upgrade(pkgs, parallel=args.parallel, dry_run=args.dry_run)
            print(json.dumps([r.__dict__ for r in res], indent=2))
            return 0

        if args.cmd == 'rebuild':
            if not args.pkg:
                print('specify --pkg')
                return 2
            res = upgr.rebuild(args.pkg, dry_run=args.dry_run)
            print(json.dumps(res.__dict__, indent=2))
            return 0

        if args.cmd == 'rollback':
            if not args.pkg or not args.archive:
                print('specify --pkg and --archive')
                return 2
            ok = upgr.rollback(args.pkg, args.archive)
            print('ok' if ok else 'failed')
            return 0

        if args.cmd == 'clean':
            if not args.pkg:
                print('specify --pkg')
                return 2
            res = upgr.clean_old_versions(args.pkg)
            print(json.dumps(res, indent=2))
            return 0

        p.print_help()
        return 1


if __name__ == '__main__':
    NewpkgUpgrade.cli_main()
