"""
newpkg_remove.py

Gerencia remoção de pacotes no ecossistema newpkg.

Funcionalidades:
- remove(pkg_name, purge=False, simulate=False): remove arquivos registrados no DB
- purge(pkg_name): remove configs/extra (e.g. /etc/<pkg>)
- simulate(pkg_name): mostra o que seria removido
- rollback(pkg_name, backup_dir=None): restaura backup criado antes da remoção
- archive_before_remove(pkg_name): cria backup .tar.xz para rollback
- integra com newpkg_db, newpkg_hooks, newpkg_sandbox, newpkg_logger
- executa hooks pre_remove/post_remove e on_error quando necessário
- opera por padrão dentro de sandbox (bubblewrap) para segurança

Assume que `newpkg_db` oferece métodos como:
- get_package(name) -> object with name/version/status (or raises)
- list_files(package_name) -> iterable of file records (path, hash, size)
- remove_package(name) -> removes package record
- add_log(package, phase, status, log_path=None)
- update_package_status(name, status)

E que `newpkg_hooks` provê:
- run(hook_type, pkg_name=..., build_dir=..., destdir=...)

"""
from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


class RemoveError(Exception):
    pass


class NewpkgRemove:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None, hooks: Any = None):
        self.cfg = cfg
        self.logger = logger
        self.db = db
        self.sandbox = sandbox
        self.hooks = hooks

        # config defaults
        try:
            self.backup_dir = Path(self.cfg.get('REMOVE_BACKUP_DIR')) if self.cfg else None
        except Exception:
            self.backup_dir = None
        if not self.backup_dir:
            self.backup_dir = Path(os.environ.get('NEWPKG_REMOVE_BACKUP', '/var/tmp/newpkg_backups'))
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        try:
            self.purge_configs_default = bool(self.cfg.get('REMOVE_PURGE_CONFIGS'))
        except Exception:
            self.purge_configs_default = True

        try:
            self.use_sandbox_default = bool(self.cfg.get('REMOVE_SANDBOX'))
        except Exception:
            self.use_sandbox_default = True

        try:
            self.confirm_required = bool(self.cfg.get('REMOVE_CONFIRM_REQUIRED'))
        except Exception:
            self.confirm_required = True

    # ---------------- logging ----------------
    def _log(self, event: str, level: str = 'INFO', message: Optional[str] = None, meta: Optional[Dict[str, Any]] = None):
        if self.logger:
            self.logger.log_event(event, level=level, message=message or event, metadata=meta or {})

    # ---------------- helpers ----------------
    def _get_package(self, pkg_name: str) -> Any:
        if not self.db:
            raise RemoveError('newpkg_db not configured')
        try:
            pkg = self.db.get_package(pkg_name)
            return pkg
        except Exception:
            # fallback: try listing packages and match by name
            try:
                for p in self.db.list_packages():
                    if getattr(p, 'name', None) == pkg_name or p == pkg_name:
                        return p
            except Exception:
                pass
        raise RemoveError(f'Package not found in DB: {pkg_name}')

    def _list_files(self, pkg_name: str) -> List[Dict[str, Any]]:
        # expects db.list_files or db.get_files
        out: List[Dict[str, Any]] = []
        if not self.db:
            return out
        try:
            # try multiple method names
            if hasattr(self.db, 'list_files'):
                rows = self.db.list_files(pkg_name)
                for r in rows:
                    # assume r has .path or is dict
                    if isinstance(r, dict):
                        out.append(r)
                    else:
                        out.append({'path': getattr(r, 'path', str(r)), 'hash': getattr(r, 'hash', None)})
                return out
            elif hasattr(self.db, 'get_files'):
                rows = self.db.get_files(pkg_name)
                for r in rows:
                    if isinstance(r, dict):
                        out.append(r)
                    else:
                        out.append({'path': getattr(r, 'path', str(r)), 'hash': getattr(r, 'hash', None)})
                return out
            else:
                # try db.fetch_files or query
                return out
        except Exception:
            return out

    def _confirm(self, pkg_name: str) -> bool:
        if not self.confirm_required:
            return True
        resp = input(f'Confirm removal of {pkg_name}? [y/N]: ')
        return resp.strip().lower() in ('y', 'yes')

    def _archive_before_remove(self, pkg_name: str, files: List[str], archive_name: Optional[str] = None) -> Path:
        if not archive_name:
            ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
            archive_name = f'{pkg_name}-backup-{ts}.tar.xz'
        dest = self.backup_dir / archive_name
        # create tar.xz
        with tarfile.open(dest, 'w:xz') as tar:
            for f in files:
                try:
                    pf = Path(f)
                    if pf.exists():
                        tar.add(str(pf), arcname=str(pf.relative_to('/')))
                except Exception:
                    # skip problematic files
                    continue
        return dest

    # ---------------- verify ownership / safety ----------------
    def verify_ownership(self, file_path: str, pkg_name: str) -> bool:
        # verify that the file_path is recorded for pkg_name in DB
        try:
            files = self._list_files(pkg_name)
            normalized = {str(Path(x['path']).resolve()) for x in files if 'path' in x}
            return str(Path(file_path).resolve()) in normalized
        except Exception:
            return False

    def _safe_remove_path(self, path: Path, use_sandbox: bool = True) -> Tuple[bool, str]:
        """Remove a file or directory, optionally inside sandbox."""
        try:
            if use_sandbox and self.sandbox:
                # run rm -rf inside sandbox for safety
                cmd = ['/bin/sh', '-lc', f"rm -rf -- '{str(path)}'"]
                res = self.sandbox.run(cmd, cwd=Path('/'), timeout=300)
                if res.returncode != 0:
                    return False, res.stderr or 'rm failed'
                return True, ''
            else:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=False)
                elif path.exists():
                    path.unlink()
                return True, ''
        except Exception as e:
            return False, str(e)

    # ---------------- main remove flow ----------------
    def remove(self, pkg_name: str, purge: Optional[bool] = None, simulate: bool = False, backup: Optional[bool] = None, use_sandbox: Optional[bool] = None) -> Dict[str, Any]:
        """Remove a package safely.

        - purge: whether to remove configs (defaults to config)
        - simulate: if True, only show plan, do not perform destructive actions
        - backup: whether to create backup before deletion (default True)
        - use_sandbox: whether to perform rm inside sandbox (default from config)
        """
        if purge is None:
            purge = self.purge_configs_default
        if backup is None:
            backup = True
        if use_sandbox is None:
            use_sandbox = self.use_sandbox_default

        pkg = self._get_package(pkg_name)
        files = self._list_files(pkg_name)
        file_paths = [str(Path(x['path'])) for x in files if x.get('path')]

        plan = {
            'package': pkg_name,
            'count_files': len(file_paths),
            'files': file_paths,
            'purge_configs': purge,
            'simulate': simulate,
        }

        self._log('remove.plan', level='INFO', message='Remove plan generated', meta=plan)

        if simulate:
            return {'status': 'simulate', 'plan': plan}

        if not self._confirm(pkg_name):
            raise RemoveError('User aborted')

        # run pre_remove hooks
        try:
            if self.hooks:
                self.hooks.execute_safe('pre_remove', pkg_name=pkg_name)
        except Exception:
            pass

        backup_path = None
        if backup and file_paths:
            try:
                backup_path = self._archive_before_remove(pkg_name, file_paths)
                self._log('remove.backup', level='INFO', message='Backup created', meta={'archive': str(backup_path)})
            except Exception as e:
                self._log('remove.backup.fail', level='ERROR', message='Backup failed', meta={'error': str(e)})
                # proceed depending on policy; we'll continue

        removed = []
        failed = []
        for fp in file_paths:
            p = Path(fp)
            # safety: only remove if recorded in DB
            if not self.verify_ownership(fp, pkg_name):
                self._log('remove.skip', level='WARNING', message=f'Skipping unowned file {fp}', meta={'pkg': pkg_name})
                failed.append({'path': fp, 'error': 'not-owned'})
                continue
            ok, err = self._safe_remove_path(p, use_sandbox=use_sandbox)
            if ok:
                removed.append(fp)
            else:
                failed.append({'path': fp, 'error': err})
                # attempt rollback if severe
                self._log('remove.file.fail', level='ERROR', message=f'Failed to remove {fp}: {err}', meta={'pkg': pkg_name})

        # optionally purge config directories e.g. /etc/<pkg>
        purged = []
        purge_failed = []
        if purge:
            etc_path = Path('/etc') / pkg_name
            if etc_path.exists():
                ok, err = self._safe_remove_path(etc_path, use_sandbox=use_sandbox)
                if ok:
                    purged.append(str(etc_path))
                else:
                    purge_failed.append({'path': str(etc_path), 'error': err})

        # update DB
        try:
            if hasattr(self.db, 'remove_package'):
                self.db.remove_package(pkg_name)
            elif hasattr(self.db, 'update_package_status'):
                self.db.update_package_status(pkg_name, 'removed')
            try:
                self.db.add_log(pkg_name, 'remove', 'ok' if not failed else 'partial', log_path=str(backup_path) if backup_path else None)
            except Exception:
                pass
        except Exception as e:
            self._log('remove.db.fail', level='ERROR', message='Failed to update DB', meta={'pkg': pkg_name, 'error': str(e)})

        # run post_remove hooks
        try:
            if self.hooks:
                self.hooks.execute_safe('post_remove', pkg_name=pkg_name)
        except Exception:
            pass

        result = {'status': 'ok' if not failed else 'partial', 'removed': removed, 'failed': failed, 'backup': str(backup_path) if backup_path else None, 'purged': purged, 'purge_failed': purge_failed}
        self._log('remove.done', level='INFO', message='Remove completed', meta={'pkg': pkg_name, 'result': result})
        return result

    # ---------------- purge API ----------------
    def purge(self, pkg_name: str, simulate: bool = False) -> Dict[str, Any]:
        return self.remove(pkg_name, purge=True, simulate=simulate)

    # ---------------- rollback ----------------
    def rollback(self, archive_path: str, target_root: str = '/') -> Dict[str, Any]:
        ap = Path(archive_path)
        if not ap.exists():
            raise RemoveError('Backup archive not found')
        try:
            # extract archive to temporary dir then copy back
            tmp = Path(tempfile.mkdtemp(prefix='newpkg-rollback-'))
            with tarfile.open(ap, 'r:xz') as tar:
                tar.extractall(path=tmp)
            # copy back into target_root
            for item in tmp.iterdir():
                dest = Path(target_root) / item.name
                if dest.exists():
                    # remove existing and replace
                    if dest.is_dir():
                        shutil.rmtree(dest)
                    else:
                        dest.unlink()
                shutil.move(str(item), str(dest))
            shutil.rmtree(tmp)
            self._log('rollback.ok', level='INFO', message='Rollback applied', meta={'archive': str(ap)})
            return {'status': 'ok', 'archive': str(ap)}
        except Exception as e:
            self._log('rollback.fail', level='ERROR', message='Rollback failed', meta={'archive': str(ap), 'error': str(e)})
            raise RemoveError(f'Rollback failed: {e}')

    # ---------------- cleanup orphans ----------------
    def clean_orphans(self, simulate: bool = True) -> Dict[str, Any]:
        # use newpkg_db to find orphan packages (no reverse deps)
        if not self.db:
            raise RemoveError('DB not configured')
        try:
            # naive approach: use methods similar to depclean
            pkgs = [p.name for p in self.db.list_packages()]
        except Exception:
            raise RemoveError('Failed to list packages')
        to_remove = []
        for pkg in pkgs:
            deps = self.db.get_deps(pkg)
            # find reverse deps by checking other packages
            rev = False
            for other in pkgs:
                if other == pkg:
                    continue
                other_deps = self.db.get_deps(other)
                if any(d.get('depends_on') == pkg for d in other_deps):
                    rev = True
                    break
            if not rev:
                to_remove.append(pkg)
        if simulate:
            return {'status': 'simulate', 'candidates': to_remove}
        results = {'removed': [], 'failed': []}
        for p in to_remove:
            try:
                self.remove(p, purge=False, simulate=False)
                results['removed'].append(p)
            except Exception as e:
                results['failed'].append({'pkg': p, 'error': str(e)})
        return results

    # ---------------- remove build artifacts ----------------
    def remove_build_artifacts(self, pkg_name: str) -> Dict[str, Any]:
        # try to find build dirs under NEWPKG_BUILD_ROOT
        build_root = Path(self.cfg.get('NEWPKG_BUILD_ROOT')) if self.cfg else None
        if not build_root:
            return {'status': 'no_build_root'}
        pattern = f"{pkg_name}*"
        removed = []
        failed = []
        for p in build_root.glob(pattern):
            try:
                shutil.rmtree(p)
                removed.append(str(p))
            except Exception as e:
                failed.append({'path': str(p), 'error': str(e)})
        return {'removed': removed, 'failed': failed}


# ---------------- CLI ----------------
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(prog='newpkg-remove')
    ap.add_argument('--pkg', '-p', required=True)
    ap.add_argument('--simulate', action='store_true')
    ap.add_argument('--purge', action='store_true')
    ap.add_argument('--rollback', help='archive path to rollback from', default=None)
    args = ap.parse_args()

    # minimal bootstrap
    try:
        from newpkg_db import NewpkgDB
    except Exception:
        NewpkgDB = None
    try:
        from newpkg_hooks import NewpkgHooks
    except Exception:
        NewpkgHooks = None

    cfg = None
    class CfgShim:
        def get(self, k):
            return None
    cfg = CfgShim()

    db = None
    if NewpkgDB is not None:
        dbp = os.environ.get('NEWPKG_DB_PATH')
        if dbp:
            db = NewpkgDB(db_path=dbp)
            db.init_db()

    hooks = None
    if NewpkgHooks is not None:
        hooks = NewpkgHooks(cfg)

    remover = NewpkgRemove(cfg, logger=None, db=db, sandbox=None, hooks=hooks)
    if args.rollback:
        print(remover.rollback(args.rollback))
    else:
        print(remover.remove(args.pkg, purge=args.purge, simulate=args.simulate))
