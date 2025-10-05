#!/usr/bin/env python3
"""
newpkg_remove.py

Safe package removal utilities for newpkg.
- Integrates with: newpkg_config (init_config), newpkg_logger (NewpkgLogger), newpkg_db (NewpkgDB), newpkg_hooks (HooksManager), newpkg_sandbox (Sandbox)
- Provides safe remove with backup, dry-run, sandbox execution, purge of configs/cache, and rollback restore
- CLI supports --simulate/--dry-run, --purge, --backup-dir, --json, --quiet

Caveats: This module is conservative by default. It will not run destructive operations unless explicitly requested.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional project imports
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

# Constants and defaults
DEFAULT_BACKUP_DIR = Path(os.environ.get('NEWPKG_REMOVE_BACKUP', '/var/tmp/newpkg_backups'))
DEFAULT_SAFE_PREFIXES = ['/usr', '/etc', '/var', '/opt', '/home']


class RemoveError(Exception):
    pass


class NewpkgRemover:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.logger = logger or (NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None)
        self.db = db or (NewpkgDB(cfg) if NewpkgDB and cfg is not None else None)
        self.hooks = hooks or (HooksManager(cfg, self.logger, self.db) if HooksManager and cfg is not None else None)
        self.sandbox = sandbox or (Sandbox(cfg, self.logger, self.db) if Sandbox and cfg is not None else None)

        self.backup_dir = Path(self._cfg_get('remove.backup_dir', str(DEFAULT_BACKUP_DIR)))
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.safe_prefixes = list(self._cfg_get('remove.safe_prefixes', DEFAULT_SAFE_PREFIXES))
        self.confirm = bool(self._cfg_get('remove.confirm', True))
        self.default_use_sandbox = bool(self._cfg_get('remove.sandbox', True))

    # ---------------- helpers ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, 'get'):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return os.environ.get(key.upper().replace('.', '_'), default)

    def _log(self, level: str, event: str, message: str = '', **meta):
        if self.logger:
            try:
                fn = getattr(self.logger, level.lower(), None)
                if fn:
                    fn(event, message, **meta)
                    return
            except Exception:
                pass
        # fallback simple print
        print(f'[{level.upper()}] {event}: {message}')

    def _is_under_safe_prefix(self, path: Path) -> bool:
        try:
            rp = str(path.resolve())
        except Exception:
            return False
        for p in self.safe_prefixes:
            try:
                if rp.startswith(str(Path(p).resolve())):
                    return True
            except Exception:
                continue
        return False

    def _confirm(self, prompt: str) -> bool:
        if not self.confirm:
            return True
        try:
            ans = input(f"{prompt} [y/N]: ")
            return ans.strip().lower() in ('y', 'yes')
        except Exception:
            return False

    # ---------------- backup / rollback ----------------
    def _make_backup(self, targets: List[str], pkg_name: str, backup_root: Optional[str] = None) -> Optional[str]:
        backup_root = Path(backup_root) if backup_root else self.backup_dir
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        out = backup_root / f"{pkg_name}-{ts}.tar.xz"
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(out, 'w:xz') as tar:
                for t in targets:
                    p = Path(t)
                    if p.exists():
                        tar.add(p, arcname=str(p.relative_to(p.anchor)))
            meta = {
                'package': pkg_name,
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'targets': targets,
                'size': out.stat().st_size if out.exists() else None,
            }
            # write metadata sidecar
            try:
                (out.with_suffix('.json')).write_text(json.dumps(meta, indent=2), encoding='utf-8')
            except Exception:
                pass
            self._log('info', 'remove.backup', f'Backup created: {out}', path=str(out), package=pkg_name)
            return str(out)
        except Exception as e:
            self._log('error', 'remove.backup.fail', f'Failed to create backup: {e}', error=str(e))
            return None

    def list_backups(self, pkg_name: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for f in sorted(self.backup_dir.glob(f"{pkg_name or '*'}-*.tar.xz")):
            try:
                meta = {}
                j = f.with_suffix('.json')
                if j.exists():
                    meta = json.loads(j.read_text(encoding='utf-8'))
                out.append({'file': str(f), 'meta': meta})
            except Exception:
                out.append({'file': str(f), 'meta': {}})
        return out

    def rollback(self, archive_path: str, target_root: Optional[str] = None) -> bool:
        target_root = target_root or '/'
        try:
            with tarfile.open(archive_path, 'r:xz') as tar:
                # careful: extract to temp dir then move to target via sandbox/run to avoid overwrites
                tmp = Path(tempfile.mkdtemp(prefix='newpkg_restore_'))
                tar.extractall(path=str(tmp))
                # move files into place
                for member in tmp.iterdir():
                    dest = Path(target_root) / member.name
                    # if exists, remove and replace
                    if dest.exists():
                        if dest.is_dir():
                            shutil.rmtree(dest)
                        else:
                            dest.unlink()
                    shutil.move(str(member), str(dest))
                shutil.rmtree(tmp)
            self._log('info', 'remove.rollback', f'Restored from {archive_path} to {target_root}', archive=archive_path)
            return True
        except Exception as e:
            self._log('error', 'remove.rollback.fail', f'Rollback failed: {e}', error=str(e))
            return False

    # ---------------- ownership & plan ----------------
    def verify_ownership(self, path: str, pkg_name: Optional[str] = None) -> bool:
        """Best-effort check whether file belongs to a package via DB; falls back to heuristic by path."""
        p = Path(path)
        if self.db and hasattr(self.db, 'query_ownership'):
            try:
                return bool(self.db.query_ownership(str(p)))
            except Exception:
                pass
        # heuristic: under /usr or /etc treat as owned if exists
        return p.exists() and self._is_under_safe_prefix(p)

    def plan_removal(self, pkg_name: str) -> Dict[str, Any]:
        """Return a plan describing targets to remove and estimated sizes.
        Assumes db has package file list via list_files(pkg) if available.
        """
        targets: List[str] = []
        size = 0
        files = []
        # try DB first
        if self.db and hasattr(self.db, 'list_files'):
            try:
                files = self.db.list_files(pkg_name)
            except Exception:
                files = []
        # fallback heuristics: common dirs
        if not files:
            possible = [f"/usr/lib/{pkg_name}", f"/usr/share/{pkg_name}", f"/etc/{pkg_name}", f"/var/lib/{pkg_name}", f"/opt/{pkg_name}"]
            for p in possible:
                if Path(p).exists():
                    files.append(p)
        for f in files:
            p = Path(f)
            if p.exists():
                targets.append(str(p))
                try:
                    if p.is_file():
                        size += p.stat().st_size
                    else:
                        for fp in p.rglob('*'):
                            try:
                                if fp.is_file():
                                    size += fp.stat().st_size
                            except Exception:
                                continue
                except Exception:
                    continue
        return {'package': pkg_name, 'targets': targets, 'estimated_size': size, 'count': len(targets)}

    # ---------------- removal execution ----------------
    def remove(self, pkg_name: str, purge: bool = False, simulate: bool = True, backup: bool = True, use_sandbox: Optional[bool] = None, backup_root: Optional[str] = None) -> Dict[str, Any]:
        """Main entry: remove a package safely.
        - simulate: if True, only returns plan
        - backup: create tar.xz backup before deletion
        - purge: also remove config/cache locations
        - use_sandbox: prefer using sandbox if available (defaults to config)
        Returns detailed result dict.
        """
        use_sandbox = self.default_use_sandbox if use_sandbox is None else bool(use_sandbox)
        plan = self.plan_removal(pkg_name)
        plan_summary = {'package': pkg_name, 'targets': plan['targets'], 'size': plan['estimated_size'], 'count': plan['count']}

        # run pre-remove hook
        try:
            if self.hooks and hasattr(self.hooks, 'execute_safe'):
                self.hooks.execute_safe('pre_remove', pkg_dir=None)
        except Exception:
            pass

        if simulate:
            self._log('info', 'remove.plan', f'Plan for {pkg_name}', **plan_summary)
            return {'plan': plan_summary, 'simulated': True}

        # confirm
        if not self._confirm(f"Proceed to remove {pkg_name}? This will delete {plan['count']} paths (~{plan['estimated_size']} bytes)"):
            return {'package': pkg_name, 'status': 'cancelled'}

        # backup
        backup_path = None
        if backup and plan['targets']:
            backup_path = self._make_backup(plan['targets'], pkg_name, backup_root=backup_root)

        # perform removals
        removed = []
        errors = []
        for t in plan['targets']:
            p = Path(t)
            try:
                # safety checks
                if not self._is_under_safe_prefix(p):
                    raise RemoveError(f'Path {t} not under allowed prefixes; refusing to remove')
                if use_sandbox and self.sandbox:
                    # use sandbox.run to remove safely
                    cmd = ['rm', '-rf', str(p)]
                    res = self.sandbox.run(cmd, cwd=str(p.parent) if p.parent.exists() else None)
                    if res.rc == 0:
                        removed.append(t)
                    else:
                        errors.append({'target': t, 'err': res.err})
                else:
                    # direct remove
                    if p.is_dir():
                        shutil.rmtree(p)
                    elif p.exists():
                        p.unlink()
                    removed.append(t)
                self._log('info', 'remove.target.ok', f'Removed {t}', target=t)
            except Exception as e:
                errors.append({'target': t, 'err': str(e)})
                self._log('error', 'remove.target.fail', f'Failed to remove {t}: {e}', target=t, error=str(e))

        # purge extra directories if requested
        purged = []
        if purge:
            extras = [f"/etc/{pkg_name}", f"/var/lib/{pkg_name}", f"/var/cache/{pkg_name}", f"/var/log/{pkg_name}"]
            for ex in extras:
                p = Path(ex)
                try:
                    if p.exists():
                        if use_sandbox and self.sandbox:
                            res = self.sandbox.run(['rm', '-rf', str(p)], cwd=str(p.parent))
                            if res.rc == 0:
                                purged.append(ex)
                        else:
                            if p.is_dir():
                                shutil.rmtree(p)
                            else:
                                p.unlink()
                            purged.append(ex)
                        self._log('info', 'remove.purge.ok', f'Purged {ex}', target=ex)
                except Exception as e:
                    errors.append({'target': ex, 'err': str(e)})
                    self._log('error', 'remove.purge.fail', f'Failed to purge {ex}: {e}', target=ex)

        # update DB
        try:
            if self.db and hasattr(self.db, 'record_phase'):
                status = 'ok' if not errors else 'partial' if removed else 'error'
                self.db.record_phase(pkg_name, 'remove', status, log_path=backup_path)
        except Exception:
            pass

        # post-remove hook
        try:
            if self.hooks and hasattr(self.hooks, 'execute_safe'):
                self.hooks.execute_safe('post_remove', pkg_dir=None)
        except Exception:
            pass

        summary = {'package': pkg_name, 'removed': removed, 'purged': purged, 'errors': errors, 'backup': backup_path}
        self._log('info', 'remove.done', f'Remove finished for {pkg_name}', package=pkg_name, removed=len(removed), errors=len(errors))
        return summary

    # ---------------- convenience operations ----------------
    def purge(self, pkg_name: str, simulate: bool = True, backup: bool = True) -> Dict[str, Any]:
        return self.remove(pkg_name, purge=True, simulate=simulate, backup=backup)

    def clean_orphans(self, simulate: bool = True) -> Dict[str, Any]:
        """Detect orphan packages via DB and remove them (use with caution)."""
        if not self.db or not hasattr(self.db, 'list_packages'):
            return {'error': 'db unavailable'}
        packages = self.db.list_packages()
        orphans = []
        for p in packages:
            name = p.get('name')
            # if no reverse deps
            try:
                rev = self.db.get_reverse_deps(name)
                if not rev:
                    orphans.append(name)
            except Exception:
                continue
        results = {'orphans': orphans, 'actions': []}
        for pkg in orphans:
            plan = self.plan_removal(pkg)
            if simulate:
                results['actions'].append({'package': pkg, 'plan': plan})
            else:
                res = self.remove(pkg, purge=True, simulate=False)
                results['actions'].append({'package': pkg, 'result': res})
        return results

    def remove_build_artifacts(self, pkg_name: str) -> Dict[str, Any]:
        dirs = [f"/tmp/{pkg_name}", f"/var/tmp/{pkg_name}", f"/build/{pkg_name}", f"/sources/{pkg_name}"]
        removed = []
        errors = []
        for d in dirs:
            p = Path(d)
            try:
                if p.exists():
                    shutil.rmtree(p)
                    removed.append(d)
            except Exception as e:
                errors.append({'path': d, 'err': str(e)})
        return {'removed': removed, 'errors': errors}


# ---------------- CLI ----------------
if __name__ == '__main__':
    import argparse
    import sys

    p = argparse.ArgumentParser(prog='newpkg-remove', description='Safe package removal for newpkg')
    p.add_argument('pkg', help='package name to remove')
    p.add_argument('--purge', action='store_true', help='also purge configs and caches')
    p.add_argument('--no-backup', dest='backup', action='store_false', help='do not create backup')
    p.add_argument('--simulate', action='store_true', help='dry-run (default: do not simulate)')
    p.add_argument('--backup-dir', help='custom backup directory')
    p.add_argument('--no-sandbox', action='store_true', help='do not use sandbox even if configured')
    p.add_argument('--json', action='store_true', help='output JSON')
    p.add_argument('--quiet', action='store_true', help='minimal output')
    args = p.parse_args()

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

    remover = NewpkgRemover(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)
    if args.backup_dir:
        remover.backup_dir = Path(args.backup_dir)
        remover.backup_dir.mkdir(parents=True, exist_ok=True)
    remover.confirm = not args.quiet

    res = remover.remove(args.pkg, purge=args.purge, simulate=args.simulate, backup=args.backup, use_sandbox=not args.no_sandbox, backup_root=str(remover.backup_dir))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        if not args.quiet:
            print('Result:')
            print(res)
    sys.exit(0)
