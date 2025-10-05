"""
newpkg_sync.py

Sincronizador de múltiplos repositórios git para newpkg.
- Operações: add_repo, clone_repo, fetch_repo, sync_repo, sync_all, check_status, verify_repo, rollback_repo, clean_repo
- Execução paralela via asyncio
- Execução de comandos dentro de newpkg_sandbox (se fornecido)
- Hooks pre_sync / post_sync via newpkg_hooks
- GPG verification (opcional, via gnupg)
- Dry-run suportado

Design notes:
- Este módulo assume que `cfg` expõe 'sync.repos_dir' e opções como 'sync.parallel' e 'sync.verify_gpg'.
- `logger`, `db`, `sandbox`, `hooks` são opcionais e integráveis quando presentes.

"""
from __future__ import annotations

import asyncio
import os
import shutil
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

try:
    import gnupg
    _HAS_GNUPG = True
except Exception:
    gnupg = None
    _HAS_GNUPG = False


class SyncError(Exception):
    pass


class NewpkgSync:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None, hooks: Any = None):
        self.cfg = cfg
        self.logger = logger
        self.db = db
        self.sandbox = sandbox
        self.hooks = hooks

        # config defaults
        repos_dir = None
        try:
            repos_dir = self.cfg.get('sync.repos_dir')
        except Exception:
            repos_dir = None
        if not repos_dir:
            repos_dir = os.path.expanduser('~/.local/share/newpkg/repos')
        self.repos_dir = Path(repos_dir)
        self.repos_dir.mkdir(parents=True, exist_ok=True)

        try:
            self.parallel = bool(self.cfg.get('sync.parallel'))
        except Exception:
            self.parallel = True

        try:
            self.verify_gpg = bool(self.cfg.get('sync.verify_gpg'))
        except Exception:
            self.verify_gpg = True

        try:
            self.use_sandbox = bool(self.cfg.get('sync.sandbox'))
        except Exception:
            self.use_sandbox = True

        try:
            self.shallow = bool(self.cfg.get('sync.shallow'))
        except Exception:
            self.shallow = True

        # internal registry: name -> metadata
        # metadata: {url, branch, path}
        self._repos: Dict[str, Dict[str, Any]] = {}
        # load repos from DB or config if available
        try:
            self._load_from_cfg()
        except Exception:
            pass

        # gnupg
        self._gpg = gnupg.GPG() if _HAS_GNUPG else None

    # ---------------- logging ----------------
    def _log(self, event: str, level: str = 'INFO', message: Optional[str] = None, meta: Optional[Dict[str, Any]] = None):
        if self.logger:
            self.logger.log_event(event, level=level, message=message or event, metadata=meta or {})

    # ---------------- config load ----------------
    def _load_from_cfg(self) -> None:
        try:
            repos = self.cfg.get('repos') or {}
            for name, meta in repos.items():
                url = meta.get('url')
                branch = meta.get('branch', 'main')
                path = meta.get('path')
                if path:
                    path = str(Path(path).expanduser())
                self.add_repo(name, url, branch=branch, path=path, shallow=meta.get('shallow', self.shallow), persist=False)
        except Exception:
            pass

    # ---------------- repo registration ----------------
    def add_repo(self, name: str, url: str, branch: str = 'main', path: Optional[str] = None, shallow: Optional[bool] = None, persist: bool = True) -> Dict[str, Any]:
        """Register a repo in the local registry.
        If path not provided the repo will be cloned under repos_dir/name
        persist: if True attempt to write to DB/config (best-effort)
        """
        if shallow is None:
            shallow = self.shallow
        repo_path = Path(path) if path else (self.repos_dir / name)
        self._repos[name] = {'url': url, 'branch': branch, 'path': str(repo_path), 'shallow': bool(shallow)}
        if persist and self.db and hasattr(self.db, 'add_repo'):
            try:
                self.db.add_repo(name, url, branch, str(repo_path))
            except Exception:
                pass
        self._log('sync.add_repo', level='INFO', message=f'Added repo {name}', meta={'name': name, 'url': url, 'path': str(repo_path)})
        return self._repos[name]

    # ---------------- utility: run git (possibly in sandbox) ----------------
    async def _run_git(self, args: List[str], cwd: Optional[Path] = None, timeout: Optional[int] = 300) -> Tuple[int, str, str]:
        cmd = ['git'] + args
        if self.use_sandbox and self.sandbox:
            # run via sandbox.run which is assumed to provide .returncode, .stdout, .stderr
            try:
                res = self.sandbox.run(cmd, cwd=cwd, timeout=timeout)
                return res.returncode, res.stdout, res.stderr
            except Exception as e:
                return 1, '', str(e)
        # run locally via asyncio.subprocess
        proc = await asyncio.create_subprocess_exec(*cmd, cwd=str(cwd) if cwd else None, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return 1, '', 'timeout'
        return proc.returncode, out.decode('utf-8', errors='ignore'), err.decode('utf-8', errors='ignore')

    # ---------------- clone ----------------
    async def clone_repo(self, name: str, shallow: Optional[bool] = None, dry_run: bool = False) -> Dict[str, Any]:
        meta = self._repos.get(name)
        if not meta:
            raise SyncError('repo not registered')
        url = meta['url']
        branch = meta.get('branch', 'main')
        path = Path(meta['path'])
        shallow = self.shallow if shallow is None else shallow
        if path.exists() and (path / '.git').exists():
            return {'status': 'exists', 'path': str(path)}
        if dry_run:
            return {'status': 'dryrun', 'action': 'clone', 'url': url, 'path': str(path)}
        path.parent.mkdir(parents=True, exist_ok=True)
        args = ['clone']
        if shallow:
            args += ['--depth', '1']
        args += ['--branch', branch, url, str(path)]
        code, out, err = await self._run_git(args, cwd=None)
        if code != 0:
            self._log('sync.clone.fail', level='ERROR', message=f'clone failed for {name}', meta={'name': name, 'err': err})
            return {'status': 'error', 'error': err}
        self._log('sync.clone.ok', level='INFO', message=f'cloned {name}', meta={'name': name, 'path': str(path)})
        return {'status': 'ok', 'path': str(path)}

    # ---------------- fetch (no merge) ----------------
    async def fetch_repo(self, name: str, dry_run: bool = False) -> Dict[str, Any]:
        meta = self._repos.get(name)
        if not meta:
            raise SyncError('repo not registered')
        path = Path(meta['path'])
        if not path.exists() or not (path / '.git').exists():
            return {'status': 'missing', 'detail': 'not-cloned'}
        if dry_run:
            return {'status': 'dryrun', 'action': 'fetch', 'path': str(path)}
        code, out, err = await self._run_git(['fetch', '--all', '--tags'], cwd=path)
        if code != 0:
            self._log('sync.fetch.fail', level='ERROR', message=f'fetch failed for {name}', meta={'name': name, 'err': err})
            return {'status': 'error', 'error': err}
        self._log('sync.fetch.ok', level='INFO', message=f'fetch ok for {name}', meta={'name': name})
        return {'status': 'ok', 'out': out}

    # ---------------- check status ----------------
    async def check_status(self, name: str, dry_run: bool = False) -> Dict[str, Any]:
        meta = self._repos.get(name)
        if not meta:
            raise SyncError('repo not registered')
        path = Path(meta['path'])
        if not path.exists() or not (path / '.git').exists():
            return {'status': 'missing'}
        if dry_run:
            return {'status': 'dryrun'}
        # git remote show origin or git status -sb
        code, out, err = await self._run_git(['status', '-sb'], cwd=path)
        if code != 0:
            return {'status': 'error', 'error': err}
        # parse for ahead/behind
        ahead = 'ahead' in out
        behind = 'behind' in out
        dirty = '??' in out or ' M ' in out
        return {'status': 'ok', 'ahead': ahead, 'behind': behind, 'dirty': dirty, 'status_out': out}

    # ---------------- verify via GPG (optional) ----------------
    def verify_repo(self, name: str, tag: Optional[str] = None) -> Dict[str, Any]:
        if not _HAS_GNUPG or not self._gpg:
            return {'status': 'error', 'error': 'gnupg not available'}
        meta = self._repos.get(name)
        if not meta:
            raise SyncError('repo not registered')
        path = Path(meta['path'])
        if not path.exists():
            return {'status': 'missing'}
        # find annotated tag signature or commit signature
        # use git verify-tag or git verify-commit
        target = tag if tag else 'HEAD'
        try:
            proc = subprocess.run(['git', 'verify-commit', target], cwd=str(path), capture_output=True, text=True)
            if proc.returncode == 0:
                return {'status': 'ok', 'verified': True, 'output': proc.stdout}
            else:
                return {'status': 'error', 'verified': False, 'error': proc.stderr}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    # ---------------- merge / update working tree ----------------
    async def _merge_branch(self, name: str, remote: str = 'origin', branch: Optional[str] = None, dry_run: bool = False) -> Dict[str, Any]:
        meta = self._repos.get(name)
        if not meta:
            raise SyncError('repo not registered')
        path = Path(meta['path'])
        branch = branch or meta.get('branch', 'main')
        if not path.exists() or not (path / '.git').exists():
            return {'status': 'missing'}
        if dry_run:
            return {'status': 'dryrun', 'action': 'merge', 'branch': branch}
        # checkout branch
        code, out, err = await self._run_git(['checkout', branch], cwd=path)
        if code != 0:
            return {'status': 'error', 'error': err}
        # pull (fast-forward only)
        code, out, err = await self._run_git(['pull', '--ff-only', remote, branch], cwd=path)
        if code != 0:
            # if non-fast-forward or conflict, report error
            self._log('sync.merge.fail', level='ERROR', message=f'merge failed for {name}', meta={'name': name, 'err': err})
            return {'status': 'error', 'error': err}
        self._log('sync.merge.ok', level='INFO', message=f'repo updated {name}', meta={'name': name})
        return {'status': 'ok', 'out': out}

    # ---------------- sync single repo ----------------
    async def sync_repo(self, name: str, dry_run: bool = False, verify_gpg: Optional[bool] = None) -> Dict[str, Any]:
        meta = self._repos.get(name)
        if not meta:
            raise SyncError('repo not registered')
        if verify_gpg is None:
            verify_gpg = self.verify_gpg

        result = {'name': name, 'steps': []}
        # pre_sync hooks
        if self.hooks:
            try:
                self.hooks.execute_safe('pre_sync', pkg_name=name, build_dir=Path(meta['path']) if meta.get('path') else None)
            except Exception:
                pass

        # ensure cloned
        if not Path(meta['path']).exists() or not (Path(meta['path']) / '.git').exists():
            c = await self.clone_repo(name, shallow=meta.get('shallow', self.shallow), dry_run=dry_run)
            result['steps'].append({'clone': c})
            if c.get('status') != 'ok' and c.get('status') != 'exists' and not dry_run:
                # cloning failed
                if self.hooks:
                    self.hooks.execute_safe('on_error', pkg_name=name)
                return {'name': name, 'status': 'error', 'error': c}

        # fetch
        f = await self.fetch_repo(name, dry_run=dry_run)
        result['steps'].append({'fetch': f})
        if f.get('status') == 'error':
            if self.hooks:
                self.hooks.execute_safe('on_error', pkg_name=name)
            return {'name': name, 'status': 'error', 'error': f}

        # merge/update working tree
        m = await self._merge_branch(name, branch=meta.get('branch', 'main'), dry_run=dry_run)
        result['steps'].append({'merge': m})
        if m.get('status') == 'error':
            # do not auto rollback (config requested no auto rollback)
            if self.hooks:
                self.hooks.execute_safe('on_error', pkg_name=name)
            return {'name': name, 'status': 'error', 'error': m}

        # optional gpg verify
        ver = None
        if verify_gpg:
            try:
                ver = self.verify_repo(name)
            except Exception as e:
                ver = {'status': 'error', 'error': str(e)}
        result['steps'].append({'verify': ver})

        # update DB with latest commit
        try:
            path = Path(meta['path'])
            # obtain latest commit
            code, out, err = await self._run_git(['rev-parse', 'HEAD'], cwd=path)
            if code == 0:
                commit = out.strip()
                ts = datetime.utcnow().isoformat() + 'Z'
                self.update_db(name, commit, ts)
                result['commit'] = commit
        except Exception:
            pass

        # post_sync hooks
        if self.hooks:
            try:
                self.hooks.execute_safe('post_sync', pkg_name=name, build_dir=Path(meta['path']))
            except Exception:
                pass

        result['status'] = 'ok'
        self._log('sync.repo.ok', level='INFO', message=f'synced repo {name}', meta={'name': name})
        return result

    # ---------------- sync all ----------------
    async def sync_all(self, dry_run: bool = False, parallel_limit: int = 4) -> List[Dict[str, Any]]:
        names = list(self._repos.keys())
        results: List[Dict[str, Any]] = []
        if not self.parallel:
            for n in names:
                results.append(await self.sync_repo(n, dry_run=dry_run))
            return results

        sem = asyncio.Semaphore(parallel_limit)

        async def worker(n: str):
            async with sem:
                return await self.sync_repo(n, dry_run=dry_run)

        tasks = [asyncio.create_task(worker(n)) for n in names]
        for t in tasks:
            try:
                r = await t
                results.append(r)
            except Exception as e:
                results.append({'status': 'error', 'error': str(e)})
        return results

    # ---------------- rollback (manual) ----------------
    async def rollback_repo(self, name: str, commit: str, dry_run: bool = False) -> Dict[str, Any]:
        meta = self._repos.get(name)
        if not meta:
            raise SyncError('repo not registered')
        path = Path(meta['path'])
        if dry_run:
            return {'status': 'dryrun', 'action': 'checkout', 'commit': commit}
        # checkout commit (detached) and optionally reset branch
        code, out, err = await self._run_git(['checkout', commit], cwd=path)
        if code != 0:
            return {'status': 'error', 'error': err}
        self._log('sync.rollback', level='INFO', message=f'Rolled back repo {name} to {commit}', meta={'name': name, 'commit': commit})
        return {'status': 'ok', 'commit': commit}

    # ---------------- clean repo ----------------
    def clean_repo(self, name: str) -> Dict[str, Any]:
        meta = self._repos.get(name)
        if not meta:
            raise SyncError('repo not registered')
        path = Path(meta['path'])
        if not path.exists():
            return {'status': 'missing'}
        try:
            # remove untracked files and run garbage collection
            subprocess.run(['git', 'clean', '-fdx'], cwd=str(path))
            subprocess.run(['git', 'gc', '--prune=now'], cwd=str(path))
            return {'status': 'ok'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    # ---------------- meta / db update ----------------
    def get_repo_info(self, name: str) -> Dict[str, Any]:
        meta = self._repos.get(name)
        if not meta:
            raise SyncError('repo not registered')
        path = Path(meta['path'])
        info: Dict[str, Any] = dict(meta)
        try:
            if path.exists() and (path / '.git').exists():
                # head commit
                proc = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=str(path), capture_output=True, text=True)
                if proc.returncode == 0:
                    info['head'] = proc.stdout.strip()
                # size (rough)
                info['size_bytes'] = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
        except Exception:
            pass
        return info

    def update_db(self, name: str, commit_hash: str, timestamp: str) -> None:
        if not self.db:
            return
        try:
            if hasattr(self.db, 'update_repo'):
                self.db.update_repo(name, commit_hash, timestamp)
            elif hasattr(self.db, 'add_log'):
                self.db.add_log(name, 'sync', 'ok', log_path=None)
        except Exception:
            pass


# ---------------- CLI demo ----------------
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(prog='newpkg-sync')
    ap.add_argument('--add', help='add repo in format name=url[,branch]')
    ap.add_argument('--sync', action='store_true')
    ap.add_argument('--sync-all', action='store_true')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    cfg = None
    class CfgShim:
        def get(self, k):
            return None
    cfg = CfgShim()

    sync = NewpkgSync(cfg)
    if args.add:
        s = args.add
        # parse
        if '=' in s:
            name, rest = s.split('=', 1)
            if ',' in rest:
                url, branch = rest.split(',', 1)
            else:
                url, branch = rest, 'main'
            sync.add_repo(name.strip(), url.strip(), branch=branch.strip())
            print('added')
    if args.list:
        print(json.dumps(sync._repos, indent=2))
    if args.sync_all:
        import asyncio
        res = asyncio.run(sync.sync_all(dry_run=args.dry_run))
        print(json.dumps(res, indent=2))
    if args.sync:
        # sync a specific repo name (first registered)
        if not sync._repos:
            print('no repos registered')
        else:
            name = list(sync._repos.keys())[0]
            import asyncio
            res = asyncio.run(sync.sync_repo(name, dry_run=args.dry_run))
            print(json.dumps(res, indent=2))
