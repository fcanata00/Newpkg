"""
newpkg_hooks.py

Hook discovery and execution for newpkg
- Discover hooks in project and global hook directories
- Execute hooks with optional sandboxing (integrates with sandbox.wrap or bubblewrap fallback)
- Cache hook metadata (sha256 + mtime) in .newpkg/hooks_cache.json
- Log via provided logger (NewpkgLogger) and record results in newpkg_db via record_hook
- Public API:
    - HooksManager(cfg=None, logger=None, db=None, sandbox=None)
    - discover(hook_dirs: Optional[List[str]] = None)
    - list_hooks(hook_type: Optional[str] = None)
    - run(hook_type, pkg_dir=None, env=None, abort_on_failure=True)
    - execute_safe(...)
    - summary(results)
    - export_cache(path=None)

"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class HooksError(Exception):
    pass


class HooksManager:
    CACHE_DIR = '.newpkg'
    CACHE_FILE = 'hooks_cache.json'

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.logger = logger
        self.db = db
        self.sandbox = sandbox
        # discovered hooks mapping: {hook_type: [Path, ...]}
        self.hooks: Dict[str, List[Path]] = {}
        # cache structure: {str(path): {sha256, mtime}}
        self.cache: Dict[str, Dict[str, Any]] = {}
        self._load_cache()

    # ---------------- config helpers ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, 'get'):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        # env fallback
        ev = key.upper().replace('.', '_')
        if ev in os.environ:
            return os.environ.get(ev)
        return default

    def _log_info(self, event: str, message: str, **meta):
        if self.logger and hasattr(self.logger, 'info'):
            try:
                self.logger.info(f'hook:{event}', message, **meta)
                return
            except Exception:
                pass
        print(f"[INFO] hook:{event} - {message}")

    def _log_error(self, event: str, message: str, **meta):
        if self.logger and hasattr(self.logger, 'error'):
            try:
                self.logger.error(f'hook:{event}', message, **meta)
                return
            except Exception:
                pass
        print(f"[ERROR] hook:{event} - {message}")

    # ---------------- cache ----------------
    def _cache_path(self, base: Optional[Path] = None) -> Path:
        base = base or Path('.').resolve()
        d = base / self.CACHE_DIR
        d.mkdir(parents=True, exist_ok=True)
        return d / self.CACHE_FILE

    def _load_cache(self, base: Optional[Path] = None) -> None:
        try:
            p = self._cache_path(base=base)
            if p.exists():
                self.cache = json.loads(p.read_text(encoding='utf-8'))
            else:
                self.cache = {}
        except Exception:
            self.cache = {}

    def export_cache(self, path: Optional[str] = None, base: Optional[Path] = None) -> Optional[str]:
        try:
            if path:
                out = Path(path)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(self.cache, indent=2), encoding='utf-8')
                return str(out)
            p = self._cache_path(base=base)
            p.write_text(json.dumps(self.cache, indent=2), encoding='utf-8')
            return str(p)
        except Exception:
            return None

    # ---------------- utilities ----------------
    def _sha256(self, p: Path) -> str:
        h = hashlib.sha256()
        with p.open('rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    def _is_executable(self, p: Path) -> bool:
        try:
            st = p.stat()
            return bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        except Exception:
            return False

    # ---------------- discovery ----------------
    def discover(self, hook_dirs: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """Discover hooks in configured directories.

        hook_dirs default order:
          - project hooks: ./hooks
          - global hooks from config: cfg.get('hooks.dir') or /etc/newpkg/hooks
        Hooks should be executable files or scripts named <hook_type>.<ext> or placed in a subdir by type.
        """
        discovered: Dict[str, List[str]] = {}
        # default project hooks
        candidates: List[Path] = []
        if hook_dirs:
            for hd in hook_dirs:
                hp = Path(hd)
                if hp.exists():
                    candidates.append(hp)
        else:
            proj = Path('.') / 'hooks'
            if proj.exists():
                candidates.append(proj)
            cfg_dir = self._cfg_get('hooks.dir', None) or '/etc/newpkg/hooks'
            if cfg_dir:
                cfgp = Path(cfg_dir)
                if cfgp.exists():
                    candidates.append(cfgp)
        # scan candidates
        for base in candidates:
            # if base is a directory of types: hooks/<type>/*
            if base.is_dir():
                for child in base.iterdir():
                    if child.is_dir():
                        htype = child.name
                        for f in child.iterdir():
                            if f.is_file() and (self._is_executable(f) or f.suffix in ('.sh', '.py')):
                                discovered.setdefault(htype, []).append(str(f))
                    else:
                        # file maybe named hooktype.name.ext or <type>.<ext>
                        name = child.name
                        parts = name.split('.')
                        if len(parts) >= 2:
                            htype = parts[0]
                        else:
                            htype = 'generic'
                        if child.is_file() and (self._is_executable(child) or child.suffix in ('.sh', '.py')):
                            discovered.setdefault(htype, []).append(str(child))
        # update internal structure
        self.hooks = {k: [Path(x) for x in v] for k, v in discovered.items()}
        # update cache for discovered files
        for k, lst in self.hooks.items():
            for p in lst:
                try:
                    sha = self._sha256(p)
                    mtime = p.stat().st_mtime
                    key = str(p.resolve())
                    self.cache[key] = {'sha256': sha, 'mtime': mtime, 'type': k}
                except Exception:
                    continue
        # persist cache
        self.export_cache()
        # log summary
        total = sum(len(v) for v in discovered.values())
        self._log_info('discover', f'Discovered {total} hooks across {len(discovered)} types')
        return discovered

    def list_hooks(self, hook_type: Optional[str] = None) -> Dict[str, List[str]]:
        if hook_type:
            lst = self.hooks.get(hook_type, [])
            return {hook_type: [str(x) for x in lst]}
        return {k: [str(x) for x in v] for k, v in self.hooks.items()}

    # ---------------- sandbox helper ----------------
    def _prepare_sandbox_cmd(self, cmd: List[str], cwd: Path, extra_binds: Optional[List[str]] = None) -> List[str]:
        # use sandbox.wrap if available
        if self.sandbox and hasattr(self.sandbox, 'wrap'):
            try:
                return self.sandbox.wrap(cmd, binds=extra_binds or [], cwd=str(cwd))
            except Exception:
                pass
        # fallback to bubblewrap
        bwrap = shutil.which('bwrap')
        if not bwrap:
            return cmd
        args = [bwrap, '--unshare-all', '--share-net', '--proc', '/proc', '--dev', '/dev']
        args += ['--bind', str(cwd), str(cwd), '--chdir', str(cwd)]
        for b in (extra_binds or []):
            try:
                args += ['--ro-bind', str(b), str(b)]
            except Exception:
                continue
        args += ['--'] + cmd
        return args

    # ---------------- run hooks ----------------
    def _exec_single(self, hook_path: Path, cwd: Path, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None, use_sandbox: bool = True) -> Dict[str, Any]:
        cmd = [str(hook_path)]
        # if python script without executable bit, run with python
        if hook_path.suffix in ('.py',) and not self._is_executable(hook_path):
            cmd = [shutil.which('python3') or 'python3', str(hook_path)]
        if use_sandbox:
            extra_binds = self._cfg_get('sandbox.extra_binds', []) or []
            full_cmd = self._prepare_sandbox_cmd(cmd, cwd, extra_binds)
        else:
            full_cmd = cmd
        start = time.time()
        try:
            proc = subprocess.run(full_cmd, cwd=str(cwd), env=(env or os.environ), capture_output=True, text=True, timeout=timeout)
            dur = time.time() - start
            return {'path': str(hook_path), 'rc': proc.returncode, 'out': proc.stdout, 'err': proc.stderr, 'duration': dur}
        except subprocess.TimeoutExpired as e:
            dur = time.time() - start
            return {'path': str(hook_path), 'rc': 124, 'out': '', 'err': f'timeout: {e}', 'duration': dur}
        except Exception as e:
            dur = time.time() - start
            return {'path': str(hook_path), 'rc': 1, 'out': '', 'err': str(e), 'duration': dur}

    def run(self, hook_type: str, pkg_dir: Optional[str] = None, env: Optional[Dict[str, str]] = None, abort_on_failure: bool = True, timeout: Optional[int] = None) -> Dict[str, Any]:
        """Run all hooks of a given type. Returns list of results per hook and summary."""
        cwd = Path(pkg_dir) if pkg_dir else Path('.')
        hooks = self.hooks.get(hook_type, [])
        if not hooks:
            self._log_info('run.empty', f'No hooks for type {hook_type}', type=hook_type, pkg=str(cwd))
            return {'total': 0, 'ok': 0, 'failed': 0, 'results': []}
        results = []
        ok = 0
        failed = 0
        use_sandbox = bool(self._cfg_get('hooks.sandbox', True))
        for h in hooks:
            res = self._exec_single(h, cwd, env=env, timeout=timeout, use_sandbox=use_sandbox)
            results.append(res)
            if res.get('rc', 1) == 0:
                ok += 1
                self._log_info(f'{hook_type}.ok', f'Hook {h.name} succeeded', hook=str(h), pkg=str(cwd), duration=res.get('duration'))
                # record to DB
                try:
                    if self.db and hasattr(self.db, 'record_hook'):
                        self.db.record_hook(cwd.name, hook_type, 'ok')
                except Exception:
                    pass
            else:
                failed += 1
                self._log_error(f'{hook_type}.fail', f'Hook {h.name} failed rc={res.get("rc")}', hook=str(h), pkg=str(cwd), stderr=res.get('err'))
                try:
                    if self.db and hasattr(self.db, 'record_hook'):
                        self.db.record_hook(cwd.name, hook_type, 'error')
                except Exception:
                    pass
                if abort_on_failure:
                    break
        summary = {'total': len(hooks), 'ok': ok, 'failed': failed, 'results': results}
        # emit summary log
        self._log_info(f'{hook_type}.summary', f'{ok}/{len(hooks)} hooks succeeded for {hook_type}', type=hook_type, pkg=str(cwd), ok=ok, failed=failed)
        return summary

    def execute_safe(self, hook_type: str, pkg_dir: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        """Run hooks but do not raise; always return summary."""
        try:
            # if hooks.silent_continue true, we won't abort on failure
            abort = bool(self._cfg_get('hooks.abort_on_failure', True))
            summary = self.run(hook_type, pkg_dir=pkg_dir, env=env, abort_on_failure=abort, timeout=timeout)
            return summary
        except Exception as e:
            self._log_error('execute_safe.exception', f'Exception running hooks: {e}', hook_type=hook_type, pkg=pkg_dir)
            return {'total': 0, 'ok': 0, 'failed': 0, 'results': [], 'error': str(e)}

    def summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        return {'total': results.get('total', 0), 'ok': results.get('ok', 0), 'failed': results.get('failed', 0)}


# ---------------- CLI for testing ----------------
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(prog='newpkg-hooks')
    ap.add_argument('cmd', choices=['discover', 'list', 'run'])
    ap.add_argument('--type', help='hook type to run/list')
    ap.add_argument('--dir', help='package dir or hooks dir')
    ap.add_argument('--no-cache', action='store_true')
    args = ap.parse_args()

    mgr = HooksManager()
    if args.cmd == 'discover':
        out = mgr.discover(hook_dirs=[args.dir] if args.dir else None)
        print(json.dumps(out, indent=2))
    elif args.cmd == 'list':
        print(json.dumps(mgr.list_hooks(args.type), indent=2))
    elif args.cmd == 'run':
        if not args.type:
            print('please pass --type')
        else:
            res = mgr.execute_safe(args.type, pkg_dir=args.dir)
            print(json.dumps(res, indent=2))
