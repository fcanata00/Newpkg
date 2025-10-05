"""
newpkg_hooks.py

Gerenciamento de hooks para newpkg.
- Descobre hooks locais (dentro de package/hooks) e globais (/etc/newpkg/hooks.d, /usr/share/newpkg/hooks)
- Valida (permissões, hash) e executa hooks dentro do sandbox (opcional)
- Gera e mantém cache em .newpkg/hooks_cache.json
- Fornece API para executar hooks por estágio (pre/post configure/build/install/remove), on_error e cleanup

Uso:
    hooks = NewpkgHooks(cfg, logger=logger, sandbox=sandbox)
    hooks.discover(Path('package'))
    hooks.run('pre_build', pkg_name='mypkg', build_dir=Path('...'))

"""
from __future__ import annotations

import os
import stat
import subprocess
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


HOOK_TYPES = [
    'pre_configure', 'post_configure',
    'pre_build', 'post_build',
    'pre_install', 'post_install',
    'pre_remove', 'post_remove',
    'on_error', 'cleanup',
]

GLOBAL_HOOK_DIRS = [Path('/etc/newpkg/hooks.d'), Path('/usr/share/newpkg/hooks')]
CACHE_PATH = Path('.newpkg') / 'hooks_cache.json'


class HookError(Exception):
    pass


class NewpkgHooks:
    def __init__(self, cfg: Any = None, logger: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.logger = logger
        self.sandbox = sandbox
        self.hooks: Dict[str, List[Path]] = {t: [] for t in HOOK_TYPES}
        self.allow_global = True
        try:
            self.allow_global = bool(self.cfg.get('hooks.allow_global'))
        except Exception:
            self.allow_global = True
        self.abort_on_failure = True
        try:
            self.abort_on_failure = bool(self.cfg.get('hooks.abort_on_failure'))
        except Exception:
            self.abort_on_failure = True
        self.default_sandbox = True
        try:
            self.default_sandbox = bool(self.cfg.get('hooks.default_sandbox'))
        except Exception:
            self.default_sandbox = True

        # ensure cache dir
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._load_cache()
        # load global hooks
        if self.allow_global:
            self.load_global_hooks()

    # ---------------- cache ----------------
    def _load_cache(self) -> None:
        if CACHE_PATH.exists():
            try:
                self._cache = json.loads(CACHE_PATH.read_text(encoding='utf-8'))
            except Exception:
                self._cache = {}
        else:
            self._cache = {}

    def _save_cache(self) -> None:
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            CACHE_PATH.write_text(json.dumps(self._cache, indent=2, ensure_ascii=False), encoding='utf-8')
        except Exception:
            pass

    # ---------------- discovery ----------------
    def discover(self, pkg_dir: Path) -> Dict[str, List[str]]:
        """Discover hooks inside a package directory. Returns mapping hook_type -> list of path strings."""
        pkg_dir = Path(pkg_dir)
        found: Dict[str, List[str]] = {t: [] for t in HOOK_TYPES}
        hooks_dir = pkg_dir / 'hooks'
        if not hooks_dir.exists() or not hooks_dir.is_dir():
            return found
        for t in HOOK_TYPES:
            candidate = hooks_dir / f"{t}.sh"
            if candidate.exists() and candidate.is_file():
                # register localized hook with highest priority
                self.register(t, candidate)
                found[t].append(str(candidate))
        # update cache metadata for pkg
        self._cache[str(pkg_dir)] = {'discovered_at': datetime.utcnow().isoformat() + 'Z', 'hooks': found}
        self._save_cache()
        return found

    def load_global_hooks(self) -> None:
        """Load hooks from global directories."""
        for d in GLOBAL_HOOK_DIRS:
            try:
                if not d.exists():
                    continue
                for p in sorted(d.iterdir()):
                    if not p.is_file():
                        continue
                    name = p.name
                    # global hooks can be named like pre_build.sh or prefixed with stage
                    for t in HOOK_TYPES:
                        if name.startswith(t):
                            self.register(t, p)
            except Exception:
                continue

    # ---------------- register / list ----------------
    def register(self, hook_type: str, path: Path) -> None:
        if hook_type not in HOOK_TYPES:
            raise HookError(f'Unknown hook type: {hook_type}')
        p = Path(path)
        if p not in self.hooks[hook_type]:
            self.hooks[hook_type].append(p)
            # update cache
            self._cache.setdefault('registered', {}).setdefault(hook_type, [])
            rp = str(p)
            if rp not in self._cache['registered'].get(hook_type, []):
                self._cache['registered'].setdefault(hook_type, []).append(rp)
            self._save_cache()

    def list_hooks(self) -> Dict[str, List[str]]:
        return {t: [str(p) for p in self.hooks.get(t, [])] for t in HOOK_TYPES}

    # ---------------- validation ----------------
    def validate_hook(self, path: Path, check_hash: bool = False) -> Tuple[bool, Optional[str]]:
        """Validate that hook is executable and optionally return its sha256 hash.

        Returns (valid, hash_hex) where hash_hex may be None if not computed.
        """
        p = Path(path)
        if not p.exists() or not p.is_file():
            return False, None
        mode = p.stat().st_mode
        if not (mode & stat.S_IXUSR):
            # try to set executable bit for user
            try:
                p.chmod(mode | stat.S_IXUSR)
            except Exception:
                return False, None
        h = None
        if check_hash:
            try:
                h = hashlib.sha256(p.read_bytes()).hexdigest()
            except Exception:
                h = None
        return True, h

    # ---------------- run hook ----------------
    def _build_env(self, pkg_name: Optional[str], stage: Optional[str], build_dir: Optional[Path], destdir: Optional[Path], profile: Optional[str]) -> Dict[str, str]:
        env = os.environ.copy()
        if pkg_name:
            env['NEWPKG_PKGNAME'] = str(pkg_name)
        if stage:
            env['NEWPKG_STAGE'] = stage
        if profile:
            env['NEWPKG_PROFILE'] = profile
        if build_dir:
            env['NEWPKG_BUILDDIR'] = str(build_dir)
        if destdir:
            env['NEWPKG_DESTDIR'] = str(destdir)
        # include config-provided env overrides
        try:
            extra = self.cfg.get('hooks.env') or {}
            if isinstance(extra, dict):
                for k, v in extra.items():
                    env[str(k)] = str(v)
        except Exception:
            pass
        return env

    def _exec_local(self, path: Path, cwd: Optional[Path], env: Dict[str, str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        # run locally (not sandboxed)
        try:
            cp = subprocess.run([str(path)], cwd=str(cwd) if cwd else None, env=env, capture_output=True, text=True, timeout=timeout)
            return cp.returncode, cp.stdout, cp.stderr
        except subprocess.TimeoutExpired as e:
            return -1, e.stdout or '', f'Timeout after {timeout}s'
        except Exception as e:
            return -1, '', str(e)

    def run(self, hook_type: str, pkg_name: Optional[str] = None, build_dir: Optional[Path] = None, destdir: Optional[Path] = None, profile: Optional[str] = None, use_sandbox: Optional[bool] = None, timeout: Optional[int] = None, abort_on_fail: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Run all hooks of type `hook_type` (registered and discovered).

        Returns list of result dicts with keys: path, rc, stdout, stderr, duration, started_at, finished_at, hash
        """
        if hook_type not in HOOK_TYPES:
            raise HookError(f'Unknown hook type: {hook_type}')
        if use_sandbox is None:
            use_sandbox = self.default_sandbox
        if abort_on_fail is None:
            abort_on_fail = self.abort_on_failure

        results = []
        env = self._build_env(pkg_name, hook_type, build_dir, destdir, profile)
        hooks = list(self.hooks.get(hook_type, []))

        for h in hooks:
            started = datetime.utcnow()
            started_at = started.isoformat() + 'Z'
            valid, hsh = self.validate_hook(h, check_hash=True)
            if not valid:
                msg = f'Hook {h} not valid or not executable'
                self._log_event(h, 'ERROR', msg, {'pkg': pkg_name, 'hook': str(h)})
                if abort_on_fail:
                    raise HookError(msg)
                else:
                    results.append({'path': str(h), 'rc': -1, 'stdout': '', 'stderr': msg, 'hash': hsh, 'started_at': started_at, 'finished_at': None, 'duration': 0.0})
                    continue

            # execute
            try:
                if use_sandbox and self.sandbox:
                    # execute inside sandbox; sandbox.run expects a list command
                    cmd = ['/bin/sh', str(h)]
                    res = self.sandbox.run(cmd, cwd=build_dir, env=env, timeout=timeout)
                    rc = res.returncode
                    out = res.stdout
                    err = res.stderr
                else:
                    rc, out, err = self._exec_local(h, cwd=build_dir, env=env, timeout=timeout)
            except Exception as e:
                rc = -1
                out = ''
                err = str(e)

            finished = datetime.utcnow()
            finished_at = finished.isoformat() + 'Z'
            duration = (finished - started).total_seconds()

            resdict = {
                'path': str(h),
                'rc': rc,
                'stdout': out,
                'stderr': err,
                'hash': hsh,
                'started_at': started_at,
                'finished_at': finished_at,
                'duration': duration,
            }
            results.append(resdict)

            # logging
            level = 'INFO' if rc == 0 else 'ERROR'
            self._log_event(h, level, f'Hook {hook_type} executed', {'pkg': pkg_name, 'hook': str(h), 'rc': rc})

            if rc != 0:
                # run on_error hooks
                try:
                    self.execute_safe('on_error', pkg_name=pkg_name, build_dir=build_dir, destdir=destdir, profile=profile)
                except Exception:
                    pass
                if abort_on_fail:
                    raise HookError(f'Hook {h} failed with rc={rc}: {err}')

        return results

    def execute_safe(self, hook_type: str, **kwargs) -> List[Dict[str, Any]]:
        try:
            return self.run(hook_type, **kwargs)
        except Exception as e:
            # log and swallow
            self._log_event(None, 'ERROR', f'Hook {hook_type} execution raised: {e}', {})
            return []

    # ---------------- utilities ----------------
    def _log_event(self, hook_path: Optional[Path], level: str, message: str, metadata: Dict[str, Any]) -> None:
        if self.logger:
            meta = dict(metadata)
            if hook_path:
                meta['hook'] = str(hook_path)
            self.logger.log_event('hook_event', level=level, message=message, metadata=meta)

    def export_cache(self, output: Optional[Path] = None) -> Dict[str, Any]:
        data = self._cache
        if output:
            try:
                Path(output).parent.mkdir(parents=True, exist_ok=True)
                Path(output).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
            except Exception:
                pass
        return data


# ---------------- CLI demo ----------------
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(prog='newpkg-hooks')
    ap.add_argument('--discover', help='package dir to discover hooks in')
    ap.add_argument('--run', help='hook type to run', choices=HOOK_TYPES)
    ap.add_argument('--pkg', help='package name', default=None)
    ap.add_argument('--build-dir', help='build dir for hooks', default=None)
    args = ap.parse_args()

    cfg = None
    try:
        class CfgShim:
            def get(self, k):
                return None
        cfg = CfgShim()
    except Exception:
        cfg = None

    hooks = NewpkgHooks(cfg)
    if args.discover:
        found = hooks.discover(Path(args.discover))
        print(json.dumps(found, indent=2))
    if args.run:
        bd = Path(args.build_dir) if args.build_dir else None
        res = hooks.execute_safe(args.run, pkg_name=args.pkg, build_dir=bd)
        print(json.dumps(res, indent=2))
