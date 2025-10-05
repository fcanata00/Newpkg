"""
newpkg_sandbox.py

Sandbox abstraction for newpkg builds and operations.
- Supports backends: bubblewrap (bwrap), proot (fallback), and a "none" (no sandbox) mode.
- Integrates with newpkg_config (cfg.get), newpkg_logger (NewpkgLogger) and newpkg_db (NewpkgDB) when provided.
- Provides convenient API:
    - Sandbox(cfg, logger=None, db=None, name=None)
    - sandbox.run(cmd, cwd=None, env=None, timeout=None) -> SandboxResult
    - sandbox.run_in_sandbox(cmd, pkg=None, ...) -> same as run but creates ephemeral workspace
    - sandbox.bind(src, dest, ro=True) to add binds
    - sandbox.sandbox_for_package(pkg_name, layout_dirs=None) -> prepares layout and returns path
    - sandbox.cleanup() to cleanup temporary sandboxes

Security notes:
- By default destructive binds are prevented; configuration controls allowlisting.
- Removes dangerous env vars by default when entering sandbox.

This module is defensive: if backends are missing it falls back gracefully and logs warnings.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try imports from project; fallbacks if not available
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


@dataclass
class SandboxResult:
    rc: int
    out: str
    err: str
    duration: float
    backend: str
    created_tmp: Optional[str] = None


class SandboxError(Exception):
    pass


class Sandbox:
    """Sandbox wrapper supporting bwrap and proot with safe defaults."""

    DEFAULT_ALLOWED_BINDS = ['/tmp', '/var/tmp', '/usr', '/bin', '/lib', '/lib64', '/etc', '/home']

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, name: Optional[str] = None):
        self.cfg = cfg
        self.logger = logger or (NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None)
        self.db = db
        self.name = name or f'newpkg-sandbox-{uuid.uuid4().hex[:8]}'

        # backend selection
        self._preferred_backend = (self._cfg_get('sandbox.backend') or os.environ.get('NEWPKG_SANDBOX_BACKEND') or 'bwrap').lower()
        self._backend = self._detect_backend()

        # sandbox root (for ephemeral sandboxes)
        self._tmp_roots: List[Path] = []

        # binds list (tuples of src,dest,ro)
        self._binds: List[Tuple[str, str, bool]] = []

        # security options
        self.rootless = bool(self._cfg_get('sandbox.rootless', True))
        self.max_mem = self._cfg_get('sandbox.max_mem', None)  # e.g. '512M'
        self.max_cpu = int(self._cfg_get('sandbox.max_cpu', 0) or 0)

        # allowlist for binds - absolute paths only
        self.allowed_binds = list(self._cfg_get('sandbox.allowed_binds', self.DEFAULT_ALLOWED_BINDS))

        # cleanup on exit
        self.preserve_tmp = bool(self._cfg_get('sandbox.preserve_tmp', False))

        # sanitize env list to remove dangerous variables
        self._blacklist_env = set(self._cfg_get('sandbox.blacklist_env', ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH']))

        self._log_info('init', f'Initialized sandbox (backend={self._backend})', backend=self._backend, name=self.name)

    # ---------------- config helper ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, 'get'):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        # try env fallback
        ev = key.upper().replace('.', '_')
        return os.environ.get(ev, default)

    # ---------------- logging helpers ----------------
    def _log_info(self, event: str, message: str, **meta):
        if self.logger and hasattr(self.logger, 'info'):
            try:
                self.logger.info(f'sandbox:{event}', message, sandbox=self.name, **meta)
                return
            except Exception:
                pass
        print(f'[INFO] sandbox:{event} - {message}')

    def _log_error(self, event: str, message: str, **meta):
        if self.logger and hasattr(self.logger, 'error'):
            try:
                self.logger.error(f'sandbox:{event}', message, sandbox=self.name, **meta)
                return
            except Exception:
                pass
        print(f'[ERROR] sandbox:{event} - {message}')

    # ---------------- backend detection ----------------
    def _detect_backend(self) -> str:
        # try to honor preferred backend
        pref = self._preferred_backend
        if pref == 'bwrap' and shutil.which('bwrap'):
            return 'bwrap'
        if pref == 'proot' and shutil.which('proot'):
            return 'proot'
        # fallback order
        if shutil.which('bwrap'):
            return 'bwrap'
        if shutil.which('proot'):
            return 'proot'
        # no sandbox available
        return 'none'

    # ---------------- bind management ----------------
    def bind(self, src: str, dest: Optional[str] = None, ro: bool = True) -> None:
        """Add a bind mount for the sandbox. dest defaults to same path inside sandbox root."""
        srcp = str(Path(src).expanduser().resolve())
        # simple allowlist check
        allowed = any(srcp.startswith(str(Path(a).resolve())) for a in self.allowed_binds)
        if not allowed:
            raise SandboxError(f'Bind path {srcp} not allowed by sandbox.allowed_binds')
        destp = dest or srcp
        self._binds.append((srcp, destp, bool(ro)))
        self._log_info('bind.add', f'Bind added {srcp} -> {destp} (ro={ro})', src=srcp, dest=destp, ro=ro)

    # ---------------- environment sanitization ----------------
    def _sanitize_env(self, env: Optional[Dict[str, str]]) -> Dict[str, str]:
        base = dict(os.environ)
        # remove blacklisted
        for k in list(base.keys()):
            if k in self._blacklist_env:
                base.pop(k, None)
        # apply overrides
        if env:
            base.update(env)
        # ensure NEWPKG_* helpful paths
        # provide defaults if not present
        base.setdefault('NEWPKG_SOURCES', os.environ.get('NEWPKG_SOURCES', '/sources'))
        base.setdefault('NEWPKG_BUILD', os.environ.get('NEWPKG_BUILD', '/build'))
        base.setdefault('NEWPKG_DEST', os.environ.get('NEWPKG_DEST', '/'))
        return base

    # ---------------- helpers to build command wrappers ----------------
    def _build_bwrap_cmd(self, inner_cmd: List[str], cwd: Optional[str] = None) -> List[str]:
        args: List[str] = ['bwrap', '--unshare-all', '--share-net', '--proc', '/proc', '--dev', '/dev']
        # set tmp and home inside
        args += ['--tmpfs', '/tmp', '--tmpfs', '/var/tmp']
        # add binds
        for src, dest, ro in self._binds:
            if ro:
                args += ['--ro-bind', src, dest]
            else:
                args += ['--bind', src, dest]
        # working dir
        if cwd:
            args += ['--chdir', cwd]
        args += ['--'] + inner_cmd
        return args

    def _build_proot_cmd(self, inner_cmd: List[str], cwd: Optional[str] = None) -> List[str]:
        # proot basic wrapper: proot -b src:dest -- /bin/sh -c 'cd cwd && exec ...'
        args = ['proot']
        for src, dest, ro in self._binds:
            args += ['-b', f'{src}:{dest}']
        if cwd:
            inner = ['sh', '-c', f'cd {shlex_quote(cwd)} && exec {shlex_join(inner_cmd)}']
        else:
            inner = inner_cmd
        args += ['--'] + inner
        return args

    # ---------------- run command ----------------
    def run(self, cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> SandboxResult:
        """Run a command in the chosen sandbox backend and return SandboxResult.

        cmd: list of argv (no shell). cwd is path inside host (we bind it into sandbox if needed).
        """
        start = time.time()
        backend_used = self._backend
        sanitized_env = self._sanitize_env(env)

        # ensure cwd exists
        cwdp = Path(cwd) if cwd else None
        if cwdp and not cwdp.exists():
            raise SandboxError(f'cwd {cwd} does not exist')

        # always add cwd to binds so that inner command can access it at same path
        if cwdp:
            try:
                self.bind(str(cwdp), str(cwdp), ro=False)
            except SandboxError:
                # bind may already exist or be disallowed
                pass

        if backend_used == 'bwrap':
            wrapper = self._build_bwrap_cmd(cmd, cwd)
        elif backend_used == 'proot':
            # proot may not be ideal; fallback to running directly
            wrapper = self._build_proot_cmd(cmd, cwd)
        else:
            # no sandbox: run directly
            wrapper = cmd

        # run
        try:
            proc = subprocess.run(wrapper, cwd=str(cwdp) if cwdp else None, env=sanitized_env, capture_output=True, text=True, timeout=timeout)
            rc = proc.returncode
            out = proc.stdout or ''
            err = proc.stderr or ''
        except subprocess.TimeoutExpired as e:
            rc = 124
            out = ''
            err = f'timeout: {e}'
        except Exception as e:
            rc = 1
            out = ''
            err = str(e)

        dur = time.time() - start
        # record to DB if available
        try:
            if self.db and hasattr(self.db, 'record_phase'):
                pkg = os.environ.get('NEWPKG_CURRENT_PKG') or self.name
                self.db.record_phase(pkg, 'sandbox.run', 'ok' if rc == 0 else 'error', log_path=None)
        except Exception:
            pass

        # log
        if rc == 0:
            self._log_info('run.ok', f'Cmd succeeded: {cmd}', cmd=cmd, rc=rc, duration=dur)
        else:
            self._log_error('run.fail', f'Cmd failed: {cmd} rc={rc}', cmd=cmd, rc=rc, duration=dur, stderr=err)

        return SandboxResult(rc=rc, out=out, err=err, duration=dur, backend=backend_used)

    # ---------------- ephemeral sandbox helpers ----------------
    def sandbox_for_package(self, pkg_name: str, layout_dirs: Optional[Dict[str, str]] = None) -> Path:
        """Create a sandbox workspace root for a package and return its path.

        layout_dirs can map names like 'sources','build','dest' to relative paths inside the sandbox root.
        """
        tmp = Path(tempfile.mkdtemp(prefix=f'newpkg_sandbox_{pkg_name}_'))
        self._tmp_roots.append(tmp)
        # default layout
        layout = layout_dirs or {'sources': 'sources', 'build': 'build', 'dest': 'dest', 'tmp': 'tmp'}
        for k, v in layout.items():
            (tmp / v).mkdir(parents=True, exist_ok=True)
        self._log_info('sandbox.create', f'Created sandbox workspace at {tmp}', pkg=pkg_name, path=str(tmp))
        return tmp

    def run_in_sandbox(self, cmd: List[str], pkg_name: Optional[str] = None, timeout: Optional[int] = None) -> SandboxResult:
        """Create an ephemeral sandbox, run cmd inside, and clean up (unless preserve_tmp True)."""
        root = self.sandbox_for_package(pkg_name or 'ephemeral')
        # bind root into sandbox
        try:
            self.bind(str(root), str(root), ro=False)
        except Exception:
            pass
        # run with cwd=root
        try:
            res = self.run(cmd, cwd=str(root), timeout=timeout)
            return res
        finally:
            if not self.preserve_tmp:
                try:
                    shutil.rmtree(root)
                    self._tmp_roots.remove(root)
                    self._log_info('sandbox.cleanup', f'Removed sandbox {root}')
                except Exception:
                    pass

    def cleanup(self) -> None:
        """Cleanup any temporary roots created by this Sandbox instance."""
        for p in list(self._tmp_roots):
            try:
                if p.exists():
                    if not self.preserve_tmp:
                        shutil.rmtree(p)
                        self._log_info('sandbox.cleanup', f'Removed {p}')
                self._tmp_roots.remove(p)
            except Exception as e:
                self._log_error('sandbox.cleanup.fail', f'Failed to cleanup {p}: {e}')


# small helpers for safe shell building
def shlex_quote(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"'


def shlex_join(args: List[str]) -> str:
    return ' '.join(shlex_quote(a) for a in args)


# CLI for quick tests
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(prog='newpkg-sandbox')
    parser.add_argument('cmd', nargs=argparse.REMAINDER, help='command to run in sandbox')
    parser.add_argument('--backend', choices=['bwrap', 'proot', 'none'], help='force backend')
    parser.add_argument('--preserve', action='store_true', help='preserve temporary sandbox')
    args = parser.parse_args()

    cfg = None
    if init_config:
        try:
            cfg = init_config()
        except Exception:
            cfg = None
    db = NewpkgDB(cfg) if NewpkgDB and cfg is not None else None
    logger = NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None

    sb = Sandbox(cfg=cfg, logger=logger, db=db)
    if args.backend:
        sb._preferred_backend = args.backend
        sb._backend = sb._detect_backend()
    sb.preserve_tmp = bool(args.preserve)
    if not args.cmd:
        print('no command provided; use -- to pass a command')
    else:
        res = sb.run(args.cmd)
        print('rc=', res.rc)
        print('out=', res.out)
        print('err=', res.err)
