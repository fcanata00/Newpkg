"""
newpkg_patcher.py

Patch management for newpkg
- Apply/revert individual patches using 'patch' or 'git apply'
- Apply/revert all detected patches for a package
- Verify patch integrity (sha256)
- Marker file: .applied_patches.json stored in target source dir
- Optional sandbox execution via provided sandbox object or bubblewrap
- Integration points:
    - Config keys: patch.dir, patch.tool, patch.flags, patch.verify_hash, patch.sandbox, sandbox.extra_binds
    - Logger: expects NewpkgLogger (info/warning/error)
    - DB: will call db.record_phase(package, 'patch', status)

Public API:
- NewpkgPatcher(cfg=None, logger=None, db=None, sandbox=None)
- find_patches(pkg_name_or_dir) -> list[Path]
- apply_patch(patch_path, cwd, strip=1, verify_hash=None) -> dict
- revert_patch(patch_path, cwd, strip=1) -> dict
- apply_all(pkg, cwd, stop_on_error=True) -> dict
- revert_all(pkg, cwd, stop_on_error=True) -> dict
- status(cwd) -> dict
- verify_patch(patch_path, expected_sha256) -> bool

"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


class PatchError(Exception):
    pass


@dataclass
class PatchResult:
    patch: str
    status: str
    out: Optional[str] = None
    err: Optional[str] = None
    duration: Optional[float] = None
    sha256: Optional[str] = None


class NewpkgPatcher:
    MARKER = '.applied_patches.json'

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.logger = logger
        self.db = db
        self.sandbox = sandbox

        # config defaults (compatible with older uppercase keys)
        self.patch_dir_key = 'patch.dir'
        self.patch_tool = self._cfg_get('patch.tool', 'patch')
        self.patch_flags = self._cfg_get('patch.flags', ['-p1', '--forward'])
        self.verify_hash_default = bool(self._cfg_get('patch.verify_hash', True))
        self.use_sandbox_default = bool(self._cfg_get('patch.sandbox', True))
        self.sandbox_extra_binds = self._cfg_get('sandbox.extra_binds', []) or []

    # ---------------- internal helpers ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        # try hierarchical lowercase key, then legacy uppercase
        try:
            if self.cfg and hasattr(self.cfg, 'get'):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        # legacy env fallback
        env_key = key.upper().replace('.', '_')
        if env_key in os.environ:
            return os.environ.get(env_key)
        return default

    def _log_info(self, event: str, message: str, **meta):
        if self.logger and hasattr(self.logger, 'info'):
            try:
                self.logger.info(event, message=message, **meta)
                return
            except Exception:
                pass
        # fallback
        print(f"[INFO] {event}: {message}")

    def _log_error(self, event: str, message: str, **meta):
        if self.logger and hasattr(self.logger, 'error'):
            try:
                self.logger.error(event, message=message, **meta)
                return
            except Exception:
                pass
        print(f"[ERROR] {event}: {message}")

    def _marker_path(self, cwd: Path) -> Path:
        return cwd / self.MARKER

    def _read_marker(self, cwd: Path) -> Dict[str, Any]:
        mp = self._marker_path(cwd)
        if not mp.exists():
            return {'applied': []}
        try:
            return json.loads(mp.read_text(encoding='utf-8'))
        except Exception:
            return {'applied': []}

    def _write_marker(self, cwd: Path, data: Dict[str, Any]) -> None:
        mp = self._marker_path(cwd)
        try:
            mp.write_text(json.dumps(data, indent=2), encoding='utf-8')
        except Exception:
            pass

    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with path.open('rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    def _run_cmd(self, cmd: List[str], cwd: Optional[Path] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        start = time.time()
        try:
            proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout)
            dur = time.time() - start
            return {'rc': proc.returncode, 'out': proc.stdout, 'err': proc.stderr, 'duration': dur}
        except subprocess.TimeoutExpired as e:
            dur = time.time() - start
            return {'rc': 124, 'out': '', 'err': f'timeout: {e}', 'duration': dur}
        except Exception as e:
            dur = time.time() - start
            return {'rc': 1, 'out': '', 'err': str(e), 'duration': dur}

    def _prepare_sandbox_cmd(self, inner_cmd: List[str], cwd: Path) -> List[str]:
        # if sandbox provided as object, assume it has .wrap(cmd, binds=[]) method
        if self.sandbox:
            try:
                if hasattr(self.sandbox, 'wrap'):
                    return self.sandbox.wrap(inner_cmd, binds=self.sandbox_extra_binds, cwd=str(cwd))
            except Exception:
                pass
        # Try bubblewrap default invocation
        bwrap = shutil.which('bwrap')
        if not bwrap:
            return inner_cmd
        args = [bwrap, '--unshare-all', '--share-net', '--proc', '/proc', '--dev', '/dev']
        # ro-bind working dir as itself to allow applying patches inside
        args += ['--bind', str(cwd), str(cwd), '--chdir', str(cwd)]
        # extra binds
        for b in self.sandbox_extra_binds:
            args += ['--ro-bind', str(b), str(b)]
        args += ['--'] + inner_cmd
        return args

    # ---------------- public API ----------------
    def find_patches(self, pkg: str) -> List[Path]:
        """Find patch files for a package name or directory.

        - If pkg is a directory, scan that directory for *.patch, *.diff
        - If pkg is a package name, look into configured patch.dir (e.g., patches/<pkg>/)
        """
        p = Path(pkg)
        candidates: List[Path] = []
        if p.exists() and p.is_dir():
            for ext in ('*.patch', '*.diff', '*.patch.gz'):
                for f in p.glob(ext):
                    candidates.append(f)
            return sorted(candidates)
        # treat as package name
        pd = self._cfg_get(self.patch_dir_key)
        if pd:
            base = Path(pd) / pkg
            if base.exists() and base.is_dir():
                for ext in ('*.patch', '*.diff'):
                    for f in base.glob(ext):
                        candidates.append(f)
        # fallback - look under ./patches/<pkg>
        base2 = Path('patches') / pkg
        if base2.exists() and base2.is_dir():
            for ext in ('*.patch', '*.diff'):
                for f in base2.glob(ext):
                    candidates.append(f)
        return sorted(candidates)

    def verify_patch(self, patch_path: str, expected_sha256: Optional[str] = None) -> bool:
        p = Path(patch_path)
        if not p.exists():
            return False
        sha = self._sha256(p)
        if expected_sha256:
            return sha.lower() == expected_sha256.lower()
        # if verification requested but no expected provided, return True but record
        return True

    def apply_patch(self, patch_path: str, cwd: Optional[str] = None, strip: int = 1, verify_hash: Optional[bool] = None) -> Dict[str, Any]:
        cwdp = Path(cwd) if cwd else Path('.').resolve()
        patchf = Path(patch_path)
        if not patchf.exists():
            raise PatchError(f'patch not found: {patch_path}')
        verify_hash = self.verify_hash_default if verify_hash is None else verify_hash
        sha = None
        if verify_hash:
            sha = self._sha256(patchf)
        cmd = []
        # prefer git apply if patch looks like git patch
        use_git = False
        try:
            first = patchf.read_text(errors='ignore').splitlines()[0]
            if first.startswith('From ') or 'git' in first[:20].lower():
                use_git = True
        except Exception:
            pass
        if use_git and shutil.which('git'):
            cmd = ['git', 'apply', f'--directory={cwdp}', str(patchf)]
        else:
            # fallback to standard patch utility
            patch_prog = self.patch_tool or 'patch'
            flags = list(self.patch_flags) if isinstance(self.patch_flags, (list, tuple)) else [self.patch_flags]
            cmd = [patch_prog] + flags + ['-i', str(patchf)]
        # sandbox wrapper
        if self.sandbox or self.use_sandbox_default:
            full_cmd = self._prepare_sandbox_cmd(cmd, cwdp)
        else:
            full_cmd = cmd
        self._log_info('patch.apply.start', f'Applying {patchf.name} to {cwdp}', patch=str(patchf), cwd=str(cwdp))
        start = time.time()
        res = self._run_cmd(full_cmd, cwd=cwdp)
        dur = time.time() - start
        ok = res.get('rc', 1) == 0
        result = PatchResult(patch=str(patchf), status='ok' if ok else 'error', out=res.get('out'), err=res.get('err'), duration=dur, sha256=sha)
        # update marker if ok
        if ok:
            marker = self._read_marker(cwdp)
            entry = {'patch': str(patchf.name), 'applied_at': datetime.utcnow().isoformat() + 'Z', 'sha256': sha}
            marker.setdefault('applied', []).append(entry)
            self._write_marker(cwdp, marker)
            self._log_info('patch.apply.ok', f'Applied {patchf.name}', patch=str(patchf), cwd=str(cwdp), duration=dur)
            # db record
            try:
                if self.db and hasattr(self.db, 'record_phase'):
                    pkgname = cwdp.name
                    self.db.record_phase(pkgname, 'patch', 'ok', log_path=None)
            except Exception:
                pass
            return dict(result.__dict__)
        else:
            self._log_error('patch.apply.fail', f'Failed to apply {patchf.name}', patch=str(patchf), cwd=str(cwdp), stderr=res.get('err'))
            try:
                if self.db and hasattr(self.db, 'record_phase'):
                    pkgname = cwdp.name
                    self.db.record_phase(pkgname, 'patch', 'error', log_path=None)
            except Exception:
                pass
            return dict(result.__dict__)

    def revert_patch(self, patch_path: str, cwd: Optional[str] = None, strip: int = 1) -> Dict[str, Any]:
        """Attempt to revert a given patch. Uses 'patch -R' or 'git apply -R' if available."""
        cwdp = Path(cwd) if cwd else Path('.').resolve()
        patchf = Path(patch_path)
        if not patchf.exists():
            raise PatchError(f'patch not found: {patch_path}')
        # choose tool
        use_git = False
        try:
            first = patchf.read_text(errors='ignore').splitlines()[0]
            if first.startswith('From ') or 'git' in first[:20].lower():
                use_git = True
        except Exception:
            pass
        if use_git and shutil.which('git'):
            cmd = ['git', 'apply', '--reverse', str(patchf)]
        else:
            patch_prog = self.patch_tool or 'patch'
            flags = list(self.patch_flags) if isinstance(self.patch_flags, (list, tuple)) else [self.patch_flags]
            # translate flags: replace -p1 with -p1 for strip; add -R for reverse
            cmd = [patch_prog] + flags + ['-R', '-i', str(patchf)]
        if self.sandbox or self.use_sandbox_default:
            full_cmd = self._prepare_sandbox_cmd(cmd, cwdp)
        else:
            full_cmd = cmd
        self._log_info('patch.revert.start', f'Reverting {patchf.name} in {cwdp}', patch=str(patchf), cwd=str(cwdp))
        start = time.time()
        res = self._run_cmd(full_cmd, cwd=cwdp)
        dur = time.time() - start
        ok = res.get('rc', 1) == 0
        result = PatchResult(patch=str(patchf), status='ok' if ok else 'error', out=res.get('out'), err=res.get('err'), duration=dur)
        if ok:
            # remove from marker
            marker = self._read_marker(cwdp)
            newlist = [e for e in marker.get('applied', []) if e.get('patch') != patchf.name]
            marker['applied'] = newlist
            self._write_marker(cwdp, marker)
            self._log_info('patch.revert.ok', f'Reverted {patchf.name}', patch=str(patchf), cwd=str(cwdp), duration=dur)
            try:
                if self.db and hasattr(self.db, 'record_phase'):
                    self.db.record_phase(cwdp.name, 'patch_revert', 'ok')
            except Exception:
                pass
            return dict(result.__dict__)
        else:
            self._log_error('patch.revert.fail', f'Failed to revert {patchf.name}', patch=str(patchf), cwd=str(cwdp), stderr=res.get('err'))
            try:
                if self.db and hasattr(self.db, 'record_phase'):
                    self.db.record_phase(cwdp.name, 'patch_revert', 'error')
            except Exception:
                pass
            return dict(result.__dict__)

    def apply_all(self, pkg: str, cwd: Optional[str] = None, stop_on_error: bool = True) -> Dict[str, Any]:
        cwdp = Path(cwd) if cwd else Path(pkg) if Path(pkg).exists() else Path('.').resolve()
        patches = self.find_patches(pkg if Path(pkg).is_dir() else pkg)
        results: List[Dict[str, Any]] = []
        ok_count = 0
        for p in patches:
            try:
                r = self.apply_patch(str(p), cwd=str(cwdp))
                results.append(r)
                if r.get('status') == 'ok':
                    ok_count += 1
                else:
                    if stop_on_error:
                        break
            except Exception as e:
                results.append({'patch': str(p), 'status': 'error', 'err': str(e)})
                if stop_on_error:
                    break
        summary = {'total': len(patches), 'applied': ok_count, 'results': results}
        self._log_info('patch.apply_all.done', f'Applied {ok_count}/{len(patches)} patches for {pkg}', pkg=pkg, cwd=str(cwdp))
        return summary

    def revert_all(self, pkg: str, cwd: Optional[str] = None, stop_on_error: bool = True) -> Dict[str, Any]:
        cwdp = Path(cwd) if cwd else Path(pkg) if Path(pkg).exists() else Path('.').resolve()
        marker = self._read_marker(cwdp)
        applied = list(marker.get('applied', []))
        # revert in reverse order
        results: List[Dict[str, Any]] = []
        ok_count = 0
        for entry in reversed(applied):
            patchname = entry.get('patch')
            # try local path resolution
            candidates = [cwdp / patchname, Path('patches') / cwdp.name / patchname]
            found = None
            for c in candidates:
                if c.exists():
                    found = c
                    break
            if not found:
                results.append({'patch': patchname, 'status': 'missing'})
                if stop_on_error:
                    break
                else:
                    continue
            try:
                r = self.revert_patch(str(found), cwd=str(cwdp))
                results.append(r)
                if r.get('status') == 'ok':
                    ok_count += 1
                else:
                    if stop_on_error:
                        break
            except Exception as e:
                results.append({'patch': patchname, 'status': 'error', 'err': str(e)})
                if stop_on_error:
                    break
        summary = {'total': len(applied), 'reverted': ok_count, 'results': results}
        self._log_info('patch.revert_all.done', f'Reverted {ok_count}/{len(applied)} patches for {pkg}', pkg=pkg, cwd=str(cwdp))
        return summary

    def status(self, cwd: Optional[str] = None) -> Dict[str, Any]:
        cwdp = Path(cwd) if cwd else Path('.').resolve()
        marker = self._read_marker(cwdp)
        return {'applied': marker.get('applied', [])}


# quick CLI for local testing
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(prog='newpkg-patcher')
    ap.add_argument('cmd', choices=['list', 'apply', 'revert', 'apply-all', 'revert-all', 'status'])
    ap.add_argument('target', nargs='?', help='package name or patch path or directory')
    ap.add_argument('--cwd', help='working dir to apply in')
    args = ap.parse_args()
    patcher = NewpkgPatcher()
    if args.cmd == 'list':
        print([str(p) for p in patcher.find_patches(args.target or '.')])
    elif args.cmd == 'apply':
        res = patcher.apply_patch(args.target, cwd=args.cwd)
        print(json.dumps(res, indent=2))
    elif args.cmd == 'revert':
        res = patcher.revert_patch(args.target, cwd=args.cwd)
        print(json.dumps(res, indent=2))
    elif args.cmd == 'apply-all':
        res = patcher.apply_all(args.target or '.', cwd=args.cwd)
        print(json.dumps(res, indent=2))
    elif args.cmd == 'revert-all':
        res = patcher.revert_all(args.target or '.', cwd=args.cwd)
        print(json.dumps(res, indent=2))
    elif args.cmd == 'status':
        print(json.dumps(patcher.status(args.cwd), indent=2))
