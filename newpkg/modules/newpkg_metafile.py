#!/usr/bin/env python3
"""
newpkg_metafile.py

Metafile manager for newpkg: load/merge/validate/resolve/apply/prepare
Integrations:
 - newpkg_config (init_config)
 - newpkg_logger (NewpkgLogger)
 - newpkg_db (NewpkgDB)
 - newpkg_download (NewpkgDownloader.batch_download)
 - newpkg_patcher (NewpkgPatcher.apply_all)
 - newpkg_hooks (HooksManager.execute_safe)

Public API (class Metafile):
 - load(path)
 - merge(other_path)
 - validate()
 - expand_env(extra_env)
 - resolve_sources(download_dir, parallel)
 - verify_sources()
 - apply_patches(workdir)
 - prepare_environment(destdir, builddir)
 - export_to_db()
 - generate_manifest()
 - summary()

This implementation is defensive: optional dependencies are handled gracefully and operations fall back to best-effort behavior.
"""
from __future__ import annotations

import json
import os
import shutil
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# optional internal modules
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
    from newpkg_download import NewpkgDownloader
except Exception:
    NewpkgDownloader = None

try:
    from newpkg_patcher import NewpkgPatcher
except Exception:
    NewpkgPatcher = None

try:
    from newpkg_hooks import HooksManager
except Exception:
    HooksManager = None

CACHE_DIR = Path.home() / '.cache' / 'newpkg' / 'metafiles'
CACHE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class Metafile:
    raw: Dict[str, Any] = field(default_factory=dict)
    path: Optional[Path] = None
    cfg: Any = None
    logger: Any = None
    db: Any = None
    downloader: Any = None
    patcher: Any = None
    hooks: Any = None

    def __post_init__(self):
        if not self.logger and NewpkgLogger and self.cfg is not None:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, self.db)
            except Exception:
                self.logger = None
        if not self.db and NewpkgDB and self.cfg is not None:
            try:
                self.db = NewpkgDB(self.cfg)
            except Exception:
                self.db = None
        if not self.downloader and NewpkgDownloader and self.cfg is not None:
            try:
                self.downloader = NewpkgDownloader(self.cfg, self.logger, self.db)
            except Exception:
                self.downloader = None
        if not self.patcher and NewpkgPatcher and self.cfg is not None:
            try:
                self.patcher = NewpkgPatcher(self.cfg, self.logger, self.db)
            except Exception:
                self.patcher = None
        if not self.hooks and HooksManager and self.cfg is not None:
            try:
                self.hooks = HooksManager(self.cfg, self.logger, self.db)
            except Exception:
                self.hooks = None

    # ---------------- utils ----------------
    def _log(self, level: str, event: str, message: str = '', **meta):
        if self.logger:
            try:
                fn = getattr(self.logger, level.lower(), None)
                if fn:
                    fn(event, message, **meta)
                    return
            except Exception:
                pass
        print(f'[{level}] {event}: {message}')

    def _cache_path(self) -> Path:
        if not self.path:
            return CACHE_DIR / 'unnamed.json'
        key = f"{self.path.name}.json"
        return CACHE_DIR / key

    # ---------------- load / merge ----------------
    def load(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(path)
        self.path = p
        try:
            text = p.read_text(encoding='utf-8')
            # try json first, then toml if available
            if p.suffix in ('.json',):
                self.raw = json.loads(text)
            else:
                # try to parse as toml if lib available
                try:
                    import tomllib as _toml
                    self.raw = _toml.loads(text)
                except Exception:
                    try:
                        import tomli as _tomli
                        self.raw = _tomli.loads(text)
                    except Exception:
                        # fallback: attempt json parse
                        self.raw = json.loads(text)
            self._log('info', 'metafile.load', f'Loaded metafile {path}', path=str(p))
            # write cache
            try:
                self._cache_write()
            except Exception:
                pass
        except Exception as e:
            self._log('error', 'metafile.load.fail', f'Failed to load {path}: {e}', path=str(p))
            raise

    def merge(self, other_path: str) -> None:
        # load other and shallow-merge arrays and dicts
        p = Path(other_path)
        if not p.exists():
            raise FileNotFoundError(other_path)
        try:
            other = Metafile(cfg=self.cfg, logger=self.logger, db=self.db)
            other.load(other_path)
            # merge simple: combine lists for keys: sources, patches, env, phases
            for key in ('sources', 'patches'):
                a = self.raw.get(key, [])
                b = other.raw.get(key, [])
                merged = list(a) + [x for x in b if x not in a]
                if merged:
                    self.raw[key] = merged
            # merge env/phases as dicts (other overrides base)
            for key in ('env', 'phases', 'build', 'meta'):
                base = dict(self.raw.get(key, {}) or {})
                otherd = dict(other.raw.get(key, {}) or {})
                base.update(otherd)
                if base:
                    self.raw[key] = base
            self._log('info', 'metafile.merge', f'Merged {other_path} into {self.path or "<in-memory>"}', other=str(other_path))
        except Exception as e:
            self._log('error', 'metafile.merge.fail', f'Failed to merge {other_path}: {e}', other=str(other_path))
            raise

    # ---------------- cache helpers ----------------
    def _cache_write(self) -> None:
        p = self._cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            p.write_text(json.dumps({'loaded_at': datetime.utcnow().isoformat() + 'Z', 'raw': self.raw}, indent=2), encoding='utf-8')
        except Exception:
            pass

    def _cache_read(self) -> Optional[Dict[str, Any]]:
        p = self._cache_path()
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            return None

    # ---------------- validation ----------------
    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        # basic required fields
        name = self.raw.get('name') or (self.path.name if self.path else None)
        if not name:
            errors.append('missing name')
        sources = self.raw.get('sources', [])
        if not isinstance(sources, list):
            errors.append('sources must be a list')
        else:
            for s in sources:
                if not isinstance(s, dict) and not isinstance(s, str):
                    errors.append(f'invalid source entry: {s}')
                else:
                    # if dict, expect url and optional sha256
                    if isinstance(s, dict):
                        if 'url' not in s:
                            errors.append(f'source missing url: {s}')
                        if 'sha256' in s and len(str(s.get('sha256'))) not in (64,):
                            errors.append(f'invalid sha256 for {s.get("url")}')
        patches = self.raw.get('patches', [])
        if patches and not isinstance(patches, list):
            errors.append('patches must be a list')
        # optional consistency checks
        # detect duplicate URLs
        urls = []
        for s in sources:
            u = s['url'] if isinstance(s, dict) else s
            if u in urls:
                errors.append(f'duplicate source URL {u}')
            urls.append(u)
        ok = len(errors) == 0
        if ok:
            self._log('info', 'metafile.validate.ok', f'Metafile validated: {name}', name=name)
        else:
            self._log('error', 'metafile.validate.fail', f'Metafile validation failed: {errors}', errors=errors)
        return ok, errors

    # ---------------- environment expansion ----------------
    def expand_env(self, extra_env: Optional[Dict[str, str]] = None) -> None:
        env = dict(self.raw.get('env', {}) or {})
        env.update(extra_env or {})
        # simple ${VAR} expansion for strings in env and phases
        def expand_value(v: Any) -> Any:
            if isinstance(v, str):
                try:
                    return os.path.expandvars(v.format(**env))
                except Exception:
                    return os.path.expandvars(v)
            return v

        self.raw['env'] = {k: expand_value(v) for k, v in env.items()}
        phases = self.raw.get('phases', {}) or {}
        for phase, cmds in phases.items():
            if isinstance(cmds, list):
                phases[phase] = [expand_value(c) for c in cmds]
        self.raw['phases'] = phases
        self._log('info', 'metafile.expand', 'Expanded environment and phases', env_keys=list(self.raw['env'].keys()))

    # ---------------- sources resolution ----------------
    def resolve_sources(self, download_dir: Optional[str] = None, parallel: Optional[int] = None) -> List[Dict[str, Any]]:
        tasks: List[Dict[str, Any]] = []
        download_dir = download_dir or str(Path('.').resolve() / 'sources')
        ddir = Path(download_dir)
        ddir.mkdir(parents=True, exist_ok=True)
        for s in self.raw.get('sources', []) or []:
            if isinstance(s, str):
                url = s
                fname = None
                sha = None
            else:
                url = s.get('url')
                fname = s.get('filename')
                sha = s.get('sha256') or s.get('checksum')
            dest = str(ddir / (fname or Path(url).name))
            tasks.append({'url': url, 'dest': dest, 'checksum': sha})
        if not tasks:
            return []
        # call downloader.batch_download if available
        if self.downloader and hasattr(self.downloader, 'batch_download'):
            try:
                res = self.downloader.batch_download(self.raw.get('name', 'pkg'), tasks, parallel=parallel)
                self._log('info', 'metafile.resolve', f'Downloaded {len(res)} sources', package=self.raw.get('name'))
                return res
            except Exception as e:
                self._log('error', 'metafile.resolve.fail', f'Download failed: {e}')
                raise
        # fallback: attempt simple sync downloads via downloader.download_sync if present
        results = []
        for t in tasks:
            try:
                if self.downloader and hasattr(self.downloader, 'download_sync'):
                    r = self.downloader.download_sync(t['url'], dest=t['dest'], checksum=t.get('checksum'))
                    results.append(r)
                else:
                    # best-effort using curl/wget
                    from subprocess import run
                    cmd = ['curl', '-L', '-o', t['dest'], t['url']]
                    proc = run(cmd)
                    results.append({'rc': proc.returncode, 'out': t['dest'], 'err': '' if proc.returncode == 0 else 'curl failed'})
            except Exception as e:
                results.append({'rc': 1, 'out': '', 'err': str(e)})
        return results

    def verify_sources(self) -> List[Dict[str, Any]]:
        ok_list: List[Dict[str, Any]] = []
        for s in self.raw.get('sources', []) or []:
            if isinstance(s, str):
                url = s
                sha = None
                dest = None
            else:
                url = s.get('url')
                sha = s.get('sha256') or s.get('checksum')
                dest = s.get('filename') or Path(url).name
            # locate file under cached sources directory
            cached = Path('.').resolve() / 'sources' / (Path(url).name)
            if not cached.exists():
                ok_list.append({'url': url, 'status': 'missing'})
                continue
            if sha:
                # compute hash
                h = hashlib.sha256()
                try:
                    with cached.open('rb') as fh:
                        for chunk in iter(lambda: fh.read(65536), b''):
                            h.update(chunk)
                    got = h.hexdigest()
                    ok = got.lower() == sha.lower()
                    ok_list.append({'url': url, 'status': 'ok' if ok else 'mismatch', 'sha_expected': sha, 'sha_got': got})
                except Exception as e:
                    ok_list.append({'url': url, 'status': 'error', 'error': str(e)})
            else:
                ok_list.append({'url': url, 'status': 'ok', 'note': 'no-checksum'})
        self._log('info', 'metafile.verify', f'Verified {len(ok_list)} sources', package=self.raw.get('name'))
        return ok_list

    # ---------------- patch application ----------------
    def apply_patches(self, workdir: Optional[str] = None, stop_on_error: bool = True) -> Dict[str, Any]:
        # workdir defaults to the source directory root
        workdir = workdir or str(Path('.').resolve())
        if not self.patcher or not hasattr(self.patcher, 'apply_all'):
            self._log('warning', 'metafile.patcher.missing', 'Patcher module not available; skipping patches')
            return {'applied': 0, 'total': 0}
        patches = self.raw.get('patches', []) or []
        # if patches are dicts with path, use that; otherwise look for patch files under patches/<pkg>
        patch_paths = []
        for p in patches:
            if isinstance(p, str):
                patch_paths.append(p)
            elif isinstance(p, dict):
                if 'path' in p:
                    patch_paths.append(p['path'])
                elif 'file' in p:
                    patch_paths.append(p['file'])
        # if no explicit patch list, let patcher discover
        if not patch_paths:
            res = self.patcher.apply_all(self.raw.get('name', 'pkg'), cwd=workdir, stop_on_error=stop_on_error)
            return res
        # otherwise apply each explicitly
        results = []
        applied = 0
        for pp in patch_paths:
            try:
                r = self.patcher.apply_patch(pp, cwd=workdir)
                results.append(r)
                if r.get('status') == 'ok':
                    applied += 1
            except Exception as e:
                results.append({'patch': pp, 'status': 'error', 'err': str(e)})
                if stop_on_error:
                    break
        summary = {'total': len(patch_paths), 'applied': applied, 'results': results}
        self._log('info', 'metafile.patches.done', f'Applied {applied}/{len(patch_paths)} patches', package=self.raw.get('name'))
        return summary

    # ---------------- hooks ----------------
    def run_hooks(self, hook_type: str, pkg_dir: Optional[str] = None) -> Dict[str, Any]:
        if not self.hooks or not hasattr(self.hooks, 'execute_safe'):
            self._log('warning', 'metafile.hooks.missing', f'Hook manager not available for {hook_type}')
            return {'total': 0, 'ok': 0, 'failed': 0}
        return self.hooks.execute_safe(hook_type, pkg_dir=pkg_dir)

    # ---------------- environment / prepare ----------------
    def prepare_environment(self, destdir: Optional[str] = None, builddir: Optional[str] = None) -> Dict[str, Any]:
        name = self.raw.get('name') or (self.path.name if self.path else 'pkg')
        destdir = destdir or str(Path('.').resolve() / 'destdir' / name)
        builddir = builddir or str(Path('.').resolve() / 'build' / name)
        Path(destdir).mkdir(parents=True, exist_ok=True)
        Path(builddir).mkdir(parents=True, exist_ok=True)
        # write env.json with expanded env
        env = dict(self.raw.get('env', {}) or {})
        env_out = {'env': env, 'phases': self.raw.get('phases', {})}
        envfile = Path(builddir) / 'env.json'
        try:
            envfile.write_text(json.dumps(env_out, indent=2), encoding='utf-8')
        except Exception:
            pass
        self._log('info', 'metafile.prepare', f'Prepared build env for {name}', builddir=builddir, destdir=destdir)
        return {'builddir': builddir, 'destdir': destdir, 'envfile': str(envfile)}

    # ---------------- DB export ----------------
    def export_to_db(self) -> bool:
        if not self.db:
            self._log('warning', 'metafile.db.missing', 'NewpkgDB not configured; skipping export')
            return False
        try:
            name = self.raw.get('name') or (self.path.name if self.path else 'pkg')
            version = self.raw.get('version')
            origin = self.raw.get('origin')
            pid = self.db.add_package(name, version=version, origin=origin, status='metafile')
            # add sources as deps? store in meta
            self.db.set_meta(f'metafile:{name}', self.raw)
            self._log('info', 'metafile.db.export', f'Exported {name} to DB', package=name, pid=pid)
            return True
        except Exception as e:
            self._log('error', 'metafile.db.fail', f'Failed to export to DB: {e}')
            return False

    # ---------------- manifest / summary ----------------
    def generate_manifest(self) -> Dict[str, Any]:
        manifest = {
            'name': self.raw.get('name'),
            'version': self.raw.get('version'),
            'sources': self.raw.get('sources', []),
            'patches': self.raw.get('patches', []),
            'env': self.raw.get('env', {}),
            'phases': self.raw.get('phases', {}),
            'generated_at': datetime.utcnow().isoformat() + 'Z'
        }
        # try to estimate sizes if sources available locally
        total_size = 0
        sizes = []
        for s in manifest['sources']:
            url = s if isinstance(s, str) else s.get('url')
            local = Path('sources') / Path(url).name
            if local.exists():
                try:
                    sz = local.stat().st_size
                    total_size += sz
                    sizes.append({'file': str(local), 'size': sz})
                except Exception:
                    continue
        manifest['size_total'] = total_size
        manifest['filesizes'] = sizes
        return manifest

    def summary(self) -> Dict[str, Any]:
        name = self.raw.get('name') or (self.path.name if self.path else 'pkg')
        manifest = self.generate_manifest()
        ok, errors = self.validate()
        return {
            'name': name,
            'valid': ok,
            'errors': errors,
            'manifest': manifest,
        }


# CLI convenience
if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(prog='newpkg-metafile')
    p.add_argument('cmd', choices=['load', 'merge', 'validate', 'resolve', 'verify', 'apply', 'prepare', 'export', 'summary'])
    p.add_argument('path', nargs='?', help='metafile path or package name')
    p.add_argument('--workdir', help='working dir / builddir')
    args = p.parse_args()

    cfg = None
    if init_config:
        try:
            cfg = init_config()
        except Exception:
            cfg = None

    db = NewpkgDB(cfg) if NewpkgDB and cfg is not None else None
    logger = NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None
    mf = Metafile(cfg=cfg, logger=logger, db=db)

    if args.cmd == 'load' and args.path:
        mf.load(args.path)
        print('loaded')
    elif args.cmd == 'merge' and args.path:
        mf.load(args.path)
        # expect second path via env NEWPKG_MERGE or ask
        other = os.environ.get('NEWPKG_MERGE')
        if other:
            mf.merge(other)
            print('merged')
        else:
            print('please set NEWPKG_MERGE env or use programmatically')
    elif args.cmd == 'validate':
        ok, errs = mf.validate()
        print('ok' if ok else 'failed', errs)
    elif args.cmd == 'resolve':
        mf.load(args.path)
        res = mf.resolve_sources()
        print(json.dumps(res, indent=2))
    elif args.cmd == 'verify':
        mf.load(args.path)
        res = mf.verify_sources()
        print(json.dumps(res, indent=2))
    elif args.cmd == 'apply':
        mf.load(args.path)
        res = mf.apply_patches(workdir=args.workdir)
        print(json.dumps(res, indent=2))
    elif args.cmd == 'prepare':
        mf.load(args.path)
        res = mf.prepare_environment()
        print(json.dumps(res, indent=2))
    elif args.cmd == 'export':
        mf.load(args.path)
        ok = mf.export_to_db()
        print('exported' if ok else 'failed')
    elif args.cmd == 'summary':
        if args.path:
            mf.load(args.path)
        print(json.dumps(mf.summary(), indent=2))
    else:
        p.print_help()
