"""
newpkg_metafile.py

Gerencia metafiles (TOML/YAML) que descrevem pacotes para newpkg.
Suporta:
 - TOML (tomllib / tomli), YAML (PyYAML optional)
 - múltiplas sources (mirrors), múltiplos patches
 - checksum + optional GPG verify
 - environment expansion (${VAR})
 - merge of pass1 metafile with main metafile (e.g. gcc-13.2.0-pass1.toml)
 - integration hooks for newpkg_download, newpkg_patcher, newpkg_db, newpkg_hooks
 - generate_manifest -> JSON normalized output

The class is intentionally defensive (best-effort integration when helper modules are missing).

Example usage:
    mf = NewpkgMetaFile(cfg, logger=logger, db=db, downloader=dl, patcher=patcher)
    mf.load('packages/gcc/gcc-13.2.0-pass1.toml')
    mf.merge_metafile('packages/gcc/gcc-13.2.0.toml')
    mf.validate()
    mf.expand_env(extra_env={'LFS_TGT':'x86_64-lfs-linux-gnu'})
    mf.resolve_sources()
    mf.apply_patches()
    manifest = mf.generate_manifest()
    mf.export_to_db()

"""
from __future__ import annotations

import os
import re
import json
import shutil
import hashlib
import tempfile
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# toml loader
try:
    import tomllib as _toml
except Exception:
    try:
        import tomli as _toml  # type: ignore
    except Exception:
        _toml = None

# yaml optional
try:
    import yaml
    _HAS_YAML = True
except Exception:
    yaml = None
    _HAS_YAML = False

# gpg optional
try:
    import gnupg
    _HAS_GNUPG = True
except Exception:
    gnupg = None
    _HAS_GNUPG = False


class MetaFileError(Exception):
    pass


ENV_VAR_RE = re.compile(r"\$\{([^}]+)\}")


class NewpkgMetaFile:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, downloader: Any = None, patcher: Any = None, hooks: Any = None):
        self.cfg = cfg
        self.logger = logger
        self.db = db
        self.downloader = downloader
        self.patcher = patcher
        self.hooks = hooks

        # loaded data
        self.raw: Dict[str, Any] = {}
        self.meta: Dict[str, Any] = {}

        # resolved paths for downloaded sources/patches
        self._resolved_sources: List[Dict[str, Any]] = []
        self._resolved_patches: List[Dict[str, Any]] = []

        # config defaults
        try:
            self.search_paths = self.cfg.get('metafile.search_paths') or []
        except Exception:
            self.search_paths = []
        try:
            self.validate_hash = bool(self.cfg.get('metafile.validate_hash'))
        except Exception:
            self.validate_hash = True
        try:
            self.gpg_verify = bool(self.cfg.get('metafile.gpg_verify'))
        except Exception:
            self.gpg_verify = True
        try:
            self.apply_patches_by_default = bool(self.cfg.get('metafile.apply_patches'))
        except Exception:
            self.apply_patches_by_default = True
        try:
            self.safe_mode = bool(self.cfg.get('metafile.safe_mode'))
        except Exception:
            self.safe_mode = True

        # gpg
        self._gpg = gnupg.GPG() if _HAS_GNUPG else None

    # ---------------- logging ----------------
    def _log(self, event: str, level: str = 'INFO', message: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> None:
        if self.logger:
            try:
                self.logger.log_event(event, level=level, message=message or event, metadata=meta or {})
            except Exception:
                pass

    # ---------------- load ----------------
    def load(self, path: str) -> Dict[str, Any]:
        p = Path(path)
        if not p.exists():
            # try search paths
            for sp in self.search_paths:
                spath = Path(sp) / p
                if spath.exists():
                    p = spath
                    break
            else:
                raise MetaFileError(f'Metafile not found: {path}')

        text = p.read_bytes()
        data: Dict[str, Any] = {}
        if p.suffix in ('.toml', '.tml') and _toml is not None:
            try:
                data = _toml.loads(text.decode('utf-8'))
            except Exception as e:
                raise MetaFileError(f'Failed to parse TOML: {e}')
        elif p.suffix in ('.yaml', '.yml') and _HAS_YAML:
            try:
                data = yaml.safe_load(text)
            except Exception as e:
                raise MetaFileError(f'Failed to parse YAML: {e}')
        elif p.suffix == '.json':
            try:
                data = json.loads(text.decode('utf-8'))
            except Exception as e:
                raise MetaFileError(f'Failed to parse JSON: {e}')
        else:
            # try toml fallback
            if _toml is not None:
                try:
                    data = _toml.loads(text.decode('utf-8'))
                except Exception:
                    raise MetaFileError('Unsupported metafile format or missing parser')
            else:
                raise MetaFileError('No TOML/YAML parser available')

        # normalize keys to lower-case top-level
        data = {k: v for k, v in data.items()}
        self.raw = data
        self.meta = self._normalize(data)
        self._log('metafile.load', level='INFO', message=f'Loaded metafile {p}', meta={'path': str(p)})
        return self.meta

    def _normalize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # create a normalized meta structure with defaults
        m: Dict[str, Any] = {}
        m['name'] = data.get('name') or data.get('pkg') or data.get('package')
        m['version'] = data.get('version')
        m['release'] = data.get('release')
        m['description'] = data.get('description')

        # sources: allow list of strings or list of dicts
        sources_raw = data.get('sources') or data.get('source') or []
        sources: List[Dict[str, Any]] = []
        if isinstance(sources_raw, (list, tuple)):
            for s in sources_raw:
                if isinstance(s, str):
                    sources.append({'url': s})
                elif isinstance(s, dict):
                    sources.append(dict(s))
        elif isinstance(sources_raw, str):
            sources.append({'url': sources_raw})
        m['sources'] = sources

        # patches
        patches_raw = data.get('patches') or []
        patches: List[Dict[str, Any]] = []
        if isinstance(patches_raw, (list, tuple)):
            for p in patches_raw:
                if isinstance(p, str):
                    patches.append({'url': p, 'apply': True})
                elif isinstance(p, dict):
                    patches.append(dict(p))
        m['patches'] = patches

        # dependencies
        deps = data.get('dependencies') or data.get('depends') or {}
        m['dependencies'] = deps

        # env
        env = data.get('env') or {}
        m['env'] = env

        # checks
        checks = data.get('checks') or data.get('verify') or {}
        m['checks'] = checks

        # phases
        phases = data.get('phases') or {}
        m['phases'] = phases

        # meta: source metadata like type, mirrors
        m['meta'] = data.get('meta') or {}

        # file origin for reference
        return m

    # ---------------- merge pass1 with main metafile ----------------
    def merge_metafile(self, other_path: str) -> Dict[str, Any]:
        """Merge another metafile into the currently loaded one. Values from other override when appropriate.

        Use case: load gcc-13.2.0-pass1.toml then merge gcc-13.2.0.toml to compose full build.
        """
        other = NewpkgMetaFile(self.cfg, logger=self.logger, db=self.db, downloader=self.downloader, patcher=self.patcher, hooks=self.hooks)
        other.load(other_path)
        # merge simple strategy: combine sources/patches and override top-level keys when present in other
        merged = dict(self.meta)
        for k in ('sources', 'patches'):
            merged[k] = list({json.dumps(x, sort_keys=True): x for x in (merged.get(k, []) + other.meta.get(k, []))}.values())
        # override fields
        for key in ('name', 'version', 'release', 'description', 'env', 'phases', 'dependencies', 'checks'):
            if other.meta.get(key) is not None:
                if isinstance(merged.get(key), dict) and isinstance(other.meta.get(key), dict):
                    # merge dicts
                    merged[key] = dict(merged.get(key) or {})
                    merged[key].update(other.meta.get(key) or {})
                else:
                    merged[key] = other.meta.get(key)
        self.meta = merged
        self._log('metafile.merge', level='INFO', message=f'Merged metafile {other_path}', meta={'merged_keys': list(merged.keys())})
        return self.meta

    # ---------------- validation ----------------
    def validate(self) -> Tuple[bool, List[str]]:
        errs: List[str] = []
        if not self.meta.get('name'):
            errs.append('missing name')
        if not self.meta.get('version'):
            errs.append('missing version')
        if not self.meta.get('sources'):
            errs.append('no sources defined')
        # check source urls
        for s in self.meta.get('sources', []):
            if 'url' not in s:
                errs.append(f'source missing url: {s}')
        # patches sanity
        for p in self.meta.get('patches', []):
            if 'url' not in p and 'file' not in p:
                errs.append(f'patch missing url/file: {p}')
        # phases allowed
        if self.safe_mode:
            for name, cmd in (self.meta.get('phases') or {}).items():
                if isinstance(cmd, str) and any(tok in cmd for tok in ('&&', ';', '|', '>', '<')):
                    errs.append(f'unsafe token in phase {name}')
        ok = not errs
        self._log('metafile.validate', level='INFO' if ok else 'ERROR', message='Validated metafile', meta={'ok': ok, 'errors': errs})
        return ok, errs

    # ---------------- env expansion ----------------
    def expand_env(self, extra_env: Optional[Dict[str, str]] = None) -> None:
        env = dict(os.environ)
        env.update(self.meta.get('env') or {})
        if extra_env:
            env.update(extra_env)
        # perform ${VAR} substitution in phases, env values
        def _expand_text(s: str) -> str:
            def repl(m):
                key = m.group(1)
                return env.get(key, '')
            return ENV_VAR_RE.sub(repl, s)

        # expand env values
        newenv = {}
        for k, v in (self.meta.get('env') or {}).items():
            if isinstance(v, str):
                newenv[k] = _expand_text(v)
            else:
                newenv[k] = v
        self.meta['env'] = newenv

        # expand phases
        phases = {}
        for name, cmd in (self.meta.get('phases') or {}).items():
            if isinstance(cmd, str):
                phases[name] = _expand_text(cmd)
            else:
                phases[name] = cmd
        self.meta['phases'] = phases
        self._log('metafile.expand', level='INFO', message='Expanded environment variables', meta={'env_keys': list(newenv.keys())})

    # ---------------- resolve sources (download) ----------------
    def resolve_sources(self, download_dir: Optional[str] = None, parallel: int = 4, resume: bool = True) -> List[Dict[str, Any]]:
        if not self.downloader:
            raise MetaFileError('downloader not configured')
        dd = Path(download_dir) if download_dir else Path(tempfile.mkdtemp(prefix=f'newpkg-src-{self.meta.get("name")}-'))
        dd.mkdir(parents=True, exist_ok=True)
        tasks: List[Dict[str, Any]] = []
        for src in self.meta.get('sources', []):
            url = src.get('url')
            filename = src.get('filename') or Path(url).name
            dest = dd / filename
            task = {'url': url, 'dest': str(dest), 'checksum': src.get('sha256') or src.get('sha1') or src.get('md5'), 'checksum_type': 'sha256' if src.get('sha256') else ('sha1' if src.get('sha1') else ('md5' if src.get('md5') else None)), 'mirrors': src.get('mirrors'), 'resume': resume}
            tasks.append(task)
        # run downloader.download_many
        import asyncio
        coro = self.downloader.download_many(tasks, parallel=parallel)
        try:
            results = asyncio.run(coro)
        except Exception as e:
            raise MetaFileError(f'download failed: {e}')
        resolved = []
        for i, r in enumerate(results):
            entry = dict(self.meta.get('sources')[i])
            entry['download'] = r
            resolved.append(entry)
        self._resolved_sources = resolved
        self._log('metafile.resolve_sources', level='INFO', message=f'Downloaded sources to {str(dd)}', meta={'count': len(resolved), 'dir': str(dd)})
        return resolved

    # ---------------- apply patches ----------------
    def apply_patches(self, workdir: Optional[str] = None, strip: int = 1) -> List[Dict[str, Any]]:
        if not self.patcher:
            raise MetaFileError('patcher not configured')
        wd = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix=f'newpkg-patch-{self.meta.get("name")}-'))
        wd.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []
        for p in self.meta.get('patches', []):
            # patch may be local file or URL
            if 'file' in p:
                src = Path(p.get('file'))
                if not src.exists():
                    results.append({'patch': str(src), 'status': 'missing'})
                    continue
                res = self.patcher.apply_patch(str(src), cwd=str(wd), strip=strip)
                results.append({'patch': str(src), 'result': res})
            else:
                url = p.get('url')
                filename = Path(url).name
                dest = wd / filename
                # download patch using downloader if available
                if self.downloader:
                    import asyncio
                    coro = self.downloader.download([url], dest)
                    try:
                        dres = asyncio.run(coro)
                    except Exception as e:
                        results.append({'patch': url, 'status': 'download-fail', 'error': str(e)})
                        continue
                    if dres.get('status') != 'ok':
                        results.append({'patch': url, 'status': 'download-fail', 'error': dres})
                        continue
                    res = self.patcher.apply_patch(str(dest), cwd=str(wd), strip=strip)
                    results.append({'patch': url, 'result': res})
                else:
                    results.append({'patch': url, 'status': 'no-downloader'})
        self._resolved_patches = results
        self._log('metafile.apply_patches', level='INFO', message='Applied patches', meta={'count': len(results)})
        return results

    # ---------------- checks: checksum + gpg ----------------
    def _check_file_checksum(self, path: Path, checksum: str, ctype: str = 'sha256') -> bool:
        if not path.exists():
            return False
        try:
            h = getattr(__import__('hashlib'), ctype)()
        except Exception:
            # fallback mapping
            if ctype == 'sha256':
                h = __import__('hashlib').sha256()
            elif ctype == 'sha1':
                h = __import__('hashlib').sha1()
            else:
                h = __import__('hashlib').md5()
        with path.open('rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        return h.hexdigest().lower() == checksum.lower().replace('0x', '')

    def verify_sources(self) -> List[Dict[str, Any]]:
        results = []
        for src in self._resolved_sources:
            d = src.get('download') or {}
            path = Path(d.get('path')) if d.get('path') else None
            ok = True
            reason = None
            if self.validate_hash and path and src.get('sha256'):
                ok = self._check_file_checksum(path, src.get('sha256'), 'sha256')
                if not ok:
                    reason = 'checksum-mismatch'
            # optional GPG
            if ok and self.gpg_verify and src.get('gpg_sig') and _HAS_GNUPG:
                try:
                    sig = Path(src.get('gpg_sig'))
                    res = self._gpg.verify_file(sig.open('rb'), str(path))
                    ok = bool(getattr(res, 'valid', False))
                    if not ok:
                        reason = 'gpg-fail'
                except Exception:
                    ok = False
                    reason = 'gpg-exception'
            results.append({'source': src, 'ok': ok, 'reason': reason})
        self._log('metafile.verify_sources', level='INFO', message='Verified sources', meta={'results': len(results)})
        return results

    # ---------------- generate manifest ----------------
    def generate_manifest(self) -> Dict[str, Any]:
        manifest: Dict[str, Any] = {}
        manifest['name'] = self.meta.get('name')
        manifest['version'] = self.meta.get('version')
        manifest['release'] = self.meta.get('release')
        manifest['description'] = self.meta.get('description')
        manifest['env'] = self.meta.get('env')
        manifest['phases'] = self.meta.get('phases')
        manifest['dependencies'] = self.meta.get('dependencies')
        manifest['sources'] = []
        for s in self._resolved_sources:
            entry = dict(s)
            # compute size and sha256 if available
            d = entry.get('download') or {}
            path = Path(d.get('path')) if d.get('path') else None
            if path and path.exists():
                entry['size'] = path.stat().st_size
                entry['sha256_computed'] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest['sources'].append(entry)
        manifest['patches'] = self._resolved_patches
        manifest['generated_at'] = datetime.utcnow().isoformat() + 'Z'
        self._log('metafile.manifest', level='INFO', message='Generated manifest', meta={'name': manifest.get('name')})
        return manifest

    # ---------------- export to DB ----------------
    def export_to_db(self) -> bool:
        if not self.db:
            return False
        try:
            manifest = self.generate_manifest()
            if hasattr(self.db, 'store_manifest'):
                self.db.store_manifest(manifest)
            elif hasattr(self.db, 'add_package'):
                # best-effort add package metadata
                try:
                    self.db.add_package(manifest.get('name'), manifest.get('version'), 1, origin='metafile', status='staged')
                except Exception:
                    pass
            self._log('metafile.export', level='INFO', message='Exported manifest to DB', meta={'name': manifest.get('name')})
            return True
        except Exception as e:
            self._log('metafile.export.fail', level='ERROR', message=str(e), meta={})
            return False

    # ---------------- prepare environment for build ----------------
    def prepare_environment(self, base_dir: Optional[str] = None) -> Dict[str, Any]:
        work = Path(base_dir) if base_dir else Path(tempfile.mkdtemp(prefix=f'newpkg-work-{self.meta.get("name")}-'))
        env = dict(os.environ)
        env.update(self.meta.get('env') or {})
        # ensure common dirs
        (work / 'build').mkdir(parents=True, exist_ok=True)
        (work / 'destdir').mkdir(parents=True, exist_ok=True)
        # write an env file for reference
        (work / 'env.json').write_text(json.dumps(env, indent=2), encoding='utf-8')
        self._log('metafile.prepare', level='INFO', message='Prepared build environment', meta={'workdir': str(work)})
        return {'workdir': str(work), 'env': env}

    # ---------------- list phases and summary ----------------
    def list_phases(self) -> List[str]:
        return list((self.meta.get('phases') or {}).keys())

    def summary(self) -> Dict[str, Any]:
        return {
            'name': self.meta.get('name'),
            'version': self.meta.get('version'),
            'release': self.meta.get('release'),
            'sources': [s.get('url') for s in (self.meta.get('sources') or [])],
            'patches': [p.get('url') or p.get('file') for p in (self.meta.get('patches') or [])],
            'phases': self.list_phases(),
        }


# EOF
