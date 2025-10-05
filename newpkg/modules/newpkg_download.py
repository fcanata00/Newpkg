#!/usr/bin/env python3
"""
newpkg_download.py

Robust downloader for Newpkg with integrations:
 - Config keys: download.cache_dir, download.parallel, download.timeout, download.user_agent, download.format
 - Integrates with newpkg_config (init_config), newpkg_logger (NewpkgLogger), newpkg_db (record_phase)
 - Async downloading (aiohttp if available) with fallback to requests/curl/wget
 - download_many(tasks, parallel) where tasks = [{"url":..., "dest":..., "checksum":..., "mirrors": [...]}, ...]
 - download_sync wrapper
 - batch_download(pkg_name, sources) returns standardized results for core
 - clone_git, rsync (best-effort wrappers)
 - verify(path, checksum) and verify_gpg(path, sig)
 - extract_archive(path, dest)
 - cache management (clear_cache older than TTL)

This module is defensive: optional libs are handled gracefully and functions attempt best-effort fallbacks.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# optional libraries
try:
    import aiohttp
    _HAS_AIOHTTP = True
except Exception:
    aiohttp = None
    _HAS_AIOHTTP = False

try:
    import requests
    _HAS_REQUESTS = True
except Exception:
    requests = None
    _HAS_REQUESTS = False

# imports from our workspace (may be unavailable at import time)
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


DEFAULT_CACHE_TTL = 7 * 24 * 3600  # seconds
DEFAULT_PARALLEL = 4


class DownloadError(Exception):
    pass


class NewpkgDownloader:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None):
        self.cfg = cfg
        self.logger = logger or (NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None)
        self.db = db or (NewpkgDB(cfg) if NewpkgDB and cfg is not None else None)

        # configuration
        self.cache_dir = Path(self._cfg_get('download.cache_dir', os.environ.get('NEWPKG_DL_CACHE', '.cache/newpkg')))
        self.cache_ttl = int(self._cfg_get('download.cache_ttl', os.environ.get('NEWPKG_DL_CACHE_TTL', DEFAULT_CACHE_TTL)))
        self.parallel = int(self._cfg_get('download.parallel', os.environ.get('NEWPKG_DL_PARALLEL', DEFAULT_PARALLEL)))
        self.timeout = int(self._cfg_get('download.timeout', os.environ.get('NEWPKG_DL_TIMEOUT', 3600)))
        self.user_agent = self._cfg_get('download.user_agent', 'newpkg-downloader/1.0')

        # ensure cache dir exists
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, 'get'):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return default

    def _log(self, level: str, event: str, message: str = '', **meta):
        if self.logger:
            try:
                fn = getattr(self.logger, level.lower(), None)
                if fn:
                    fn(event, message, **meta)
                    return
            except Exception:
                pass
        # fallback
        print(f'[{level}] {event}: {message}', file=sys.stderr)

    # ---------------- verification helpers ----------------
    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with path.open('rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    def verify(self, path: str, checksum: Optional[str] = None) -> bool:
        p = Path(path)
        if not p.exists():
            return False
        if not checksum:
            return True
        try:
            got = self._sha256(p)
            return got.lower() == checksum.lower()
        except Exception:
            return False

    def verify_gpg(self, path: str, sig_path: str) -> bool:
        # best-effort: use gpg --verify
        try:
            gpg = shutil.which('gpg') or shutil.which('gpg2')
            if not gpg:
                return False
            proc = subprocess.run([gpg, '--verify', sig_path, path], capture_output=True)
            return proc.returncode == 0
        except Exception:
            return False

    # ---------------- extraction helper ----------------
    def extract_archive(self, archive: str, dest: Optional[str] = None) -> bool:
        p = Path(archive)
        d = Path(dest) if dest else p.parent / (p.stem + '-extracted')
        d.mkdir(parents=True, exist_ok=True)
        try:
            # try system tar for reliability
            if any(str(p.name).endswith(s) for s in ('.tar.gz', '.tgz', '.tar.xz', '.tar.bz2', '.tar')):
                cmd = ['tar', '-xf', str(p), '-C', str(d)]
                proc = subprocess.run(cmd, capture_output=True)
                return proc.returncode == 0
            if p.suffix == '.zip':
                import zipfile
                with zipfile.ZipFile(p) as z:
                    z.extractall(d)
                return True
            # fallback: try tarfile
            import tarfile
            with tarfile.open(p) as t:
                t.extractall(d)
            return True
        except Exception as e:
            self._log('error', 'download.extract_fail', f'Failed to extract {archive}: {e}', archive=str(archive))
            return False

    # ---------------- low level fetchers ----------------
    def _wget_fallback(self, url: str, dest: Path, timeout: int) -> Dict[str, Any]:
        # try aria2c, then wget, then curl
        for prog in ('aria2c', 'wget', 'curl'):
            exe = shutil.which(prog)
            if not exe:
                continue
            try:
                if prog == 'aria2c':
                    cmd = [exe, '-x', '4', '-s', '4', '-o', str(dest), url]
                elif prog == 'wget':
                    cmd = [exe, '-O', str(dest), url]
                else:  # curl
                    cmd = [exe, '-L', '-o', str(dest), url]
                proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
                return {'rc': proc.returncode, 'out': proc.stdout.decode(errors='ignore'), 'err': proc.stderr.decode(errors='ignore')}
            except Exception as e:
                continue
        return {'rc': 1, 'out': '', 'err': 'no-fallback'}

    async def _aio_fetch(self, session: 'aiohttp.ClientSession', url: str, dest: Path, timeout: int, headers: Dict[str, str]) -> Dict[str, Any]:
        start = time.time()
        try:
            async with session.get(url, timeout=timeout, headers=headers) as resp:
                if resp.status >= 400:
                    txt = await resp.text()
                    return {'rc': resp.status, 'out': '', 'err': f'HTTP {resp.status}: {txt[:200]}'}
                # stream to file
                with dest.open('wb') as fh:
                    async for chunk in resp.content.iter_chunked(65536):
                        fh.write(chunk)
            dur = time.time() - start
            return {'rc': 0, 'out': str(dest), 'err': '', 'duration': dur}
        except Exception as e:
            dur = time.time() - start
            return {'rc': 1, 'out': '', 'err': str(e), 'duration': dur}

    def _sync_fetch_requests(self, url: str, dest: Path, timeout: int, headers: Dict[str, str]) -> Dict[str, Any]:
        try:
            if _HAS_REQUESTS:
                r = requests.get(url, timeout=timeout, headers=headers, stream=True)
                if r.status_code >= 400:
                    return {'rc': r.status_code, 'out': '', 'err': f'HTTP {r.status_code}'}
                with dest.open('wb') as fh:
                    for chunk in r.iter_content(65536):
                        fh.write(chunk)
                return {'rc': 0, 'out': str(dest), 'err': ''}
        except Exception:
            pass
        # fallback to external programs
        return self._wget_fallback(url, dest, timeout)

    # ---------------- public download API ----------------
    async def download(self, url: str, dest: Optional[str] = None, checksum: Optional[str] = None, timeout: Optional[int] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Asynchronously download a single URL to dest. Returns dict with rc/out/err/duration."""
        timeout = int(timeout or self.timeout)
        headers = headers or {'User-Agent': self.user_agent}
        # dest resolution
        destp = Path(dest) if dest else self.cache_dir / Path(url).name
        destp.parent.mkdir(parents=True, exist_ok=True)

        # if file exists and checksum matches, skip
        if destp.exists() and checksum:
            try:
                if self.verify(str(destp), checksum):
                    self._log('info', 'download.skip', f'Using cached {destp}', url=url, dest=str(destp))
                    return {'rc': 0, 'out': str(destp), 'cached': True}
            except Exception:
                pass

        # prefer aiohttp path when available
        if _HAS_AIOHTTP:
            try:
                timeout_cfg = aiohttp.ClientTimeout(total=timeout)
                async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                    res = await self._aio_fetch(session, url, destp, timeout, headers)
            except Exception as e:
                res = {'rc': 1, 'out': '', 'err': str(e)}
        else:
            # run sync fetch in thread exec to avoid blocking
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(None, lambda: self._sync_fetch_requests(url, destp, timeout, headers))

        # verify checksum if provided
        if res.get('rc') == 0 and checksum:
            try:
                ok = self.verify(str(destp), checksum)
                if not ok:
                    self._log('warning', 'download.verify_fail', f'Checksum mismatch for {destp}', url=url)
                    # attempt fallback redownload via wget/curl
                    fb = self._wget_fallback(url, destp, timeout)
                    res = fb
            except Exception:
                pass

        # DB: record phase
        try:
            if self.db and hasattr(self.db, 'record_phase'):
                pkg = os.environ.get('NEWPKG_CURRENT_PKG') or None
                self.db.record_phase(pkg or Path(destp).stem, 'download', 'ok' if res.get('rc') == 0 else 'error', log_path=str(destp) if res.get('rc') == 0 else None)
        except Exception:
            pass

        # logging
        if res.get('rc') == 0:
            self._log('info', 'download.ok', f'Downloaded {url} -> {destp}', url=url, dest=str(destp), duration=res.get('duration'))
        else:
            self._log('error', 'download.fail', f'Failed to download {url}: {res.get("err")}', url=url, dest=str(destp))
        return res

    async def download_many(self, tasks: Iterable[Dict[str, Any]], parallel: Optional[int] = None) -> List[Dict[str, Any]]:
        """Download multiple tasks in parallel. Task format: {url, dest, checksum, mirrors}
        Returns list of results matching tasks order where each result contains rc/out/err.
        """
        parallel = int(parallel or self.parallel or DEFAULT_PARALLEL)
        tasks_list = list(tasks)
        sem = asyncio.Semaphore(parallel)

        async def _do_task(t):
            async with sem:
                url = t.get('url')
                dest = t.get('dest') or str(self.cache_dir / Path(url).name)
                checksum = t.get('checksum') or t.get('sha256')
                headers = t.get('headers') or None
                # try primary then mirrors
                urls = [url] + (t.get('mirrors') or [])
                last_res = None
                for u in urls:
                    res = await self.download(u, dest=dest, checksum=checksum, headers=headers)
                    last_res = res
                    if res.get('rc') == 0:
                        break
                return {'task': t, 'result': last_res}

        coros = [_do_task(t) for t in tasks_list]
        results = await asyncio.gather(*coros, return_exceptions=False)
        return results

    def download_sync(self, url: str, dest: Optional[str] = None, checksum: Optional[str] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        """Synchronous wrapper for download (runs the async download on event loop).
        Falls back to running in new event loop if none running.
        """
        try:
            loop = asyncio.get_running_loop()
            # if running loop, run in executor
            return asyncio.run(self.download(url, dest=dest, checksum=checksum, timeout=timeout))
        except RuntimeError:
            return asyncio.run(self.download(url, dest=dest, checksum=checksum, timeout=timeout))

    def batch_download(self, pkg_name: str, sources: List[Dict[str, Any]], parallel: Optional[int] = None) -> List[Dict[str, Any]]:
        """Convenience to download multiple sources (synchronous). Returns list of result dicts.
        Each source dict: {url, filename?, checksum, mirrors?}
        """
        tasks = []
        workdir = Path(self.cache_dir) / pkg_name
        workdir.mkdir(parents=True, exist_ok=True)
        for s in sources:
            url = s.get('url')
            fname = s.get('filename') or Path(url).name
            dest = str(workdir / fname)
            tasks.append({'url': url, 'dest': dest, 'checksum': s.get('sha256') or s.get('sha256sum'), 'mirrors': s.get('mirrors')})
        # run async batch
        res = asyncio.run(self.download_many(tasks, parallel=parallel))
        # normalize
        out = []
        for r in res:
            task = r.get('task')
            result = r.get('result')
            out.append({'url': task.get('url'), 'dest': task.get('dest'), 'rc': result.get('rc'), 'err': result.get('err'), 'out': result.get('out')})
        return out

    # ---------------- VCS / rsync helpers ----------------
    def clone_git(self, repo: str, dest: str, branch: Optional[str] = None, shallow: bool = True) -> Dict[str, Any]:
        """Clone a git repository (best-effort)."""
        destp = Path(dest)
        if destp.exists() and any(destp.iterdir()):
            return {'rc': 0, 'out': str(destp), 'err': 'exists'}
        cmd = ['git', 'clone']
        if shallow:
            cmd += ['--depth', '1']
        if branch:
            cmd += ['--branch', branch]
        cmd += [repo, str(destp)]
        try:
            proc = subprocess.run(cmd, capture_output=True)
            ok = proc.returncode == 0
            return {'rc': proc.returncode, 'out': proc.stdout.decode(errors='ignore'), 'err': proc.stderr.decode(errors='ignore')}
        except Exception as e:
            return {'rc': 1, 'out': '', 'err': str(e)}

    def rsync(self, source: str, dest: str, opts: Optional[List[str]] = None) -> Dict[str, Any]:
        r = shutil.which('rsync')
        if not r:
            return {'rc': 1, 'err': 'rsync not available'}
        cmd = [r] + (opts or ['-a', '--delete']) + [source, dest]
        try:
            proc = subprocess.run(cmd, capture_output=True)
            return {'rc': proc.returncode, 'out': proc.stdout.decode(errors='ignore'), 'err': proc.stderr.decode(errors='ignore')}
        except Exception as e:
            return {'rc': 1, 'out': '', 'err': str(e)}

    # ---------------- cache maintenance ----------------
    def clear_cache(self, older_than_days: Optional[int] = None) -> Dict[str, Any]:
        older_than_days = older_than_days if older_than_days is not None else max(1, int(self.cache_ttl // 86400))
        cutoff = datetime.utcnow() - timedelta(days=older_than_days)
        removed = 0
        size_removed = 0
        for p in self.cache_dir.rglob('*'):
            try:
                if p.is_file():
                    mtime = datetime.utcfromtimestamp(p.stat().st_mtime)
                    if mtime < cutoff:
                        size_removed += p.stat().st_size
                        p.unlink()
                        removed += 1
            except Exception:
                continue
        self._log('info', 'download.cache_clean', f'Removed {removed} files totalling {size_removed} bytes', removed=removed, size=size_removed)
        return {'removed': removed, 'size': size_removed}


# small CLI for testing
if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(prog='newpkg-download')
    p.add_argument('cmd', choices=['fetch', 'batch', 'clearcache', 'clone', 'rsync'])
    p.add_argument('target', nargs='?', help='URL, pkg name or repo')
    p.add_argument('--dest', help='destination path')
    p.add_argument('--checksum', help='expected sha256')
    p.add_argument('--parallel', type=int, help='parallel downloads')
    args = p.parse_args()

    cfg = None
    if init_config:
        try:
            cfg = init_config()
        except Exception:
            cfg = None
    db = NewpkgDB(cfg) if NewpkgDB and cfg is not None else None
    logger = NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None
    dl = NewpkgDownloader(cfg=cfg, logger=logger, db=db)

    if args.cmd == 'fetch' and args.target:
        res = dl.download_sync(args.target, dest=args.dest, checksum=args.checksum)
        print(json.dumps(res, indent=2, ensure_ascii=False))
    elif args.cmd == 'batch' and args.target:
        # expect JSON file describing sources
        srcf = Path(args.target)
        if srcf.exists():
            sources = json.loads(srcf.read_text(encoding='utf-8'))
        else:
            print('source file not found')
            sys.exit(2)
        out = dl.batch_download(srcf.stem, sources, parallel=args.parallel)
        print(json.dumps(out, indent=2, ensure_ascii=False))
    elif args.cmd == 'clearcache':
        out = dl.clear_cache()
        print(json.dumps(out, indent=2))
    elif args.cmd == 'clone' and args.target:
        out = dl.clone_git(args.target, args.dest or ('./' + Path(args.target).stem))
        print(json.dumps(out, indent=2))
    elif args.cmd == 'rsync' and args.target:
        out = dl.rsync(args.target, args.dest or './')
        print(json.dumps(out, indent=2))
    else:
        p.print_help()
