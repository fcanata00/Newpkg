#!/usr/bin/env python3
# newpkg_download.py
"""
newpkg_download.py — robust downloader for newpkg

Features:
 - Reads settings from newpkg_config (downloads.*), supports profiles
 - Async downloads via aiohttp when available, fallback to requests/curl/wget/aria2c
 - download_sync() and download_async() interfaces
 - clone_git() with shallow/depth/submodule options and profile-aware config
 - extract_archive() with path traversal protection
 - respects cfg.get('general.dry_run'), cfg.get('output.quiet'), cfg.get('output.json')
 - propagates cfg.as_env() into subprocess calls
 - integrates with newpkg_logger and newpkg_db if available
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# optional project imports
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

# optional third-party libs
try:
    import aiohttp  # type: ignore
    _HAS_AIOHTTP = True
except Exception:
    aiohttp = None
    _HAS_AIOHTTP = False

try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except Exception:
    requests = None
    _HAS_REQUESTS = False

# module logger (fallback to std logging)
_logger = logging.getLogger("newpkg.download")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.download: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)

# dataclasses
@dataclass
class DownloadResult:
    url: str
    dest: str
    ok: bool
    sha256: Optional[str] = None
    used_mirror: Optional[str] = None
    error: Optional[str] = None
    dry_run: bool = False

# helper functions
def _sha256_of_path(p: Union[str, Path]) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_extract_tar(tar_path: Union[str, Path], dest: Union[str, Path]) -> None:
    """
    Extract tar file but prevent path traversal (no member escaping dest).
    Supports gz/xz/bz2 as handled by tarfile.
    """
    dest = Path(dest).resolve()
    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            member_path = dest.joinpath(member.name).resolve()
            if not str(member_path).startswith(str(dest)):
                raise RuntimeError(f"Unsafe path in tar archive: {member.name}")
        tf.extractall(path=str(dest))

# Main class
class NewpkgDownloader:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None):
        # load config
        self.cfg = cfg or (init_config() if init_config else None)
        # prefer project's logger if given
        if logger:
            self.logger = logger
        else:
            if NewpkgLogger and self.cfg is not None:
                try:
                    self.logger = NewpkgLogger.from_config(self.cfg, db)
                except Exception:
                    self.logger = None
            else:
                self.logger = None
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg is not None else None)

        # profile handling
        self.profiles: Dict[str, Any] = {}
        if self.cfg:
            self.profiles = self.cfg.get("downloads.profiles") or {}
        # default settings
        self.cache_dir = Path(self._cfg_get("downloads.cache_dir", "/var/cache/newpkg")).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.parallel = int(self._cfg_get("downloads.parallel_downloads", 4))
        self.timeout = int(self._cfg_get("downloads.timeout", 300))
        self.verify_checksums = bool(self._cfg_get("downloads.verify_checksums", True))
        self.gpg_verify = bool(self._cfg_get("downloads.gpg_verify", True))
        self.mirrors = list(self._cfg_get("downloads.mirrors", []) or [])
        self.metafile_repos = list(self._cfg_get("downloads.metafile_repos", []) or [])
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        # external command preferences
        self._curl_cmd = shutil.which("curl") or shutil.which("http")
        self._wget_cmd = shutil.which("wget")
        self._aria2c_cmd = shutil.which("aria2c")

        # attach small logger wrapper
        self._log = self._make_logger()

    def _make_logger(self):
        # unify logging: prefer self.logger, fallback to module logger
        def _fn(level: str, event: str, msg: str = "", **meta):
            try:
                if self.logger:
                    fn = getattr(self.logger, level.lower(), None)
                    if fn:
                        fn(event, msg, **meta)
                        return
            except Exception:
                pass
            # fallback
            getattr(_logger, level.lower(), _logger.info)(f"{event}: {msg} - {meta}")
        return _fn

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return default

    def apply_profile(self, profile: Optional[str] = None) -> Dict[str, Any]:
        """
        Return combined settings for a given downloads profile (merges with global).
        """
        base = {
            "mirrors": list(self.mirrors),
            "timeout": self.timeout,
            "verify_checksums": self.verify_checksums,
            "gpg_verify": self.gpg_verify,
        }
        if profile:
            pconf = self.profiles.get(profile) or {}
            # merge arrays and keys
            if "mirrors" in pconf:
                base["mirrors"] = list(pconf.get("mirrors", [])) + base["mirrors"]
            for k, v in pconf.items():
                if k != "mirrors":
                    base[k] = v
        return base

    # ----------------- download APIs -----------------
    def download_sync(self, url: str, dest: Optional[Union[str, Path]] = None,
                      sha256: Optional[str] = None, profile: Optional[str] = None) -> DownloadResult:
        """
        Synchronous download wrapper. Respects dry-run. Tries async path if aiohttp available.
        Returns DownloadResult.
        """
        if self.dry_run:
            self._log("info", "download.dryrun", f"Would download {url} -> {dest}", url=url, dest=str(dest))
            return DownloadResult(url=url, dest=str(dest or ""), ok=True, sha256=None, dry_run=True)

        # if aiohttp is available and we are not inside an active event loop, run async
        try:
            loop = asyncio.get_running_loop()
            in_running = True
        except RuntimeError:
            in_running = False

        if _HAS_AIOHTTP and not in_running:
            return asyncio.run(self.download_async(url, dest=dest, sha256=sha256, profile=profile))

        # fallback synchronous implementation using requests or curl/wget
        dest = Path(dest) if dest else self.cache_dir / Path(url).name
        dest.parent.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, **(self.cfg.as_env() if self.cfg else {})}

        # try requests
        if _HAS_REQUESTS:
            try:
                with requests.get(url, stream=True, timeout=self.timeout) as r:
                    r.raise_for_status()
                    with open(dest, "wb") as fh:
                        for chunk in r.iter_content(chunk_size=1 << 20):
                            if not chunk:
                                continue
                            fh.write(chunk)
                if sha256:
                    got = _sha256_of_path(dest)
                    if got != sha256:
                        raise RuntimeError(f"checksum mismatch for {url}: expected {sha256} got {got}")
                self._log("info", "download.ok", f"Downloaded {url} -> {dest}", url=url, dest=str(dest))
                # register to db if available
                if self.db and hasattr(self.db, "record_download"):
                    try:
                        self.db.record_download(url=str(url), dest=str(dest), checksum=sha256)
                    except Exception:
                        pass
                return DownloadResult(url=url, dest=str(dest), ok=True, sha256=sha256, used_mirror=None)
            except Exception as e:
                self._log("warning", "download.requests_fail", f"requests download failed for {url}: {e}", error=str(e))

        # try aria2c
        if self._aria2c_cmd:
            cmd = [self._aria2c_cmd, "-x", "4", "-s", "4", "-o", str(dest), url]
            return self._spawn_cmd_download(cmd, url, dest, sha256, env)

        # try curl
        if self._curl_cmd:
            cmd = [self._curl_cmd, "-L", "-o", str(dest), url]
            return self._spawn_cmd_download(cmd, url, dest, sha256, env)

        # try wget
        if self._wget_cmd:
            cmd = [self._wget_cmd, "-O", str(dest), url]
            return self._spawn_cmd_download(cmd, url, dest, sha256, env)

        raise RuntimeError("No download method available (aiohttp/requests/curl/wget/aria2c)")

    async def download_async(self, url: str, dest: Optional[Union[str, Path]] = None,
                             sha256: Optional[str] = None, profile: Optional[str] = None) -> DownloadResult:
        """
        Async download using aiohttp. Returns DownloadResult.
        """
        if self.dry_run:
            self._log("info", "download.dryrun", f"Would download {url} -> {dest}", url=url, dest=str(dest))
            return DownloadResult(url=url, dest=str(dest or ""), ok=True, dry_run=True)

        dest = Path(dest) if dest else self.cache_dir / Path(url).name
        dest.parent.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, **(self.cfg.as_env() if self.cfg else {})}
        profile_conf = self.apply_profile(profile)
        timeout = int(profile_conf.get("timeout", self.timeout))

        if not _HAS_AIOHTTP:
            # fallback to sync
            return self.download_sync(url, dest=dest, sha256=sha256, profile=profile)

        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            headers = {"User-Agent": f"newpkg-downloader/1.0"}
            async with aiohttp.ClientSession(timeout=timeout_obj) as sess:
                async with sess.get(url, headers=headers) as resp:
                    resp.raise_for_status()
                    with open(dest, "wb") as fh:
                        async for chunk in resp.content.iter_chunked(1 << 20):
                            fh.write(chunk)
            if sha256:
                got = _sha256_of_path(dest)
                if got != sha256:
                    raise RuntimeError(f"checksum mismatch for {url}: expected {sha256} got {got}")
            self._log("info", "download.ok", f"Downloaded {url} -> {dest}", url=url, dest=str(dest))
            if self.db and hasattr(self.db, "record_download"):
                try:
                    self.db.record_download(url=str(url), dest=str(dest), checksum=sha256)
                except Exception:
                    pass
            return DownloadResult(url=url, dest=str(dest), ok=True, sha256=sha256, used_mirror=None)
        except Exception as e:
            self._log("error", "download.fail", f"Async download failed for {url}: {e}", error=str(e))
            return DownloadResult(url=url, dest=str(dest), ok=False, sha256=sha256, error=str(e))

    def _spawn_cmd_download(self, cmd: List[str], url: str, dest: Union[str, Path], sha256: Optional[str], env: Dict[str, str]) -> DownloadResult:
        """
        Run external downloader command and perform checksum verification.
        """
        try:
            self._log("info", "download.cmd", f"Running {' '.join(cmd)}")
            proc = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
            if proc.returncode != 0:
                self._log("warning", "download.cmd_fail", f"cmd failed: {proc.stderr.strip()}")
                return DownloadResult(url=url, dest=str(dest), ok=False, error=proc.stderr.strip())
            if sha256:
                got = _sha256_of_path(dest)
                if got != sha256:
                    raise RuntimeError(f"checksum mismatch for {url}: expected {sha256} got {got}")
            self._log("info", "download.ok", f"Downloaded {url} -> {dest}")
            if self.db and hasattr(self.db, "record_download"):
                try:
                    self.db.record_download(url=str(url), dest=str(dest), checksum=sha256)
                except Exception:
                    pass
            return DownloadResult(url=url, dest=str(dest), ok=True, sha256=sha256)
        except Exception as e:
            return DownloadResult(url=url, dest=str(dest), ok=False, error=str(e))

    # ----------------- archive helpers -----------------
    def extract_archive(self, archive_path: Union[str, Path], dest: Union[str, Path], strip_components: int = 0) -> Tuple[bool, Optional[str]]:
        """
        Extract an archive (tar.*). Protects against path traversal.
        strip_components not fully implemented for all tar flavors; covered minimally.
        """
        archive_path = Path(archive_path)
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        try:
            # safe extract
            _safe_extract_tar(archive_path, dest)
            # simple strip-components emulation: move contents if top-level folder exists
            if strip_components > 0:
                # attempt to flatten a single top dir (best-effort)
                entries = list(dest.iterdir())
                if len(entries) == 1 and entries[0].is_dir():
                    top = entries[0]
                    for item in top.iterdir():
                        shutil.move(str(item), str(dest))
                    shutil.rmtree(str(top))
            self._log("info", "extract.ok", f"Extracted {archive_path} -> {dest}")
            return True, None
        except Exception as e:
            self._log("error", "extract.fail", f"Extraction failed for {archive_path}: {e}", error=str(e))
            return False, str(e)

    # ----------------- git helpers -----------------
    def clone_git(self, repo: str, dest: Union[str, Path], branch: Optional[str] = None,
                  tag: Optional[str] = None, commit: Optional[str] = None, depth: Optional[int] = 1,
                  submodules: bool = False, profile: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Clone a git repository into dest. Respects cfg.as_env() environment and profiles.
        Returns (ok, error).
        """
        dest = Path(dest)
        if self.dry_run:
            self._log("info", "git.dryrun", f"Would clone {repo} -> {dest}")
            return True, None

        dest.parent.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, **(self.cfg.as_env() if self.cfg else {})}
        profile_conf = self.apply_profile(profile)
        git_cmd = shutil.which("git") or "git"

        cmd = [git_cmd, "clone"]
        if depth:
            cmd += ["--depth", str(depth)]
        if branch:
            cmd += ["--branch", branch]
        if tag and not branch:
            # tags can be treated as checkout after clone
            pass
        cmd += [repo, str(dest)]
        try:
            proc = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
            if proc.returncode != 0:
                self._log("error", "git.clone_fail", f"git clone failed: {proc.stderr.strip()}")
                return False, proc.stderr.strip()
            # optionally checkout commit or tag
            if commit or tag:
                try:
                    ref = commit or tag
                    proc2 = subprocess.run([git_cmd, "checkout", ref], cwd=str(dest), env=env, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if proc2.returncode != 0:
                        self._log("warning", "git.checkout_fail", f"checkout {ref} failed: {proc2.stderr.strip()}")
                except Exception:
                    pass
            if submodules:
                subprocess.run([git_cmd, "submodule", "update", "--init", "--recursive"], cwd=str(dest), env=env)
            self._log("info", "git.clone.ok", f"Cloned {repo} -> {dest}")
            return True, None
        except Exception as e:
            return False, str(e)

    # ----------------- cache -----------------
    def clear_cache(self, older_than_seconds: Optional[int] = None) -> Dict[str, Any]:
        """
        Clear cached files in cache_dir optionally older than given seconds.
        """
        removed = []
        now = None
        if older_than_seconds:
            now = int(os.path.getmtime(self.cache_dir))
        for p in self.cache_dir.iterdir():
            try:
                if older_than_seconds:
                    mtime = int(p.stat().st_mtime)
                    if (int(now) - mtime) > older_than_seconds:
                        if p.is_file():
                            p.unlink()
                            removed.append(str(p))
                        else:
                            shutil.rmtree(p)
                            removed.append(str(p))
                else:
                    if p.is_file():
                        p.unlink()
                        removed.append(str(p))
                    else:
                        shutil.rmtree(p)
                        removed.append(str(p))
            except Exception:
                continue
        self._log("info", "cache.clear", f"Cleared {len(removed)} items from cache")
        return {"removed": removed}

    # ----------------- helpers -----------------
    def _resolve_mirrors(self, url: str, profile_conf: Dict[str, Any]) -> List[str]:
        """
        Given a base URL, try to produce mirror candidates using profile.conf mirrors.
        """
        mirrors = profile_conf.get("mirrors", []) or []
        out = [url]
        for m in mirrors:
            # simple join: replace host with mirror host if path structure identical
            try:
                p = Path(url)
                # naive: mirror + path name
                out.append(str(Path(m) / p.name))
            except Exception:
                continue
        return out

    # ----------------- convenience CLI-ish runner -----------------
    def download_many(self, urls: Iterable[Union[str, Tuple[str, Optional[str]]]], destdir: Union[str, Path],
                      profile: Optional[str] = None) -> List[DownloadResult]:
        """
        Download multiple urls. urls can be list of strings or (url, sha256) tuples.
        """
        destdir = Path(destdir)
        destdir.mkdir(parents=True, exist_ok=True)
        profile_conf = self.apply_profile(profile)
        results: List[DownloadResult] = []

        # run sequentially for simplicity; parallelism could be added
        for item in urls:
            if isinstance(item, (list, tuple)):
                url, sha = item[0], item[1]
            else:
                url, sha = item, None
            # try mirrors sequence
            tried = False
            for candidate in self._resolve_mirrors(url, profile_conf):
                tried = True
                res = self.download_sync(candidate, dest=destdir / Path(candidate).name, sha256=sha, profile=profile)
                if res.ok:
                    res.used_mirror = candidate if candidate != url else None
                    results.append(res)
                    break
                else:
                    results.append(res)
            if not tried:
                results.append(DownloadResult(url=url, dest=str(destdir), ok=False, error="no-mirrors"))
        return results

# ----------------- convenience top-level functions -----------------
_default_downloader: Optional[NewpkgDownloader] = None

def get_downloader(cfg: Any = None, logger: Any = None, db: Any = None) -> NewpkgDownloader:
    global _default_downloader
    if _default_downloader is None:
        _default_downloader = NewpkgDownloader(cfg=cfg, logger=logger, db=db)
    return _default_downloader

# CLI/demo when run directly
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(prog="newpkg-download", description="Downloader for newpkg (demo)")
    p.add_argument("url", nargs="?", help="URL to download")
    p.add_argument("--dest", help="destination path")
    p.add_argument("--profile", help="download profile")
    p.add_argument("--clear-cache", action="store_true")
    args = p.parse_args()

    cfg = init_config() if init_config else None
    dl = NewpkgDownloader(cfg=cfg)
    if args.clear_cache:
        print(dl.clear_cache())
    elif args.url:
        r = dl.download_sync(args.url, dest=args.dest)
        print(json.dumps(r.__dict__, indent=2))
    else:
        p.print_help()
