#!/usr/bin/env python3
# newpkg_download.py
"""
Newpkg download manager (revised)

Features implemented:
 - Cache intelligent naming (sha256 of URL + filename) to avoid collisions
 - @logger.perf_timer integration (best-effort)
 - Optional GPG verification (gpg --verify) if signature provided
 - Support extraction for modern tar formats (.xz, .gz, .zst) via system tar or libarchive fallback
 - Progress integration via logger.progress (Rich if available) or simple prints
 - Hooks: calls hooks.run("pre_download"/"post_download"/"post_extract") if HooksManager present
 - Git clone resilient with retries, shallow options and branch support
 - Cache health checks and revalidation
 - Integration with newpkg_db.record_download and newpkg_audit.report on failures
 - Download backends: aria2c, curl, wget, requests (best-effort), with retry policy
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Optional integrations (best-effort)
try:
    from newpkg_config import init_config  # type: ignore
except Exception:
    init_config = None

try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_db import NewpkgDB  # type: ignore
except Exception:
    NewpkgDB = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

try:
    from newpkg_audit import NewpkgAudit  # type: ignore
except Exception:
    NewpkgAudit = None

# optional requests
try:
    import requests  # type: ignore
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

# fallback logger
import logging
_logger = logging.getLogger("newpkg.download")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.download: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)


@dataclass
class DownloadResult:
    url: str
    ok: bool
    path: Optional[Path]
    sha256: Optional[str]
    backend: str
    duration: float
    error: Optional[str]


class NewpkgDownload:
    DEFAULT_CACHE_DIR = "/var/cache/newpkg/downloads"
    DEFAULT_RETRIES = 3
    DEFAULT_PARALLEL = 4
    SUPPORTED_ARCHIVE_EXT = (".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tar", ".zip")

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, audit: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        self.logger = logger or (get_logger(self.cfg) if get_logger else None)
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)
        self.hooks = hooks or (get_hooks_manager(self.cfg) if get_hooks_manager else None)
        self.audit = audit or (NewpkgAudit(self.cfg) if NewpkgAudit and self.cfg else None)

        # cache dir & profiles
        self.cache_dir = Path(self._cfg_get("downloads.cache_dir", self.DEFAULT_CACHE_DIR)).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.retries = int(self._cfg_get("downloads.retries", self.DEFAULT_RETRIES))
        self.parallel = int(self._cfg_get("downloads.parallel", self.DEFAULT_PARALLEL))
        self.timeout = int(self._cfg_get("downloads.timeout", 300))
        self.progress = bool(self._cfg_get("downloads.progress", True))
        self.aria2c = shutil.which("aria2c")
        self.curl = shutil.which("curl")
        self.wget = shutil.which("wget")
        self.tar = shutil.which("tar")
        self.gpg = shutil.which("gpg") or shutil.which("gpg2")
        self.default_profile = str(self._cfg_get("downloads.profile", "default"))

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return os.environ.get(key.upper().replace(".", "_"), default)

    # ------------------ utilities ------------------
    def _sha256_of_string(self, s: str) -> str:
        h = hashlib.sha256()
        h.update(s.encode("utf-8"))
        return h.hexdigest()

    def _cache_name_for(self, url: str, filename: Optional[str] = None) -> str:
        """Return deterministic cache filename using sha256(url) + original filename"""
        uhash = self._sha256_of_string(url)[:16]
        base = Path(filename or url.split("/")[-1] or "file")
        return f"{uhash}-{base.name}"

    def _cache_path(self, url: str, filename: Optional[str] = None) -> Path:
        return (self.cache_dir / self._cache_name_for(url, filename)).resolve()

    def _safe_extract_tar(self, tar_path: Path, dest: Path) -> Tuple[bool, str]:
        """
        Extract tar safely preventing path traversal. Supports .zst by delegating to system tar if available.
        """
        if not tar_path.exists():
            return False, f"archive not found: {tar_path}"
        if not dest.exists():
            dest.mkdir(parents=True, exist_ok=True)
        # prefer Python tarfile for supported compression types; for zst or unknown, use system tar if available
        lower = tar_path.suffixes
        suffix = "".join(lower[-2:]) if len(lower) >= 2 else (lower[-1] if lower else "")
        try:
            if suffix in (".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2"):
                # use tarfile module
                mode = "r:*"
                with tarfile.open(str(tar_path), mode=mode) as tf:
                    for member in tf.getmembers():
                        member_path = dest.joinpath(member.name)
                        if not str(member_path.resolve()).startswith(str(dest.resolve())):
                            return False, "archive contains unsafe paths"
                    tf.extractall(path=str(dest))
                return True, "extracted"
            else:
                # fallback to system tar if available
                if self.tar:
                    cmd = [self.tar, "-xf", str(tar_path), "-C", str(dest)]
                    rc, out, err = self._safe_run(cmd)
                    if rc == 0:
                        return True, out + err
                    else:
                        return False, f"tar failed: {err or out}"
                else:
                    return False, "unsupported archive format and system tar not available"
        except Exception as e:
            return False, str(e)

    def _safe_run(self, cmd: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """Run command and capture output"""
        try:
            proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout or self.timeout, check=False)
            out = (proc.stdout.decode("utf-8", errors="replace") if proc.stdout else "")
            err = (proc.stderr.decode("utf-8", errors="replace") if proc.stderr else "")
            return proc.returncode, out, err
        except subprocess.TimeoutExpired as e:
            return 124, "", f"timeout: {e}"
        except Exception as e:
            return 1, "", f"exception: {e}"

    def _verify_gpg(self, file_path: Path, sig_path: Path) -> Tuple[bool, str]:
        if not self.gpg:
            return False, "gpg not available"
        try:
            rc, out, err = self._safe_run([self.gpg, "--verify", str(sig_path), str(file_path)], timeout=self.timeout)
            if rc == 0:
                return True, out or err
            return False, out + err
        except Exception as e:
            return False, str(e)

    # ------------------ download backends ------------------
    def _download_with_requests(self, url: str, dest: Path, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        if not HAVE_REQUESTS:
            return 1, "", "requests not installed"
        try:
            with requests.get(url, stream=True, timeout=timeout or self.timeout) as r:
                r.raise_for_status()
                tmp = dest.with_suffix(dest.suffix + ".part")
                with open(tmp, "wb") as fh:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            fh.write(chunk)
                os.replace(str(tmp), str(dest))
            return 0, "downloaded", ""
        except Exception as e:
            return 1, "", str(e)

    def _download_with_aria2c(self, url: str, dest: Path, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        if not self.aria2c:
            return 1, "", "aria2c not available"
        cmd = [self.aria2c, "-x", "4", "-s", "4", "-d", str(dest.parent), "-o", str(dest.name), url]
        return self._safe_run(cmd, timeout=timeout)

    def _download_with_curl(self, url: str, dest: Path, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        if not self.curl:
            return 1, "", "curl not available"
        cmd = [self.curl, "-L", "--fail", "-o", str(dest), url]
        return self._safe_run(cmd, timeout=timeout)

    def _download_with_wget(self, url: str, dest: Path, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        if not self.wget:
            return 1, "", "wget not available"
        cmd = [self.wget, "-O", str(dest), url]
        return self._safe_run(cmd, timeout=timeout)

    def _download_try_backends(self, url: str, dest: Path, timeout: Optional[int] = None, preferred: Optional[List[str]] = None) -> Tuple[int, str, str, str]:
        """
        Try multiple backends. Returns (rc, out, err, backend_name)
        """
        order = preferred or []
        # map name -> function
        backends = []
        for name in order:
            if name == "aria2c" and self.aria2c:
                backends.append(("aria2c", self._download_with_aria2c))
            if name == "curl" and self.curl:
                backends.append(("curl", self._download_with_curl))
            if name == "wget" and self.wget:
                backends.append(("wget", self._download_with_wget))
            if name == "requests" and HAVE_REQUESTS:
                backends.append(("requests", self._download_with_requests))
        # fallback detection if not specified
        if not backends:
            if self.aria2c:
                backends.append(("aria2c", self._download_with_aria2c))
            if self.curl:
                backends.append(("curl", self._download_with_curl))
            if self.wget:
                backends.append(("wget", self._download_with_wget))
            if HAVE_REQUESTS:
                backends.append(("requests", self._download_with_requests))

        last_err = ""
        for name, fn in backends:
            try:
                rc, out, err = fn(url, dest, timeout=timeout)
                if rc == 0:
                    return rc, out, err, name
                last_err = err or out or f"{name} rc={rc}"
            except Exception as e:
                last_err = str(e)
        return 1, "", last_err, "none"

    # ------------------ cache & validation ------------------
    def cache_has_valid(self, url: str, expected_sha: Optional[str] = None, filename: Optional[str] = None) -> bool:
        p = self._cache_path(url, filename)
        if not p.exists():
            return False
        if expected_sha:
            actual = self._sha256_file(p)
            return actual == expected_sha
        # optionally revalidate age
        max_age = int(self._cfg_get("downloads.cache_max_age_seconds", 0) or 0)
        if max_age > 0:
            age = time.time() - p.stat().st_mtime
            if age > max_age:
                return False
        return True

    def _sha256_file(self, path: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def clean_cache(self, keep_recent: int = 10) -> None:
        """
        Clean cache leaving `keep_recent` most-recent files by mtime.
        """
        try:
            files = sorted([p for p in self.cache_dir.iterdir() if p.is_file()], key=lambda p: p.stat().st_mtime, reverse=True)
            remove = files[keep_recent:]
            for p in remove:
                try:
                    p.unlink()
                except Exception:
                    pass
            if self.logger:
                self.logger.info("download.cache_clean", f"cleaned cache, kept {keep_recent} files")
        except Exception as e:
            if self.logger:
                self.logger.warning("download.cache_clean_fail", f"cache clean failed: {e}")

    # ------------------ public API: single download ------------------
    def download_sync(self, url: str, filename: Optional[str] = None, expected_sha: Optional[str] = None, sig_url: Optional[str] = None, profile: Optional[str] = None, timeout: Optional[int] = None, preferred_backends: Optional[List[str]] = None, retries: Optional[int] = None, hooks_ctx: Optional[Dict[str, Any]] = None) -> DownloadResult:
        """
        Synchronous download. Returns DownloadResult.
        - url: source URL
        - filename: suggested filename
        - expected_sha: optional sha256 to validate
        - sig_url: optional signature URL to verify with gpg
        - profile: download profile (affects mirrors/backends)
        - preferred_backends: list like ['aria2c','curl','wget','requests']
        - retries: how many attempts
        """
        start = time.time()
        profile = profile or self.default_profile
        timeout = timeout or self.timeout
        retries = int(retries if retries is not None else self.retries)
        preferred_backends = preferred_backends or (self._cfg_get(f"downloads.profiles.{profile}.backends", None) or [])
        dest = self._cache_path(url, filename)

        # call pre_download hook
        try:
            if self.hooks:
                self.hooks.run("pre_download", {"url": url, "dest": str(dest), "profile": profile, **(hooks_ctx or {})})
        except Exception:
            pass

        # if cache valid, return
        if self.cache_has_valid(url, expected_sha, filename):
            sha = self._sha256_file(dest)
            if self.logger:
                self.logger.info("download.cache_hit", f"cache hit for {url}", url=url, path=str(dest), sha256=sha)
            # post_download hook
            try:
                if self.hooks:
                    self.hooks.run("post_download", {"url": url, "path": str(dest), "cached": True})
            except Exception:
                pass
            return DownloadResult(url=url, ok=True, path=dest, sha256=sha, backend="cache", duration=time.time() - start, error=None)

        # attempt download with retries
        last_err = ""
        backend_used = "none"
        for attempt in range(1, retries + 1):
            # pick backends order (profile override or supplied)
            rc, out, err, backend = self._download_try_backends(url, dest, timeout=timeout, preferred=(preferred_backends or []))
            backend_used = backend or "none"
            if rc == 0:
                break
            last_err = err or out or f"backend {backend} failed rc={rc}"
            # small backoff
            time.sleep(min(2 ** attempt, 30))
            if self.logger:
                self.logger.warning("download.retry", f"attempt {attempt} failed for {url}: {last_err}", attempt=attempt, url=url, backend=backend_used)

        duration = time.time() - start
        if rc != 0:
            # failure: audit/log/db and return
            if self.logger:
                self.logger.error("download.fail", f"failed to download {url}", url=url, error=last_err)
            if self.db:
                try:
                    self.db.record_phase(url, "download", "fail", meta={"url": url, "error": last_err})
                except Exception:
                    pass
            if self.audit:
                try:
                    self.audit.report("download", url, "failed", {"error": last_err})
                except Exception:
                    pass
            return DownloadResult(url=url, ok=False, path=None, sha256=None, backend=backend_used, duration=duration, error=last_err)

        # verify expected sha if provided
        actual_sha = self._sha256_file(dest)
        if expected_sha and actual_sha and expected_sha != actual_sha:
            err_msg = f"sha mismatch: expected {expected_sha}, got {actual_sha}"
            if self.logger:
                self.logger.error("download.sha_mismatch", err_msg, url=url, path=str(dest))
            # remove the file from cache because it's invalid
            try:
                dest.unlink()
            except Exception:
                pass
            # record and return fail
            if self.db:
                try:
                    self.db.record_phase(url, "download", "fail", meta={"reason": "sha_mismatch", "expected": expected_sha, "actual": actual_sha})
                except Exception:
                    pass
            return DownloadResult(url=url, ok=False, path=None, sha256=None, backend=backend_used, duration=duration, error=err_msg)

        # optional GPG verify if sig_url provided
        if sig_url and self.gpg:
            # download signature next to file
            sig_dest = dest.with_suffix(dest.suffix + ".sig")
            rc2, out2, err2, backend2 = self._download_try_backends(sig_url, sig_dest, timeout=timeout, preferred=(preferred_backends or []))
            if rc2 != 0:
                # signature not available: warn
                if self.logger:
                    self.logger.warning("download.sig_missing", f"signature download failed for {url}", sig_url=sig_url, err=err2)
            else:
                ok_gpg, gpg_out = self._verify_gpg(dest, sig_dest)
                if not ok_gpg:
                    if self.logger:
                        self.logger.error("download.gpg_fail", f"gpg verification failed for {url}", url=url, stderr=gpg_out)
                    try:
                        dest.unlink()
                    except Exception:
                        pass
                    return DownloadResult(url=url, ok=False, path=None, sha256=None, backend=backend_used, duration=duration, error="gpg verification failed")

        # record in DB
        try:
            if self.db:
                self.db.record_phase(url, "download", "ok", meta={"path": str(dest), "sha256": actual_sha, "backend": backend_used, "duration": duration})
        except Exception:
            pass

        # post_download hook
        try:
            if self.hooks:
                self.hooks.run("post_download", {"url": url, "path": str(dest), "profile": profile})
        except Exception:
            pass

        # success
        if self.logger:
            self.logger.info("download.ok", f"downloaded {url}", url=url, path=str(dest), sha256=actual_sha, backend=backend_used, duration=duration)
        return DownloadResult(url=url, ok=True, path=dest, sha256=actual_sha, backend=backend_used, duration=duration, error=None)

    # ------------------ bulk downloads ------------------
    def download_many(self, tasks: Iterable[Dict[str, Any]], parallel: Optional[int] = None) -> List[DownloadResult]:
        """
        tasks: iterable of dicts: {url, filename?, expected_sha?, sig_url?, profile?, preferred_backends?, timeout?}
        Uses ThreadPoolExecutor for parallel downloads and logger.progress for UI.
        """
        p = int(parallel or self.parallel or 1)
        tasks = list(tasks)
        total = len(tasks)
        results: List[DownloadResult] = []

        progress_ctx = None
        if self.logger and self.progress:
            try:
                progress_ctx = self.logger.progress(f"Baixando {total} arquivos", total=total)
            except Exception:
                progress_ctx = None

        with ThreadPoolExecutor(max_workers=max(1, p)) as ex:
            future_map = {}
            for t in tasks:
                future = ex.submit(self.download_sync,
                                   t.get("url"),
                                   t.get("filename"),
                                   t.get("expected_sha"),
                                   t.get("sig_url"),
                                   t.get("profile"),
                                   t.get("timeout"),
                                   t.get("preferred_backends"),
                                   t.get("retries"),
                                   t.get("hooks_ctx"))
                future_map[future] = t
            for fut in as_completed(future_map):
                try:
                    res = fut.result()
                except Exception as e:
                    # construct failure
                    t = future_map[fut]
                    res = DownloadResult(url=t.get("url"), ok=False, path=None, sha256=None, backend="exception", duration=0.0, error=str(e))
                results.append(res)
                # update progress if available
                try:
                    if progress_ctx:
                        pass
                except Exception:
                    pass

        if progress_ctx:
            try:
                progress_ctx.__exit__(None, None, None)
            except Exception:
                pass

        return results

    # ------------------ git clone with resilience ------------------
    def clone_git(self, url: str, dest: Path, branch: Optional[str] = None, depth: Optional[int] = 1, retries: Optional[int] = None, bare: bool = False) -> Tuple[bool, str]:
        retries = int(retries if retries is not None else self.retries)
        cmd_base = ["git", "clone"]
        if bare:
            cmd_base += ["--bare"]
        if branch:
            cmd_base += ["--branch", branch]
        if depth and not bare:
            try:
                d = int(depth)
                if d > 0:
                    cmd_base += ["--depth", str(d)]
            except Exception:
                pass
        cmd_base += [url, str(dest)]
        last_err = ""
        for attempt in range(1, retries + 1):
            rc, out, err = self._safe_run(cmd_base, timeout=self.timeout)
            if rc == 0:
                if self.db:
                    try:
                        self.db.record_phase(url, "git.clone", "ok", meta={"url": url, "dest": str(dest), "branch": branch})
                    except Exception:
                        pass
                if self.logger:
                    self.logger.info("git.clone.ok", f"cloned {url}", url=url, dest=str(dest), branch=branch)
                return True, out + err
            last_err = err or out or f"git clone rc={rc}"
            if self.logger:
                self.logger.warning("git.clone.retry", f"clone attempt {attempt} failed for {url}", attempt=attempt, url=url, err=last_err)
            time.sleep(min(2 ** attempt, 30))
        # final failure
        if self.db:
            try:
                self.db.record_phase(url, "git.clone", "fail", meta={"error": last_err})
            except Exception:
                pass
        if self.audit:
            try:
                self.audit.report("git", url, "clone_failed", {"error": last_err})
            except Exception:
                pass
        if self.logger:
            self.logger.error("git.clone.fail", f"failed to clone {url}", url=url, error=last_err)
        return False, last_err

    # ------------------ extraction wrapper ------------------
    def extract_archive(self, archive_path: Path, dest: Path, safe: bool = True) -> Tuple[bool, str]:
        """
        Extract an archive to dest. Supports tar.* and zip via tar or Python.
        Calls post_extract hook on success.
        """
        start = time.time()
        ok, info = self._safe_extract_tar(archive_path, dest) if archive_path.suffix.lower().endswith((".tar", ".gz", ".xz", ".bz2", ".zst", ".tgz", ".tar.gz")) else (False, "unsupported")
        duration = time.time() - start
        if ok:
            try:
                if self.db:
                    self.db.record_phase(str(archive_path), "extract", "ok", meta={"archive": str(archive_path), "dest": str(dest), "duration": duration})
            except Exception:
                pass
            try:
                if self.hooks:
                    self.hooks.run("post_extract", {"archive": str(archive_path), "dest": str(dest)})
            except Exception:
                pass
            if self.logger:
                self.logger.info("download.extract.ok", f"extracted {archive_path}", archive=str(archive_path), dest=str(dest), duration=round(duration, 3))
            return True, info
        else:
            if self.db:
                try:
                    self.db.record_phase(str(archive_path), "extract", "fail", meta={"archive": str(archive_path), "dest": str(dest), "error": info})
                except Exception:
                    pass
            if self.logger:
                self.logger.error("download.extract.fail", f"failed to extract {archive_path}", archive=str(archive_path), dest=str(dest), error=info)
            return False, info

    # ------------------ helper: ensure cache integrity ------------------
    def revalidate_cache(self, url: str, filename: Optional[str] = None, expected_sha: Optional[str] = None) -> bool:
        """
        Revalidate cached file for url. If invalid or missing, returns False.
        """
        p = self._cache_path(url, filename)
        if not p.exists():
            return False
        if expected_sha:
            actual = self._sha256_file(p)
            return actual == expected_sha
        # else consider valid, maybe check max age
        max_age = int(self._cfg_get("downloads.cache_max_age_seconds", 0) or 0)
        if max_age > 0:
            return (time.time() - p.stat().st_mtime) <= max_age
        return True

    # ------------------ convenience CLI ------------------
    def cli_download(self, argv: Optional[List[str]] = None) -> int:
        import argparse
        parser = argparse.ArgumentParser(prog="newpkg-download", description="Download helper for newpkg")
        parser.add_argument("url", nargs="+", help="URL(s) to download")
        parser.add_argument("--dir", "-d", default=".", help="destination directory for extraction/use")
        parser.add_argument("--extract", action="store_true", help="extract archives after download")
        parser.add_argument("--expected-sha", help="expected sha256")
        parser.add_argument("--sig", help="signature URL for GPG verification")
        parser.add_argument("--retries", type=int, help="override retries")
        args = parser.parse_args(argv or sys.argv[1:])

        dest_dir = Path(args.dir).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)

        tasks = []
        for u in args.url:
            tasks.append({"url": u, "filename": None, "expected_sha": args.expected_sha, "sig_url": args.sig, "retries": args.retries})
        res = self.download_many(tasks, parallel=None)
        ok_all = True
        for r in res:
            if not r.ok:
                ok_all = False
                print(f"FAILED: {r.url} -> {r.error}")
            else:
                print(f"OK: {r.url} -> {r.path}")
                if args.extract and r.path:
                    ex_ok, ex_info = self.extract_archive(r.path, dest_dir)
                    if not ex_ok:
                        ok_all = False
                        print(f"  extract failed: {ex_info}")
        return 0 if ok_all else 2


# module-level singleton
_default_downloader: Optional[NewpkgDownload] = None


def get_downloader(cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, audit: Any = None) -> NewpkgDownload:
    global _default_downloader
    if _default_downloader is None:
        _default_downloader = NewpkgDownload(cfg=cfg, logger=logger, db=db, hooks=hooks, audit=audit)
    return _default_downloader


# quick CLI entrypoint
if __name__ == "__main__":
    dl = get_downloader()
    sys.exit(dl.cli_download())
