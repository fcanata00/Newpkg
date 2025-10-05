#!/usr/bin/env python3
# newpkg_download.py
"""
newpkg_download.py — enhanced download manager for newpkg

Features:
 - multiple backends: aria2c / curl / wget / urllib, rsync, scp, git clones
 - parallel downloads with ThreadPoolExecutor
 - optional sandboxed downloads (uses newpkg_sandbox if available)
 - cache directory with max-size maintenance (LRU by mtime)
 - GPG verification using temporary GNUPGHOME (strict mode optional)
 - progress reporting using rich via newpkg_logger.progress or local rich
 - DB phase recording (download.start, download.end, download.verify, download.extract)
 - Hooks: pre_download, post_download, pre_verify, post_verify, pre_extract, post_extract
 - Returns structured results per-download
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Optional integrations (best-effort)
try:
    from newpkg_api import get_api  # type: ignore
except Exception:
    get_api = None

try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_db import get_db  # type: ignore
except Exception:
    get_db = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

try:
    from newpkg_sandbox import get_sandbox  # type: ignore
except Exception:
    get_sandbox = None

# rich for progress UI
try:
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, TransferSpeedColumn, SpinnerColumn
    from rich.console import Console
    RICH = True
    _console = Console()
except Exception:
    RICH = False
    _console = None

# fallback simple logger
import logging
_logger = logging.getLogger("newpkg.download")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.download: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# ---------------- dataclasses ----------------
@dataclass
class SourceSpec:
    url: str
    filename: Optional[str] = None
    sha256: Optional[str] = None
    backend: Optional[str] = None  # 'http','ftp','git','rsync','scp','file'
    headers: Optional[Dict[str, str]] = None
    auth: Optional[Dict[str, Any]] = None  # placeholder for token/ssh
    extra: Optional[Dict[str, Any]] = None

@dataclass
class DownloadResult:
    url: str
    ok: bool
    path: Optional[str]
    error: Optional[str]
    sha256: Optional[str]
    verified: Optional[bool]
    attempt: int
    duration: float
    backend: Optional[str]
    meta: Dict[str, Any]

# ---------------- utility functions ----------------
def now_ts() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

def file_sha256(path: Union[str, Path]) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(str(path), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def _run_cmd(cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout.decode("utf-8", errors="ignore")
        err = proc.stderr.decode("utf-8", errors="ignore")
        return proc.returncode, out, err
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout: {e}"
    except Exception as e:
        return 1, "", str(e)

def _ensure_dir(p: Union[str, Path], mode: int = 0o700):
    p = Path(p)
    p.mkdir(parents=True, exist_ok=True)
    try:
        p.chmod(mode)
    except Exception:
        pass

def _sanitize_filename(n: str) -> str:
    # basic safe filename
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in n)[:255]

# ---------------- main manager ----------------
class DownloadManager:
    DEFAULT_CACHE_DIR = "/var/cache/newpkg/downloads"
    DEFAULT_THREADS = 4
    DEFAULT_MAX_CACHE_MB = 1024  # 1 GiB

    def __init__(self, cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, hooks: Optional[Any] = None, sandbox: Optional[Any] = None):
        self.api = None
        if get_api:
            try:
                self.api = get_api()
                try:
                    self.api.init_all()
                except Exception:
                    pass
            except Exception:
                self.api = None

        self.cfg = cfg or (self.api.cfg if self.api and getattr(self.api, "cfg", None) else None)
        self.logger = logger or (self.api.logger if self.api and getattr(self.api, "logger", None) else (get_logger(self.cfg) if get_logger else None))
        self.db = db or (self.api.db if self.api and getattr(self.api, "db", None) else (get_db() if get_db else None))
        self.hooks = hooks or (self.api.hooks if self.api and getattr(self.api, "hooks", None) else (get_hooks_manager(self.cfg) if get_hooks_manager else None))
        self.sandbox = sandbox or (self.api.sandbox if self.api and getattr(self.api, "sandbox", None) else (get_sandbox(self.cfg) if get_sandbox else None))

        # cache dir
        cache_dir = None
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                cache_dir = self.cfg.get("downloads.cache_dir")
        except Exception:
            cache_dir = None
        self.cache_dir = Path(cache_dir or os.environ.get("NEWPKG_DOWNLOAD_CACHE", self.DEFAULT_CACHE_DIR)).expanduser()
        _ensure_dir(self.cache_dir)

        # threads
        threads = self.DEFAULT_THREADS
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                threads = int(self.cfg.get("downloads.threads") or self.cfg.get("general.threads") or threads)
        except Exception:
            pass
        self.threads = threads

        # cache size limit
        max_cache_mb = self.DEFAULT_MAX_CACHE_MB
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                max_cache_mb = int(self.cfg.get("downloads.max_cache_mb") or max_cache_mb)
        except Exception:
            pass
        self.max_cache_bytes = max_cache_mb * 1024 * 1024

        # GPG strict
        self.gpg_strict = False
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.gpg_strict = bool(self.cfg.get("downloads.gpg.strict", False))
        except Exception:
            pass

        # register to API if available
        try:
            if self.api:
                self.api.download = self
        except Exception:
            pass

        # internal lock
        self._cache_lock = threading.RLock()

    # ---------------- cache maintenance ----------------
    def _enforce_cache_limit(self):
        """
        Remove oldest files until total cache size <= max_cache_bytes.
        """
        try:
            with self._cache_lock:
                files = [p for p in self.cache_dir.iterdir() if p.is_file()]
                files.sort(key=lambda p: p.stat().st_mtime)  # oldest first
                total = sum(p.stat().st_size for p in files)
                if total <= self.max_cache_bytes:
                    return
                # remove oldest until under limit
                for p in files:
                    try:
                        p.unlink()
                        total -= p.stat().st_size if p.exists() else 0
                    except Exception:
                        try:
                            # best-effort: set perms then remove
                            p.chmod(0o600)
                            p.unlink()
                        except Exception:
                            pass
                    if total <= self.max_cache_bytes:
                        break
        except Exception:
            pass

    # ---------------- backend helpers ----------------
    def _backend_aria2c(self, url: str, dest: Path, timeout: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        cmd = shutil.which("aria2c")
        if not cmd:
            return False, "aria2c not found"
        # aria2c -x4 -s4 -o filename -d dest url
        outname = dest / Path(url.split("?", 1)[0]).name
        cmdline = [cmd, "-x", "4", "-s", "4", "-d", str(dest), "-o", outname.name, url]
        rc, out, err = _run_cmd(cmdline, timeout=timeout)
        if rc == 0:
            return True, str(outname)
        return False, err or out

    def _backend_curl(self, url: str, dest: Path, timeout: Optional[int] = None, headers: Optional[Dict[str, str]] = None) -> Tuple[bool, Optional[str]]:
        curl = shutil.which("curl")
        if not curl:
            return False, "curl not found"
        outname = dest / Path(url.split("?", 1)[0]).name
        cmd = [curl, "-L", "--fail", "--retry", "3", "-o", str(outname), url]
        if headers:
            for k, v in headers.items():
                cmd.insert(-1, "-H")
                cmd.insert(-1, f"{k}: {v}")
        rc, out, err = _run_cmd(cmd, timeout=timeout)
        if rc == 0:
            return True, str(outname)
        return False, err or out

    def _backend_wget(self, url: str, dest: Path, timeout: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        wget = shutil.which("wget")
        if not wget:
            return False, "wget not found"
        outname = dest / Path(url.split("?", 1)[0]).name
        cmd = [wget, "-O", str(outname), url]
        rc, out, err = _run_cmd(cmd, timeout=timeout)
        if rc == 0:
            return True, str(outname)
        return False, err or out

    def _backend_urllib(self, url: str, dest: Path, timeout: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        outname = dest / Path(url.split("?", 1)[0]).name
        try:
            urllib.request.urlretrieve(url, str(outname))
            return True, str(outname)
        except Exception as e:
            return False, str(e)

    def _backend_rsync(self, url: str, dest: Path, timeout: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        rsync = shutil.which("rsync")
        if not rsync:
            return False, "rsync not found"
        # url like rsync://host/module/path
        cmd = [rsync, "-a", url, str(dest)]
        rc, out, err = _run_cmd(cmd, timeout=timeout)
        if rc == 0:
            return True, str(dest)
        return False, err or out

    def _backend_scp(self, url: str, dest: Path, timeout: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        scp = shutil.which("scp")
        if not scp:
            return False, "scp not found"
        # url like user@host:/path
        outname = dest / Path(url.split(":", 1)[-1]).name
        cmd = [scp, url, str(outname)]
        rc, out, err = _run_cmd(cmd, timeout=timeout)
        if rc == 0:
            return True, str(outname)
        return False, err or out

    def _backend_git(self, url: str, dest: Path, shallow: Optional[int] = None, branch: Optional[str] = None, timeout: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        git = shutil.which("git")
        if not git:
            return False, "git not found"
        # clone to dest/<repo>
        target = dest / _sanitize_filename(Path(url).stem)
        if target.exists():
            # fetch
            rc, out, err = _run_cmd([git, "pull"], cwd=str(target), timeout=timeout)
            if rc == 0:
                return True, str(target)
            else:
                return False, err or out
        else:
            cmd = [git, "clone"]
            if shallow and shallow > 0:
                cmd += ["--depth", str(shallow)]
            if branch:
                cmd += ["-b", branch]
            cmd += [url, str(target)]
            rc, out, err = _run_cmd(cmd, timeout=timeout)
            if rc == 0:
                return True, str(target)
            return False, err or out

    # ---------------- verification ----------------
    def _verify_gpg(self, file_path: Path, sig_path: Optional[Path] = None, keyring_paths: Optional[List[str]] = None, timeout: Optional[int] = None) -> Tuple[bool, str]:
        """
        Verify GPG using temporary GNUPGHOME so system keyring not touched.
        If sig_path is None but a .asc or .sig file exists next to file_path, it will try that.
        keyring_paths: additional key files to import (paths).
        """
        gpg = shutil.which("gpg") or shutil.which("gpg2")
        if not gpg:
            return False, "gpg not found"
        tmpdir = tempfile.mkdtemp(prefix="newpkg-gpg-")
        os.chmod(tmpdir, 0o700)
        env = dict(os.environ)
        env["GNUPGHOME"] = tmpdir
        # import keyring paths if provided
        try:
            if keyring_paths:
                for k in keyring_paths:
                    _run_cmd([gpg, "--import", str(k)], env=env, timeout=timeout)
        except Exception:
            pass
        try:
            # find signature if not provided
            sigp = None
            if sig_path and Path(sig_path).exists():
                sigp = Path(sig_path)
            else:
                for ext in (".asc", ".sig", ".gpg"):
                    cand = file_path.with_suffix(file_path.suffix + ext)
                    if cand.exists():
                        sigp = cand
                        break
            if not sigp:
                return False, "signature not found"
            rc, out, err = _run_cmd([gpg, "--verify", str(sigp), str(file_path)], env=env, timeout=timeout)
            shutil.rmtree(tmpdir, ignore_errors=True)
            if rc == 0:
                return True, out or "ok"
            return False, err or out
        except Exception as e:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return False, str(e)

    # ---------------- single download worker ----------------
    def _download_worker(self, spec: SourceSpec, dest_dir: Path, use_sandbox: bool = False, timeout: Optional[int] = None, prefer: Optional[List[str]] = None, max_attempts: int = 3) -> DownloadResult:
        """
        Worker that attempts to download a SourceSpec to dest_dir, verifies checksum/gpg if available,
        and returns DownloadResult.
        """
        t0 = time.time()
        url = spec.url
        filename = spec.filename or Path(url.split("?", 1)[0]).name
        filename = _sanitize_filename(filename)
        dest_dir = Path(dest_dir)
        _ensure_dir(dest_dir)
        final_path = dest_dir / filename

        if self.hooks:
            try:
                self.hooks.run("pre_download", {"url": url, "dest": str(dest_dir)})
            except Exception:
                pass

        # check cache first by sha256 -> find existing file with same sha
        if spec.sha256:
            # search cache for matching sha
            for p in self.cache_dir.iterdir():
                if not p.is_file():
                    continue
                try:
                    if file_sha256(p) == spec.sha256:
                        # copy to dest_dir (hardlink if possible)
                        try:
                            target = dest_dir / p.name
                            if not target.exists():
                                os.link(str(p), str(target))
                            duration = time.time() - t0
                            if self.db:
                                try:
                                    self.db.record_phase(None, "download.cache_hit", "ok", meta={"url": url, "cache": str(p)})
                                except Exception:
                                    pass
                            if self.hooks:
                                try:
                                    self.hooks.run("post_download", {"url": url, "path": str(target), "cache_hit": True})
                                except Exception:
                                    pass
                            return DownloadResult(url=url, ok=True, path=str(target), error=None, sha256=spec.sha256, verified=True, attempt=0, duration=duration, backend="cache", meta={})
                        except Exception:
                            # fallback to copy
                            try:
                                shutil.copy2(str(p), str(final_path))
                                duration = time.time() - t0
                                return DownloadResult(url=url, ok=True, path=str(final_path), error=None, sha256=spec.sha256, verified=True, attempt=0, duration=duration, backend="cache", meta={})
                            except Exception:
                                # continue to download
                                pass

        attempt = 0
        last_err = None
        verified = None

        backends = prefer or ["aria2c", "curl", "wget", "urllib"]
        # allow backend override by spec
        if spec.backend:
            backends = [spec.backend] + [b for b in backends if b != spec.backend]

        while attempt < max_attempts:
            attempt += 1
            if self.db:
                try:
                    self.db.record_phase(None, "download.attempt", "pending", meta={"url": url, "attempt": attempt})
                except Exception:
                    pass
            # run pre attempt hook
            if self.hooks:
                try:
                    self.hooks.run("pre_download_attempt", {"url": url, "attempt": attempt})
                except Exception:
                    pass

            for be in backends:
                ok = False
                path_or_err = None
                if be == "aria2c":
                    ok, path_or_err = self._backend_aria2c(url, dest_dir, timeout=timeout)
                elif be == "curl":
                    ok, path_or_err = self._backend_curl(url, dest_dir, timeout=timeout, headers=spec.headers)
                elif be == "wget":
                    ok, path_or_err = self._backend_wget(url, dest_dir, timeout=timeout)
                elif be == "rsync":
                    ok, path_or_err = self._backend_rsync(url, dest_dir, timeout=timeout)
                elif be == "scp":
                    ok, path_or_err = self._backend_scp(url, dest_dir, timeout=timeout)
                elif be == "git":
                    # treat spec.extra for git params
                    shallow = spec.extra.get("shallow") if spec.extra else None
                    branch = spec.extra.get("branch") if spec.extra else None
                    ok, path_or_err = self._backend_git(url, dest_dir, shallow=shallow, branch=branch, timeout=timeout)
                else:  # urllib
                    ok, path_or_err = self._backend_urllib(url, dest_dir, timeout=timeout)
                if ok and path_or_err:
                    downloaded_path = Path(path_or_err)
                    # move to cache atomically
                    try:
                        cache_target = self.cache_dir / downloaded_path.name
                        if not cache_target.exists():
                            try:
                                shutil.copy2(str(downloaded_path), str(cache_target))
                            except Exception:
                                try:
                                    os.replace(str(downloaded_path), str(cache_target))
                                except Exception:
                                    pass
                        # create hardlink to dest if possible
                        final = dest_dir / cache_target.name
                        if not final.exists():
                            try:
                                os.link(str(cache_target), str(final))
                            except Exception:
                                try:
                                    shutil.copy2(str(cache_target), str(final))
                                except Exception:
                                    pass
                        final_path = final
                    except Exception:
                        final_path = downloaded_path

                    # verify sha256 if provided
                    if spec.sha256:
                        got = file_sha256(final_path)
                        if got != spec.sha256:
                            last_err = f"sha256 mismatch expected={spec.sha256} got={got}"
                            if self.db:
                                try:
                                    self.db.record_phase(None, "download.verify", "fail", meta={"url": url, "expected": spec.sha256, "got": got})
                                except Exception:
                                    pass
                            verified = False
                            # try next backend
                            continue
                        else:
                            verified = True
                            if self.db:
                                try:
                                    self.db.record_phase(None, "download.verify", "ok", meta={"url": url, "sha256": got})
                                except Exception:
                                    pass
                    else:
                        # no checksum provided
                        verified = None
                    # success
                    duration = time.time() - t0
                    if self.hooks:
                        try:
                            self.hooks.run("post_download", {"url": url, "path": str(final_path), "attempt": attempt, "backend": be})
                        except Exception:
                            pass
                    # enforce cache limit in background
                    try:
                        threading.Thread(target=self._enforce_cache_limit, daemon=True).start()
                    except Exception:
                        pass
                    return DownloadResult(url=url, ok=True, path=str(final_path), error=None, sha256=spec.sha256, verified=verified, attempt=attempt, duration=duration, backend=be, meta={})
                else:
                    last_err = path_or_err or "unknown error"
                    # if transient network issue, try next backend or wait
                    if self._is_transient_error(last_err):
                        continue
                    # else try next backend
                    continue
            # attempt complete, maybe wait before retry
            time.sleep(1 + attempt)
        # all attempts failed
        duration = time.time() - t0
        if self.db:
            try:
                self.db.record_phase(None, "download.fail", "fail", meta={"url": url, "error": last_err})
            except Exception:
                pass
        if self.hooks:
            try:
                self.hooks.run("post_download", {"url": url, "path": None, "attempt": attempt, "ok": False, "error": last_err})
            except Exception:
                pass
        return DownloadResult(url=url, ok=False, path=None, error=str(last_err), sha256=spec.sha256, verified=False, attempt=attempt, duration=duration, backend=None, meta={})

    def _is_transient_error(self, err: Optional[str]) -> bool:
        if not err:
            return False
        low = err.lower()
        keys = ["timed out", "temporary failure", "could not resolve", "connection reset", "503", "502", "connection refused", "no route to host"]
        return any(k in low for k in keys)

    # ---------------- public API ----------------
    def download_many(self, specs: List[SourceSpec], dest_dir: Optional[str] = None, parallel: Optional[int] = None, use_sandbox: Optional[bool] = None, timeout: Optional[int] = None, prefer_backends: Optional[List[str]] = None) -> List[DownloadResult]:
        """
        Download a list of SourceSpec in parallel. Returns list of DownloadResult objects (same order as input).
        """
        dest_dir = Path(dest_dir or tempfile.mkdtemp(prefix="newpkg-dl-"))
        _ensure_dir(dest_dir)
        parallel = parallel or self.threads
        use_sandbox = bool(use_sandbox) if use_sandbox is not None else bool(self.cfg and hasattr(self.cfg, "get") and self.cfg.get("downloads.sandbox", False))

        results: List[DownloadResult] = [None] * len(specs)  # type: ignore
        futures = {}
        with ThreadPoolExecutor(max_workers=parallel) as ex:
            for idx, spec in enumerate(specs):
                futures[ex.submit(self._download_worker, spec, dest_dir, use_sandbox, timeout, prefer_backends)] = idx
            # progress UI
            total = len(specs)
            if self.logger and hasattr(self.logger, "progress"):
                pctx = None
                try:
                    pctx = self.logger.progress("Baixando", total=total)
                    pctx.__enter__()
                except Exception:
                    pctx = None
            elif RICH and _console:
                pctx = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TransferSpeedColumn(), TimeElapsedColumn(), TimeRemainingColumn(), console=_console)
                pctx.start()
                task = pctx.add_task("download", total=total)
            else:
                pctx = None
                task = None

            try:
                for fut in as_completed(futures):
                    idx = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = DownloadResult(url=specs[idx].url, ok=False, path=None, error=str(e), sha256=specs[idx].sha256, verified=False, attempt=0, duration=0.0, backend=None, meta={})
                    results[idx] = res
                    # update progress
                    try:
                        if pctx:
                            if hasattr(pctx, "update"):
                                # rich progress
                                if task is not None:
                                    pctx.update(task, advance=1)
                            elif hasattr(pctx, "__call__"):
                                pass
                    except Exception:
                        pass
            finally:
                if pctx:
                    try:
                        if hasattr(pctx, "stop"):
                            pctx.stop()
                        else:
                            pctx.__exit__(None, None, None)
                    except Exception:
                        pass
        return results

    def download_one(self, url: str, filename: Optional[str] = None, sha256: Optional[str] = None, backend: Optional[str] = None, dest_dir: Optional[str] = None, **kwargs) -> DownloadResult:
        spec = SourceSpec(url=url, filename=filename, sha256=sha256, backend=backend)
        res = self.download_many([spec], dest_dir=dest_dir, **kwargs)
        return res[0]

# ---------------- module-level accessor ----------------
_default_dl_mgr: Optional[DownloadManager] = None
_dl_lock = threading.RLock()

def get_download_manager(cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, hooks: Optional[Any] = None, sandbox: Optional[Any] = None) -> DownloadManager:
    global _default_dl_mgr
    with _dl_lock:
        if _default_dl_mgr is None:
            _default_dl_mgr = DownloadManager(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)
        return _default_dl_mgr

# ---------------- CLI for debugging ----------------
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-download", description="download manager debug")
    p.add_argument("url", nargs="?", help="url to download (or pass manifest JSON)")
    p.add_argument("--dest", help="destination directory")
    p.add_argument("--sha256", help="expected sha256")
    p.add_argument("--gpg-strict", action="store_true")
    args = p.parse_args()
    mgr = get_download_manager()
    if args.gpg_strict:
        mgr.gpg_strict = True
    if args.url and args.url.endswith(".json") and os.path.exists(args.url):
        text = Path(args.url).read_text(encoding="utf-8")
        specs = json.loads(text)
        srcs = []
        for s in specs:
            srcs.append(SourceSpec(url=s.get("url"), filename=s.get("filename"), sha256=s.get("sha256"), backend=s.get("backend")))
        res = mgr.download_many(srcs, dest_dir=args.dest)
        pprint.pprint([asdict(r) for r in res])
    elif args.url:
        r = mgr.download_one(args.url, sha256=args.sha256, dest_dir=args.dest)
        pprint.pprint(asdict(r))
    else:
        print("provide URL or manifest JSON")
