#!/usr/bin/env python3
# newpkg_metafile.py
"""
Metafile manager for newpkg — revised.

Responsibilities:
 - load/parse metafiles (TOML/JSON/YAML)
 - resolve includes and merges
 - discover download URLs and metadata (hashes, type)
 - parallel download with cache and integrity checks
 - unpack inside sandbox when available
 - apply patches with fallback (patch -p1 -> -p0) and gz extraction
 - produce a structured MetafileResult for downstream pipelines
 - register phases on DB and invoke hooks for extensibility
"""

from __future__ import annotations

import hashlib
import json
import lzma
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import traceback
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# parsing helpers (best-effort)
try:
    import tomllib  # py3.11+
except Exception:
    tomllib = None

try:
    import toml as _toml  # type: ignore
except Exception:
    _toml = None

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# optional integration with newpkg_api and other modules (best-effort)
try:
    from newpkg_api import get_api  # type: ignore
except Exception:
    get_api = None

try:
    from newpkg_config import init_config, get_config  # type: ignore
except Exception:
    init_config = None
    get_config = None

# fallback logger
import logging
_logger = logging.getLogger("newpkg.metafile")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.metafile: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# Utility functions
def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def file_sha256(path: Union[str, Path]) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(str(path), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def detect_and_parse(path: str) -> Optional[Dict[str, Any]]:
    """Try parsing JSON/TOML/YAML using heuristics."""
    try:
        raw = Path(path).read_bytes()
    except Exception:
        return None
    txt = raw.decode("utf-8", errors="ignore")
    suffix = Path(path).suffix.lower()
    if suffix == ".toml" and tomllib:
        try:
            return tomllib.loads(txt)
        except Exception:
            pass
    if suffix == ".toml" and _toml:
        try:
            return _toml.loads(txt)
        except Exception:
            pass
    if suffix in (".yml", ".yaml") and yaml:
        try:
            return yaml.safe_load(txt)
        except Exception:
            pass
    if suffix == ".json":
        try:
            return json.loads(txt)
        except Exception:
            pass
    # heuristics
    txts = txt.strip()
    if txts.startswith("{") or txts.startswith("["):
        try:
            return json.loads(txts)
        except Exception:
            pass
    if "=" in txts and (tomllib or _toml):
        try:
            if tomllib:
                return tomllib.loads(txts)
            if _toml:
                return _toml.loads(txts)
        except Exception:
            pass
    if yaml:
        try:
            return yaml.safe_load(txts)
        except Exception:
            pass
    return None

def safe_makedirs(path: Union[str, Path], exist_ok=True):
    Path(path).mkdir(parents=True, exist_ok=exist_ok)

def run_cmd(cmd: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout or 3600)
        out = proc.stdout.decode("utf-8", errors="ignore")
        err = proc.stderr.decode("utf-8", errors="ignore")
        return proc.returncode, out, err
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout: {e}"
    except Exception as e:
        return 1, "", str(e)

# ---------------- data classes ----------------
@dataclass
class DownloadSpec:
    url: str
    filename_hint: Optional[str] = None
    sha256: Optional[str] = None
    size: Optional[int] = None
    type: Optional[str] = None  # tar.xz, tar.gz, zip, git, etc.

@dataclass
class MetafileResult:
    package: str
    metafile_path: Optional[str]
    success: bool
    downloads: List[str]
    downloaded_paths: List[str]
    unpack_dir: Optional[str]
    env: Dict[str, str]
    patches_applied: List[str]
    errors: List[str]
    duration: float
    meta: Dict[str, Any]

# ---------------- main class ----------------
class MetafileManager:
    DEFAULT_CACHE_DIR = "/var/cache/newpkg/metafiles"
    DEFAULT_DOWNLOAD_THREADS = 4
    DEFAULT_FORCE_DOWNLOAD = False

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None):
        # integrate with newpkg_api if available
        self.api = None
        if get_api:
            try:
                self.api = get_api()
                # ensure api initialized
                try:
                    self.api.init_all()
                except Exception:
                    pass
            except Exception:
                self.api = None

        # reuse provided or injected singletons
        self.cfg = cfg or (self.api.cfg if self.api and getattr(self.api, "cfg", None) else (get_config() if get_config else None))
        self.logger = logger or (self.api.logger if self.api and getattr(self.api, "logger", None) else (None))
        self.db = db or (self.api.db if self.api and getattr(self.api, "db", None) else None)
        self.hooks = hooks or (self.api.hooks if self.api and getattr(self.api, "hooks", None) else None)
        self.sandbox = sandbox or (self.api.sandbox if self.api and getattr(self.api, "sandbox", None) else None)

        # internal config
        # cache dir from config or default
        cache_from_cfg = None
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                cache_from_cfg = self.cfg.get("metafile.cache_dir")
        except Exception:
            cache_from_cfg = None
        self.cache_dir = Path(cache_from_cfg or os.environ.get("NEWPKG_META_CACHE", self.DEFAULT_CACHE_DIR)).expanduser()
        safe_makedirs(self.cache_dir)

        threads = None
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                threads = int(self.cfg.get("metafile.download_threads") or self.cfg.get("general.threads") or self.DEFAULT_DOWNLOAD_THREADS)
        except Exception:
            threads = self.DEFAULT_DOWNLOAD_THREADS
        self.threads = threads or self.DEFAULT_DOWNLOAD_THREADS

        self.force_download = bool(os.environ.get("NEWPKG_META_FORCE", "") == "1") or self.DEFAULT_FORCE_DOWNLOAD

    # ---------------- parsing & includes ----------------
    def load_metafile(self, path: str) -> Optional[Dict[str, Any]]:
        """Load a metafile and resolve recursive includes (metafiles may include other metafiles)."""
        try:
            mt = detect_and_parse(path)
            if mt is None:
                return None
            # includes support: 'include' or 'includes' may be string or list
            incs = mt.get("include") or mt.get("includes") or []
            merged = {}
            # first process includes (so main overrides included)
            if incs:
                if isinstance(incs, str):
                    incs = [incs]
                for inc in incs:
                    # resolve relative to path dir
                    cand = inc
                    if not os.path.isabs(cand):
                        cand = os.path.join(os.path.dirname(path), inc)
                    if os.path.exists(cand):
                        sub = self.load_metafile(cand)
                        if sub:
                            merged = self._merge_dicts(merged, sub)
            # finally merge mt (main overrides)
            merged = self._merge_dicts(merged, mt)
            return merged
        except Exception:
            return None

    def _merge_dicts(self, a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
        # simple recursive merge where values in b override a
        out = dict(a)
        for k, v in b.items():
            if k in out and isinstance(out[k], dict) and isinstance(v, dict):
                out[k] = self._merge_dicts(out[k], v)
            else:
                out[k] = v
        return out

    # ---------------- helpers for downloads ----------------
    def _download_one(self, spec: DownloadSpec, dest_dir: Path, timeout: Optional[int] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Download a single URL to dest_dir. Returns (ok, path_or_none, error_or_none).
        Uses curl/wget/aria2c if available; fallback to urllib.
        """
        url = spec.url
        filename = spec.filename_hint or os.path.basename(url.split("?", 1)[0]) or f"file-{int(time.time())}"
        target = dest_dir / filename
        # if cached and hash matches, skip unless force
        if target.exists() and spec.sha256:
            got = file_sha256(target)
            if got == spec.sha256 and not (self.force_download or self._env_force()):
                return True, str(target), None
        # try external downloaders
        aria = shutil.which("aria2c")
        curl = shutil.which("curl")
        wget = shutil.which("wget")
        try:
            if aria:
                cmd = [aria, "-x", "4", "-s", "4", "-d", str(dest_dir), "-o", filename, url]
                rc, out, err = run_cmd(cmd, timeout=timeout)
                if rc == 0:
                    return True, str(target), None
                else:
                    last_err = err or out
            elif curl:
                cmd = [curl, "-L", "--fail", "--retry", "3", "-o", str(target), url]
                rc, out, err = run_cmd(cmd, timeout=timeout)
                if rc == 0:
                    return True, str(target), None
                last_err = err or out
            elif wget:
                cmd = [wget, "-O", str(target), url]
                rc, out, err = run_cmd(cmd, timeout=timeout)
                if rc == 0:
                    return True, str(target), None
                last_err = err or out
            else:
                # urllib fallback
                import urllib.request
                try:
                    urllib.request.urlretrieve(url, str(target))
                    return True, str(target), None
                except Exception as e:
                    last_err = str(e)
        except Exception as e:
            last_err = str(e)
        # if reached here, download failed
        return False, None, last_err

    def _env_force(self) -> bool:
        return bool(os.environ.get("NEWPKG_FORCE_DOWNLOAD", "") in ("1", "true", "True"))

    def download_sources(self, specs: List[DownloadSpec], dest_dir: Optional[str] = None, parallel: Optional[int] = None, timeout: Optional[int] = None) -> Tuple[List[str], List[str]]:
        """
        Download multiple specs in parallel. Returns (downloaded_paths, errors).
        """
        dest_dir = Path(dest_dir or tempfile.mkdtemp(prefix="newpkg-meta-download-"))
        safe_makedirs(dest_dir)
        parallel = parallel or self.threads
        downloaded: List[str] = []
        errors: List[str] = []
        with ThreadPoolExecutor(max_workers=parallel) as ex:
            futs = {ex.submit(self._download_one, s, dest_dir, timeout): s for s in specs}
            for fut in as_completed(futs):
                s = futs[fut]
                try:
                    ok, path, err = fut.result()
                except Exception as e:
                    ok = False
                    path = None
                    err = str(e)
                if ok and path:
                    # verify sha256 if provided
                    if s.sha256:
                        got = file_sha256(path)
                        if got != s.sha256:
                            errors.append(f"integrity mismatch for {s.url} (expected {s.sha256}, got {got})")
                            # optionally remove file
                            try:
                                Path(path).unlink()
                            except Exception:
                                pass
                            continue
                    downloaded.append(path)
                else:
                    errors.append(f"{s.url}: {err}")
        return downloaded, errors

    # ---------------- unpack / extraction ----------------
    def _unpack_archive(self, path: str, dest_dir: str, use_sandbox: bool = True) -> Tuple[bool, str]:
        """
        Unpack an archive (tar.* or zip). If sandbox available and use_sandbox True,
        attempt to unpack inside sandbox; otherwise unpack locally.
        Returns (ok, message or dest_dir).
        """
        try:
            p = Path(path)
            dest = Path(dest_dir)
            safe_makedirs(dest)
            # call hooks pre_unpack
            if self.hooks:
                try:
                    self.hooks.run("pre_unpack", {"path": str(p), "dest": str(dest)})
                except Exception:
                    pass
            if use_sandbox and self.sandbox and hasattr(self.sandbox, "run_in_sandbox"):
                # create script to extract inside sandbox
                script = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".sh")
                script.write("#!/bin/sh\nset -e\n")
                # choose extraction based on suffix
                name = str(p)
                if tarfile.is_tarfile(name):
                    # use tar auto-detect
                    script.write(f"tar -xf {shlex_quote(name)} -C {shlex_quote(str(dest))}\n")
                elif zipfile.is_zipfile(name):
                    script.write(f"unzip -o {shlex_quote(name)} -d {shlex_quote(str(dest))}\n")
                else:
                    # fallback: try tar
                    script.write(f"tar -xf {shlex_quote(name)} -C {shlex_quote(str(dest))} || true\n")
                script.close()
                os.chmod(script.name, 0o755)
                try:
                    res = self.sandbox.run_in_sandbox([script.name], use_fakeroot=False)
                    rc = getattr(res, "rc", None)
                    out = getattr(res, "stdout", "") or ""
                    err = getattr(res, "stderr", "") or ""
                    try:
                        os.unlink(script.name)
                    except Exception:
                        pass
                    if rc == 0:
                        if self.hooks:
                            try:
                                self.hooks.run("post_unpack", {"path": str(p), "dest": str(dest)})
                            except Exception:
                                pass
                        return True, str(dest)
                    else:
                        return False, f"sandbox unpack failed: rc={rc} out={out} err={err}"
                except Exception as e:
                    return False, f"sandbox unpack exception: {e}"
            else:
                # local unpack
                if tarfile.is_tarfile(str(p)):
                    with tarfile.open(str(p), "r:*") as tf:
                        tf.extractall(path=str(dest))
                elif zipfile.is_zipfile(str(p)):
                    with zipfile.ZipFile(str(p), "r") as zf:
                        zf.extractall(path=str(dest))
                else:
                    # not an archive; if it's a directory or plain file, copy it
                    if p.is_dir():
                        shutil.copytree(str(p), str(dest), dirs_exist_ok=True)
                    else:
                        shutil.copy2(str(p), str(dest))
                if self.hooks:
                    try:
                        self.hooks.run("post_unpack", {"path": str(p), "dest": str(dest)})
                    except Exception:
                        pass
                return True, str(dest)
        except Exception as e:
            return False, str(e)

    # ---------------- patch application ----------------
    def _apply_patch(self, patch_path: str, workdir: str) -> Tuple[bool, str]:
        """
        Attempt to apply a patch file. If fails with -p1, try -p0. Support gz compressed patches.
        Returns (ok, message).
        """
        p = Path(patch_path)
        wd = str(workdir)
        raw_patch = str(p)
        # if gz compressed, attempt to decompress to tmp
        if p.suffix in (".gz",):
            try:
                import gzip
                tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".patch")
                with gzip.open(str(p), "rb") as fh_in:
                    tmpf.write(fh_in.read())
                tmpf.close()
                raw_patch = tmpf.name
            except Exception:
                raw_patch = str(p)
        # try patch -p1 then -p0
        for pflag in ("-p1", "-p0"):
            cmd = ["patch", pflag, "-i", raw_patch]
            rc, out, err = run_cmd(cmd, cwd=wd)
            if rc == 0:
                # cleanup tmp if used
                if raw_patch != str(p):
                    try:
                        os.unlink(raw_patch)
                    except Exception:
                        pass
                return True, f"applied with {pflag}"
        # failed both
        if raw_patch != str(p):
            try:
                os.unlink(raw_patch)
            except Exception:
                pass
        return False, "patch failed (-p1/-p0)"

    # ---------------- env merging ----------------
    def _merge_envs(self, base_env: Dict[str, str], meta_env: Optional[Dict[str, Any]], profile: Optional[str] = None) -> Dict[str, str]:
        """
        Merge envs where meta_env overrides base_env. Support simple conditional keys: if profile==X then override.
        meta_env may contain entries like:
           CFLAGS: "-O2"
           conditional:
             bootstrap:
                CFLAGS: "-O0"
        Conditional structure support is basic.
        """
        out = dict(base_env or {})
        if not meta_env:
            return out
        # copy simple keys
        for k, v in meta_env.items():
            if k == "conditional":
                continue
            out[str(k)] = str(v)
        # conditionals
        cond = meta_env.get("conditional") or {}
        if profile and isinstance(cond, dict):
            pf = cond.get(profile) or {}
            for k, v in pf.items():
                out[str(k)] = str(v)
        return out

    # ---------------- high-level process ----------------
    def process_metafile(self, metafile_path: str, destdir: Optional[str] = None, force_download: Optional[bool] = None, profile: Optional[str] = None, timeout_per_download: Optional[int] = None) -> MetafileResult:
        """
        Main entry: given a metafile path or package name, process it:
         - load metafile
         - discover downloads and patches
         - download in parallel (with cache and integrity)
         - unpack into destdir (temp by default)
         - apply patches
         - compute merged env
         - return MetafileResult
        """
        t0 = time.time()
        start_ts = now_iso()
        errors: List[str] = []
        downloaded_paths: List[str] = []
        downloads: List[str] = []
        unpack_dir: Optional[str] = None
        patches_applied: List[str] = []
        meta_out: Dict[str, Any] = {}

        # prepare singletons and options
        force = bool(force_download if force_download is not None else self.force_download)
        try:
            if hasattr(self.cfg, "get"):
                cfg_base_env = dict(self.cfg.as_env(keys=None, expanded=True, redact_secrets=False))
            else:
                cfg_base_env = dict(os.environ)
        except Exception:
            cfg_base_env = dict(os.environ)

        # record phase start
        try:
            if self.db:
                self.db.record_phase("metafile", "process.start", "pending", meta={"path": metafile_path})
        except Exception:
            pass

        # LOAD
        mf_raw = None
        try:
            # allow metafile_path to be a path or package name: try file first then ask metafile manager
            if os.path.exists(metafile_path):
                mf_raw = self.load_metafile(metafile_path)
            else:
                # try to find via metafile repository (if api.metafile exists)
                if self.api and hasattr(self.api, "call"):
                    try:
                        # try api.metafile.load_metafile_for(package)
                        res = self.api.call("metafile.load_metafile_for", {"pkg": metafile_path})
                        if res and res.get("ok") and res.get("result"):
                            mf_raw = res.get("result")
                    except Exception:
                        mf_raw = None
            if not mf_raw:
                # fallback: try to parse as path even if not exists (helpful for stdin)
                if os.path.exists(metafile_path):
                    mf_raw = detect_and_parse(metafile_path)
        except Exception as e:
            errors.append(f"load error: {e}")
            mf_raw = None

        if not mf_raw:
            msg = f"unable to load metafile: {metafile_path}"
            errors.append(msg)
            if self.db:
                try:
                    self.db.record_phase("metafile", "process.fail", "fail", meta={"error": msg})
                except Exception:
                    pass
            return MetafileResult(package=os.path.basename(metafile_path), metafile_path=metafile_path, success=False, downloads=downloads, downloaded_paths=downloaded_paths, unpack_dir=unpack_dir, env={}, patches_applied=patches_applied, errors=errors, duration=time.time() - t0, meta=meta_out)

        # canonicalize keys: support either 'downloads' or 'sources'
        ds = mf_raw.get("downloads") or mf_raw.get("sources") or mf_raw.get("files") or []
        # downloads normalized to DownloadSpec
        specs: List[DownloadSpec] = []
        for item in ds:
            if isinstance(item, str):
                specs.append(DownloadSpec(url=item))
            elif isinstance(item, dict):
                url = item.get("url") or item.get("uri") or item.get("source")
                if not url:
                    continue
                specs.append(DownloadSpec(url=url, filename_hint=item.get("filename"), sha256=item.get("sha256") or item.get("hash"), size=item.get("size"), type=item.get("type")))
        downloads = [s.url for s in specs]

        # record download phase
        try:
            if self.db:
                self.db.record_phase("metafile", "download.start", "pending", meta={"count": len(specs)})
        except Exception:
            pass

        # perform downloads
        download_dest = Path(destdir or tempfile.mkdtemp(prefix="newpkg-meta-"))
        safe_makedirs(download_dest)
        dpaths, derrs = self.download_sources(specs, dest_dir=str(download_dest), parallel=self.threads, timeout=timeout_per_download)
        downloaded_paths = dpaths
        if derrs:
            errors.extend(derrs)

        # record download done
        try:
            if self.db:
                self.db.record_phase("metafile", "download.done", "ok" if not derrs else "partial", meta={"downloaded": len(dpaths), "errors": len(derrs)})
        except Exception:
            pass

        # unpack each downloaded artifact into workdir (if multiple, create single workdir and unpack in sequence)
        workdir = tempfile.mkdtemp(prefix="newpkg-meta-unpack-")
        safe_makedirs(workdir)
        unpack_ok = True
        for dp in dpaths:
            ok, msg = self._unpack_archive(dp, workdir, use_sandbox=True)
            if not ok:
                errors.append(f"unpack {dp}: {msg}")
                unpack_ok = False
        if not unpack_ok:
            try:
                if self.db:
                    self.db.record_phase("metafile", "unpack.fail", "fail", meta={"errors": errors})
            except Exception:
                pass
            return MetafileResult(package=mf_raw.get("package", os.path.basename(metafile_path)), metafile_path=metafile_path, success=False, downloads=downloads, downloaded_paths=downloaded_paths, unpack_dir=workdir, env={}, patches_applied=patches_applied, errors=errors, duration=time.time() - t0, meta=meta_out)
        else:
            try:
                if self.db:
                    self.db.record_phase("metafile", "unpack.done", "ok", meta={"unpacked_to": workdir})
            except Exception:
                pass
            unpack_dir = workdir

        # apply patches if present
        patches = mf_raw.get("patches") or []
        for p in patches:
            ppath = p if isinstance(p, str) else p.get("path") or p.get("file")
            if not ppath:
                continue
            # resolve relative to metafile dir
            if not os.path.isabs(ppath):
                base_dir = os.path.dirname(metafile_path) if os.path.exists(metafile_path) else os.getcwd()
                alt = os.path.join(base_dir, ppath)
                if os.path.exists(alt):
                    ppath = alt
            ok, msg = self._apply_patch(ppath, unpack_dir)
            if ok:
                patches_applied.append(ppath)
            else:
                errors.append(f"patch {ppath}: {msg}")

        # record patches
        try:
            if self.db:
                self.db.record_phase("metafile", "patch.done", "ok" if not errors else "partial", meta={"applied": patches_applied, "errors": len(errors)})
        except Exception:
            pass

        # build env: merge config.build.env and metafile.env
        meta_env = mf_raw.get("env") or mf_raw.get("environment") or {}
        # profile conditional support
        active_profile = profile or (self.cfg.active_profile if hasattr(self.cfg, "active_profile") else None)
        merged_env = self._merge_envs(cfg_base_env, meta_env, profile=active_profile)
        # report meta
        meta_out["raw"] = mf_raw
        meta_out["download_count"] = len(downloaded_paths)

        # final registration hook
        try:
            if self.hooks:
                try:
                    self.hooks.run("pre_register", {"package": mf_raw.get("package"), "unpack_dir": unpack_dir, "env": merged_env})
                except Exception:
                    pass
        except Exception:
            pass

        # saved cache metadata (sha256 of all downloaded files)
        cache_meta = {"files": [], "package": mf_raw.get("package")}
        for p in downloaded_paths:
            h = file_sha256(p)
            cache_meta["files"].append({"path": p, "sha256": h})

        # final DB record
        try:
            if self.db:
                self.db.record_phase("metafile", "process.done", "ok" if not errors else "partial", meta={"package": mf_raw.get("package"), "downloaded": len(downloaded_paths), "unpack_dir": unpack_dir})
        except Exception:
            pass

        duration = time.time() - t0
        result = MetafileResult(
            package=mf_raw.get("package", os.path.basename(metafile_path)),
            metafile_path=metafile_path,
            success=(len(errors) == 0),
            downloads=downloads,
            downloaded_paths=downloaded_paths,
            unpack_dir=unpack_dir,
            env=merged_env,
            patches_applied=patches_applied,
            errors=errors,
            duration=duration,
            meta=cache_meta,
        )

        # post_register hook
        try:
            if self.hooks:
                try:
                    self.hooks.run("post_register", {"result": asdict(result)})
                except Exception:
                    pass
        except Exception:
            pass

        return result

    # ---------------- convenience methods ----------------
    def get_sources_for(self, pkg: str) -> List[str]:
        """Try to obtain download URLs for a package using metafile repository via API or by searching cache."""
        urls: List[str] = []
        if self.api:
            try:
                res = self.api.call("metafile.get_sources_for", {"pkg": pkg})
                if res and res.get("ok"):
                    val = res.get("result")
                    if isinstance(val, list):
                        urls = val
            except Exception:
                pass
        # fallback: search cache dir for files named like package-*
        try:
            for p in self.cache_dir.iterdir():
                if pkg in p.name:
                    urls.append(str(p))
        except Exception:
            pass
        return urls

# ---------------- module-level convenience ----------------
_default_manager: Optional[MetafileManager] = None

def get_metafile_manager(cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None) -> MetafileManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = MetafileManager(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)
    return _default_manager

# ---------------- shell utility ----------------
def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)

# ---------------- CLI debug ----------------
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(prog="newpkg-metafile", description="process metafile")
    p.add_argument("metafile", help="path to metafile")
    p.add_argument("--dest", help="destdir for unpack")
    p.add_argument("--force", action="store_true")
    args = p.parse_args()
    mm = get_metafile_manager()
    res = mm.process_metafile(args.metafile, destdir=args.dest, force_download=args.force)
    import pprint
    pprint.pprint(asdict(res))
