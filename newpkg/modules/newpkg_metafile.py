#!/usr/bin/env python3
# newpkg_metafile.py
"""
Metafile processor for newpkg — revised with improvements:
 - parallel downloads (ThreadPoolExecutor)
 - new hooks: pre_download, post_download, pre_patch, post_patch
 - integration with newpkg_logger (perf_timer, progress)
 - optional GPG signature verification
 - safer patch application (subprocess with args)
 - rollback of partial downloads
 - expansion of variables via newpkg_config
 - integration with newpkg_db for package/file/dep registration
 - records timings for each stage and uses logger.progress for UI
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional integrations (best-effort)
try:
    from newpkg_config import init_config, get_config  # type: ignore
except Exception:
    init_config = None
    get_config = None

try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_db import NewpkgDB  # type: ignore
except Exception:
    NewpkgDB = None

# Optional helper modules (download, patch, hooks, sandbox, deps)
try:
    from newpkg_download import Downloader  # type: ignore
except Exception:
    Downloader = None

try:
    from newpkg_patcher import apply_patch_file  # type: ignore
except Exception:
    apply_patch_file = None

try:
    from newpkg_hooks import HooksManager  # type: ignore
except Exception:
    HooksManager = None

try:
    from newpkg_sandbox import Sandbox  # type: ignore
except Exception:
    Sandbox = None

try:
    from newpkg_deps import NewpkgDeps  # type: ignore
except Exception:
    NewpkgDeps = None

# Fallback simple logger if real logger missing
import logging
_fallback_logger = logging.getLogger("newpkg.metafile")
if not _fallback_logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.metafile: %(message)s"))
    _fallback_logger.addHandler(h)
_fallback_logger.setLevel(logging.INFO)


# ---------------------- utilities ----------------------
def _now_ts() -> int:
    return int(time.time())


def _sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _which(exe: str) -> Optional[str]:
    """Return path to executable or None."""
    p = shutil.which(exe)
    return p


def _safe_run(cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess:
    """Run subprocess safely with list args (no shell)."""
    return subprocess.run(cmd, cwd=cwd, env=env or os.environ, check=check, stdout=subprocess.PIPE if capture_output else None, stderr=subprocess.PIPE if capture_output else None)


# ---------------------- dataclasses ----------------------
@dataclass
class ResolvedSource:
    name: str
    url: str
    filepath: Path
    sha256: Optional[str] = None
    gpg_sig: Optional[str] = None  # path to signature file if present


# ---------------------- main class ----------------------
class MetafileProcessor:
    """
    Process metafiles (toml/yaml/json style) describing how to fetch and prepare a source.
    """

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None):
        # config
        self.cfg = cfg or (init_config() if init_config else None)

        # logger instance
        if logger is None:
            try:
                self.logger = get_logger(self.cfg) if get_logger else None
            except Exception:
                self.logger = None
        else:
            self.logger = logger

        # fallback logger wrapper to call
        self._log = self.logger.info if self.logger else (lambda e, m, **k: _fallback_logger.info(f"{e}: {m} {k}"))

        # db
        if db is None:
            try:
                self.db = NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None
            except Exception:
                self.db = None
        else:
            self.db = db

        # hooks manager
        if hooks is None:
            try:
                self.hooks = HooksManager(self.cfg) if HooksManager and self.cfg else None
            except Exception:
                self.hooks = None
        else:
            self.hooks = hooks

        # helpers (download/patch/sandbox/deps)
        self.downloader_cls = Downloader if Downloader else None
        self.patcher_fn = apply_patch_file if apply_patch_file else None
        self.sandbox_cls = Sandbox if Sandbox else None
        self.deps_cls = NewpkgDeps if NewpkgDeps else None

        # download parallelism default
        self.max_download_workers = int(self._cfg_get("core.download_workers", min(4, (os.cpu_count() or 1))))

        # tmp/cache paths
        self.cache_dir = Path(self._cfg_get("core.metafile_cache", "/var/cache/newpkg/metafiles")).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ---------------- config helper ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return os.environ.get(key.upper().replace(".", "_"), default)

    # ---------------- metafile load & validation ----------------
    def load_metafile(self, path: str) -> Dict[str, Any]:
        """
        Load a metafile (JSON/TOML/YAML). Returns a dict.
        """
        p = Path(path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"metafile not found: {p}")
        # try to use config loader if available
        try:
            # config's _read_file is not exported - but init_config handles reading; fallback to json
            text = p.read_text(encoding="utf-8")
            try:
                data = json.loads(text)
            except Exception:
                # fallback: try config parser via init_config pattern
                # keep simple: try eval toml/yaml libs if available in config
                from newpkg_config import Config  # type: ignore
                data = Config._read_file(p)  # reuse existing method if present
            # ensure it's dict
            if not isinstance(data, dict):
                raise ValueError("metafile content is not a mapping")
        except Exception as e:
            raise RuntimeError(f"failed to parse metafile {p}: {e}")
        # expand variables if config supports it
        try:
            if self.cfg and hasattr(self.cfg, "expand_all"):
                # merge metafile into config temp and expand? We'll call expand on values using cfg
                # Create a shallow copy and expand string values
                def expand_in_obj(o):
                    if isinstance(o, str):
                        return self.cfg._expand_str(o, 10) if hasattr(self.cfg, "_expand_str") else o
                    if isinstance(o, dict):
                        return {k: expand_in_obj(v) for k, v in o.items()}
                    if isinstance(o, list):
                        return [expand_in_obj(x) for x in o]
                    return o
                data = expand_in_obj(data)
        except Exception:
            pass
        return data

    # ---------------- resolve sources ----------------
    def _resolve_single_source(self, entry: Dict[str, Any], dest_dir: Path) -> ResolvedSource:
        """
        Accepts an entry describing a source (could be dict with url/sha256/gpg/name).
        Downloads (or chooses) and returns ResolvedSource with filepath.
        """
        name = entry.get("name") or entry.get("id") or Path(entry.get("url", "")).name or "source"
        url = entry.get("url") or entry.get("src") or entry.get("git")
        if not url:
            raise ValueError("no url/git in source entry")

        # compute dest path
        fname = entry.get("filename") or Path(url).name
        dest = dest_dir / fname
        # If already in cache and sha matches, reuse
        expected_sha = entry.get("sha256")
        if dest.exists() and expected_sha:
            actual = _sha256_file(dest)
            if actual and expected_sha and actual == expected_sha:
                return ResolvedSource(name=name, url=url, filepath=dest, sha256=expected_sha, gpg_sig=None)
        # else, download
        # use Downloader if available, else fallback to wget/curl via subprocess
        # downloads use a .part temporary file then renamed to dest
        part = dest.with_suffix(dest.suffix + ".part")
        try:
            # call pre_download hook
            self._call_hook("pre_download", {"source": entry})
            if self.downloader_cls:
                dl = self.downloader_cls(cfg=self.cfg)
                dl.download(url, str(part))
            else:
                # fallback: try curl then wget
                curl = _which("curl")
                wget = _which("wget")
                if curl:
                    cmd = [curl, "-L", "-o", str(part), url]
                    _safe_run(cmd)
                elif wget:
                    cmd = [wget, "-O", str(part), url]
                    _safe_run(cmd)
                else:
                    raise RuntimeError("no downloader available (install newpkg_download or curl/wget)")
            # rename part -> dest atomically
            part.rename(dest)
            # call post_download hook
            self._call_hook("post_download", {"source": entry, "filepath": str(dest)})
        except Exception as e:
            # cleanup partial
            try:
                if part.exists():
                    part.unlink()
            except Exception:
                pass
            raise RuntimeError(f"download failed for {url}: {e}")
        # verify sha
        actual = _sha256_file(dest)
        if expected_sha and actual and expected_sha != actual:
            raise RuntimeError(f"sha256 mismatch for {dest}: expected {expected_sha}, got {actual}")
        # optional gpg signature check
        gpg_sig = entry.get("gpg_sig") or entry.get("sig")
        if gpg_sig:
            # if gpg_sig is a url, download it to .sig next to dest
            sigpath = None
            try:
                if gpg_sig.startswith("http://") or gpg_sig.startswith("https://"):
                    signame = Path(gpg_sig).name
                    sigpath = dest_dir / signame
                    part_sig = sigpath.with_suffix(sigpath.suffix + ".part")
                    if self.downloader_cls:
                        dl = self.downloader_cls(cfg=self.cfg)
                        dl.download(gpg_sig, str(part_sig))
                        part_sig.rename(sigpath)
                    else:
                        curl = _which("curl")
                        wget = _which("wget")
                        if curl:
                            _safe_run([curl, "-L", "-o", str(part_sig), gpg_sig])
                            part_sig.rename(sigpath)
                        elif wget:
                            _safe_run([wget, "-O", str(part_sig), gpg_sig])
                            part_sig.rename(sigpath)
                        else:
                            sigpath = None
                else:
                    sigpath = Path(gpg_sig).expanduser()
                if sigpath and sigpath.exists():
                    ok = self._verify_gpg(sigpath, dest)
                    if not ok:
                        raise RuntimeError("gpg signature verification failed")
            except Exception as e:
                raise RuntimeError(f"gpg verification failed: {e}")
        return ResolvedSource(name=name, url=url, filepath=dest, sha256=actual, gpg_sig=(str(sigpath) if gpg_sig else None))

    def _verify_gpg(self, sig_path: Path, file_path: Path) -> bool:
        """
        Verify GPG signature if gpg executable and public keys available (best-effort).
        Returns True if verification succeeded or skipped (no gpg).
        """
        gpg_bin = _which("gpg") or _which("gpg2")
        if not gpg_bin:
            # no gpg installed, skip but log warning
            self._log("warning.gpg", f"gpg not available, skipping signature verification for {file_path}")
            return False
        # run: gpg --verify sig file
        try:
            proc = _safe_run([gpg_bin, "--verify", str(sig_path), str(file_path)], capture_output=True, check=False)
            # exit code 0 means valid
            if proc.returncode == 0:
                return True
            # otherwise log stderr for debugging
            stderr = proc.stderr.decode("utf-8") if proc.stderr else ""
            self._log("warning.gpg", f"gpg verify returned {proc.returncode}", file=str(file_path), stderr=stderr)
            return False
        except Exception as e:
            self._log("error.gpg", f"gpg verify exception: {e}", file=str(file_path))
            return False

    # ---------------- parallel downloads ----------------
    def resolve_sources(self, sources: List[Dict[str, Any]], workdir: Optional[str] = None) -> List[ResolvedSource]:
        """
        Resolve and download multiple sources in parallel. Returns list of ResolvedSource.
        """
        start = time.time()
        dest_dir = Path(workdir or self.cache_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

        # prepare list
        entries = sources or []
        resolved: List[ResolvedSource] = []

        # use logger.progress if available
        progress_ctx = None
        if self.logger:
            try:
                progress_ctx = self.logger.progress(f"Downloading {len(entries)} sources", total=len(entries))
            except Exception:
                progress_ctx = None

        # thread pool
        max_workers = max(1, int(self._cfg_get("core.download_workers", self.max_download_workers)))
        futures = {}
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for e in entries:
                futures[ex.submit(self._resolve_single_source, e, dest_dir)] = e
            completed = 0
            for fut in as_completed(futures):
                entry = futures[fut]
                try:
                    rsrc = fut.result()
                    resolved.append(rsrc)
                    completed += 1
                    # update progress (if rich, the context manager returns a Progress)
                    try:
                        if progress_ctx:
                            # rich Progress instance
                            if hasattr(progress_ctx, "advance"):
                                progress_ctx.advance(0)  # some progress API use add_task; here we just reflect change
                            # else fallback print
                    except Exception:
                        pass
                except Exception as e:
                    # log but continue other downloads
                    self._log("error.download", f"Failed to download {entry.get('url') or entry.get('git')}: {e}", entry=entry)
        # close progress
        try:
            if progress_ctx:
                progress_ctx.__exit__(None, None, None)
        except Exception:
            pass

        if self.logger:
            try:
                self.logger.info("metafile.resolve", f"Resolved {len(resolved)} sources", duration=round(time.time()-start, 3))
            except Exception:
                pass
        return resolved

    # ---------------- apply patches ----------------
    def apply_patches(self, workdir: Path, patches: List[Dict[str, Any]], use_sandbox: bool = True) -> List[Tuple[str, bool, str]]:
        """
        Apply a list of patches. Each patch entry may contain:
         - url / file path / local path
         - strip (p-level)
         - apply_as (patch|git-am|git-apply)
         - sha256
        Returns list of tuples: (patch_identifier, ok_bool, message)
        """
        results: List[Tuple[str, bool, str]] = []
        if not patches:
            return results

        # ensure patch tool available
        patch_bin = _which("patch") or _which("busybox")
        git_bin = _which("git")
        for p in patches:
            ident = p.get("name") or p.get("file") or p.get("url") or "<patch>"
            try:
                self._call_hook("pre_patch", {"patch": p})
                # obtain patch file
                local_patch = None
                if p.get("url") and (p.get("url").startswith("http://") or p.get("url").startswith("https://")):
                    # download to workdir/patches
                    patches_dir = workdir / "patches"
                    patches_dir.mkdir(parents=True, exist_ok=True)
                    fname = Path(p.get("url")).name
                    dst = patches_dir / fname
                    # download (single, using resolve_single)
                    rs = self._resolve_single_source({"url": p.get("url"), "filename": fname}, patches_dir)
                    local_patch = rs.filepath
                elif p.get("file"):
                    fp = Path(p.get("file"))
                    if not fp.exists():
                        raise FileNotFoundError(f"patch file not found: {fp}")
                    local_patch = fp
                else:
                    raise ValueError("no patch url/file specified")
                # verify sha if present
                expected = p.get("sha256")
                if expected:
                    actual = _sha256_file(local_patch)
                    if not actual or actual != expected:
                        raise RuntimeError(f"patch sha mismatch for {local_patch}: expected {expected} got {actual}")
                # apply patch
                apply_as = p.get("apply_as", "patch")
                if apply_as == "patch":
                    if not patch_bin:
                        raise RuntimeError("patch program not available")
                    # use subprocess with safe args: patch -p{p} -i local_patch
                    p_level = str(p.get("p", 1))
                    cmd = [patch_bin, "-p" + p_level, "-i", str(local_patch)]
                    # run in workdir
                    _safe_run(cmd, cwd=str(workdir))
                elif apply_as == "git-apply":
                    if not git_bin:
                        raise RuntimeError("git not available for git-apply")
                    cmd = [git_bin, "apply", "--index", str(local_patch)]
                    _safe_run(cmd, cwd=str(workdir))
                elif apply_as == "git-am":
                    if not git_bin:
                        raise RuntimeError("git not available for git-am")
                    cmd = [git_bin, "am", str(local_patch)]
                    _safe_run(cmd, cwd=str(workdir))
                else:
                    # try generic patcher function if available
                    if self.patcher_fn:
                        ok, msg = self.patcher_fn(str(local_patch), cwd=str(workdir), strip=p.get("p", 1))
                        if not ok:
                            raise RuntimeError(msg or "patcher failed")
                    else:
                        raise RuntimeError(f"unknown patch method: {apply_as}")
                results.append((ident, True, "applied"))
                self._call_hook("post_patch", {"patch": p, "path": str(local_patch)})
            except Exception as e:
                msg = str(e)
                results.append((ident, False, msg))
                # log and continue
                self._log("error.patch", f"Failed to apply patch {ident}: {msg}", patch=ident)
        return results

    # ---------------- prepare environment ----------------
    def prepare_build_env(self, meta: Dict[str, Any]) -> Dict[str, str]:
        """
        Build environment dict for the build, expanding variables from config where possible.
        """
        env = os.environ.copy()
        # base env from meta['environment'] or meta['env']
        env_spec = meta.get("environment") or meta.get("env") or {}
        # if config provides expansion, use it
        try:
            if self.cfg and hasattr(self.cfg, "expand_all"):
                # expand each string via cfg._expand_str if available
                def expand_val(v):
                    if isinstance(v, str):
                        if hasattr(self.cfg, "_expand_str"):
                            return self.cfg._expand_str(v, 10)
                        return v
                    if isinstance(v, dict):
                        return {k: expand_val(x) for k, x in v.items()}
                    if isinstance(v, list):
                        return [expand_val(x) for x in v]
                    return v
                env_spec = expand_val(env_spec)
        except Exception:
            pass
        for k, v in env_spec.items():
            if isinstance(v, (dict, list)):
                env[k] = json.dumps(v, ensure_ascii=False)
            else:
                env[k] = str(v)
        return env

    # ---------------- register deps in DB ----------------
    def register_dependencies(self, pkg_name: str, meta: Dict[str, Any]) -> None:
        """
        If metafile has dependencies sections, register them in DB using add_dep.
        """
        if not self.db:
            return
        deps = meta.get("dependencies") or meta.get("deps") or {}
        # deps could be dict with keys runtime/build, or list
        try:
            if isinstance(deps, dict):
                for dtype, items in deps.items():
                    if isinstance(items, list):
                        for d in items:
                            self.db.add_dep(pkg_name, d, dep_type=dtype)
                    elif isinstance(items, str):
                        self.db.add_dep(pkg_name, items, dep_type=dtype)
            elif isinstance(deps, list):
                for d in deps:
                    self.db.add_dep(pkg_name, d, dep_type="runtime")
        except Exception as e:
            self._log("warning.deps", f"Failed to register deps for {pkg_name}: {e}")

    # ---------------- hook caller ----------------
    def _call_hook(self, name: str, ctx: Dict[str, Any]) -> None:
        if not self.hooks:
            return
        try:
            self.hooks.run(name, ctx)
        except Exception as e:
            # log but continue
            try:
                self._log("warning.hooks", f"hook {name} failed: {e}", hook=name)
            except Exception:
                pass

    # ----------------- main process -----------------
    def process(self, metafile_path: str, workdir: Optional[str] = None, download_profile: Optional[str] = None, apply_patches: bool = True, use_sandbox: bool = True) -> Dict[str, Any]:
        """
        Main entry point: load metafile, download sources, apply patches, prepare env, register in DB.
        Returns a dict with keys: workdir, sources (list of ResolvedSource info), patches (results), env, db_record
        """
        start_total = time.time()
        meta = self.load_metafile(metafile_path)
        name = meta.get("name") or Path(metafile_path).stem
        # create working directory
        base_work = Path(workdir or (self.cache_dir / name))
        base_work.mkdir(parents=True, exist_ok=True)

        # call pre_prepare hook
        self._call_hook("pre_prepare", {"metafile": metafile_path, "meta": meta})

        # resolve sources (parallel)
        sources_spec = meta.get("sources") or meta.get("source") or []
        try:
            t0 = time.time()
            resolved = self.resolve_sources(sources_spec, workdir=str(base_work))
            if self.logger:
                try:
                    self.logger.info("metafile.sources_resolved", f"{len(resolved)} sources", name=name, duration=round(time.time()-t0, 3))
                except Exception:
                    pass
        except Exception as e:
            raise RuntimeError(f"failed to resolve sources: {e}")

        # optionally verify additional integrity if requested (already done per-source)
        # apply patches
        patch_results = []
        if apply_patches and meta.get("patches"):
            try:
                t1 = time.time()
                # choose sandbox usage if available
                if use_sandbox and self.sandbox_cls:
                    sb = self.sandbox_cls(self.cfg)
                    with sb.enter(str(base_work)):
                        patch_results = self.apply_patches(base_work, meta.get("patches", []), use_sandbox=use_sandbox)
                else:
                    patch_results = self.apply_patches(base_work, meta.get("patches", []), use_sandbox=False)
                if self.logger:
                    try:
                        self.logger.info("metafile.patches_applied", f"patches applied", name=name, duration=round(time.time()-t1, 3))
                    except Exception:
                        pass
            except Exception as e:
                # log error but allow caller to decide fail/continue
                self._log("error.patches", f"patching stage failed: {e}", error=str(e))
                # continue

        # prepare build environment
        env = self.prepare_build_env(meta)

        # register package and files in DB
        db_record = None
        try:
            if self.db:
                pid = self.db.record_package(name, version=meta.get("version"), meta=meta, installed_by=os.environ.get("USER"))
                # record files
                for rs in resolved:
                    try:
                        self.db.record_file(name, str(rs.filepath), sha256sum=rs.sha256, size=rs.filepath.stat().st_size if rs.filepath.exists() else None)
                    except Exception:
                        pass
                # register dependencies
                self.register_dependencies(name, meta)
                db_record = {"package_id": pid}
                self.db.record_phase(name, "metafile.process", "ok", meta={"sources": len(resolved), "patches": len(patch_results)})
        except Exception as e:
            self._log("warning.db", f"DB registration failed: {e}", error=str(e))

        # call post_prepare hook
        self._call_hook("post_prepare", {"metafile": metafile_path, "meta": meta, "workdir": str(base_work)})

        # final timing
        total_dur = time.time() - start_total
        result = {
            "workdir": str(base_work),
            "name": name,
            "metafile": metafile_path,
            "sources": [{"name": r.name, "url": r.url, "path": str(r.filepath), "sha256": r.sha256} for r in resolved],
            "patches": [{"patch": p[0], "ok": p[1], "msg": p[2]} for p in patch_results],
            "env": env,
            "db": db_record,
            "duration": total_dur,
        }
        if self.logger:
            try:
                self.logger.info("metafile.done", f"metafile processed: {name}", name=name, duration=round(total_dur, 3))
            except Exception:
                pass
        return result


# ---------------------- convenience module-level API ----------------------
_default_processor: Optional[MetafileProcessor] = None


def get_processor(cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None) -> MetafileProcessor:
    global _default_processor
    if _default_processor is None:
        _default_processor = MetafileProcessor(cfg=cfg, logger=logger, db=db, hooks=hooks)
    return _default_processor


# ---------------------- CLI quick test ----------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Process a newpkg metafile (test runner)")
    parser.add_argument("metafile", help="path to metafile (json/toml/yaml)")
    parser.add_argument("--workdir", help="workdir to use", default=None)
    args = parser.parse_args()
    proc = get_processor()
    try:
        res = proc.process(args.metafile, workdir=args.workdir)
        print(json.dumps(res, indent=2, ensure_ascii=False))
    except Exception as exc:
        print("ERROR:", exc, file=sys.stderr)
        sys.exit(1)
