#!/usr/bin/env python3
# newpkg_metafile.py
"""
newpkg_metafile.py — load / validate / resolve package metafiles for newpkg

Responsibilities:
 - Load a TOML metafile (or multiple) and merge into a single package descriptor
 - Resolve sources (HTTP tarballs, git repos), support profiles from config
 - Verify checksums (sha256) and optionally GPG (if available)
 - Apply patches via newpkg_patcher (optionally inside sandbox)
 - Prepare environment (hooks, env variables) for build and export metadata to DB
 - Respect newpkg_config settings: dry-run, output.json, quiet, download profiles
 - Integrate with newpkg_logger, newpkg_db, newpkg_download, newpkg_hooks, newpkg_sandbox
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# optional integrations (best-effort)
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
    from newpkg_download import get_downloader, NewpkgDownloader
except Exception:
    get_downloader = None
    NewpkgDownloader = None

try:
    from newpkg_patcher import get_patcher, NewpkgPatcher
except Exception:
    get_patcher = None
    NewpkgPatcher = None

try:
    from newpkg_hooks import NewpkgHooks
except Exception:
    NewpkgHooks = None

try:
    from newpkg_sandbox import NewpkgSandbox
except Exception:
    NewpkgSandbox = None

# fallback logger
import logging
_logger = logging.getLogger("newpkg.metafile")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.metafile: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


# ---------- helpers ----------
def _sha256_of_path(p: Union[str, Path]) -> str:
    h = hashlib.sha256()
    with open(str(p), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_toml_like(path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return None
    try:
        import tomllib as _toml  # py3.11+
        data = _toml.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        try:
            import tomli as _toml
            with open(p, "rb") as fh:
                return _toml.load(fh)
        except Exception:
            try:
                import toml as _toml
                return _toml.loads(p.read_text(encoding="utf-8"))
            except Exception:
                _logger.debug("No TOML parser available to read %s", p)
                return None


def _merge_dict(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge b into a (mutates a). Lists replaced, dicts merged."""
    for k, v in b.items():
        if k in a and isinstance(a[k], dict) and isinstance(v, dict):
            _merge_dict(a[k], v)
        else:
            a[k] = v
    return a


@dataclass
class MetaResult:
    ok: bool
    message: str
    data: Dict[str, Any]


# ---------- main class ----------
class NewpkgMetafile:
    CACHE_DIR_DEFAULT = "/var/lib/newpkg/metafiles/cache"

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)

        # logger
        if logger:
            self.logger = logger
        else:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, db) if NewpkgLogger and self.cfg else None
            except Exception:
                self.logger = None

        # db
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)

        # downloader & patcher & hooks & sandbox (deferred)
        self.downloader = None
        self.patcher = None
        self.hooks = None
        self.sandbox = None
        self._init_optional_subsystems()

        # config-driven flags
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))
        self.cache_dir = Path(self._cfg_get("metafile.cache_dir", self.CACHE_DIR_DEFAULT))
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # default download profile
        self.default_profile = self._cfg_get("downloads.default_profile", None)

        # small logger wrapper to unify events
        self._log = self._make_logger()

    def _init_optional_subsystems(self):
        # downloader
        if get_downloader and self.cfg:
            try:
                self.downloader = get_downloader(cfg=self.cfg, logger=self.logger, db=self.db)
            except Exception:
                self.downloader = None
        # patcher
        if get_patcher and self.cfg:
            try:
                self.patcher = get_patcher(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=self.sandbox)
            except Exception:
                self.patcher = None
        # hooks
        try:
            if NewpkgHooks and self.cfg:
                self.hooks = NewpkgHooks.from_config(self.cfg)
        except Exception:
            self.hooks = None
        # sandbox
        try:
            if NewpkgSandbox and self.cfg:
                self.sandbox = NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db)
        except Exception:
            self.sandbox = None

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return os.environ.get(key.upper().replace(".", "_"), default)

    def _make_logger(self):
        def _fn(level: str, event: str, msg: str = "", **meta):
            try:
                if self.logger:
                    fn = getattr(self.logger, level.lower(), None)
                    if fn:
                        fn(event, msg, **meta)
                        return
            except Exception:
                pass
            getattr(_logger, level.lower(), _logger.info)(f"{event}: {msg} - {meta}")
        return _fn

    # ---------------- load & merge ----------------
    def load_metafile(self, path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """Load a single TOML metafile and return dict or None."""
        p = Path(path)
        data = _load_toml_like(p)
        if data is None:
            self._log("warning", "metafile.load.fail", f"Failed to parse metafile {p}", path=str(p))
            return None
        self._log("info", "metafile.load.ok", f"Loaded metafile {p}", path=str(p))
        return data

    def merge_metafiles(self, files: List[Union[str, Path]]) -> Dict[str, Any]:
        """Load multiple metafiles and deep-merge them (later files override earlier)."""
        merged: Dict[str, Any] = {}
        for f in files:
            d = self.load_metafile(f)
            if d:
                _merge_dict(merged, d)
        # normalize basic fields
        if "package" not in merged:
            merged.setdefault("package", {"name": merged.get("name", "unknown"), "version": merged.get("version", "0.0.0")})
        return merged

    # ---------------- validation ----------------
    def validate(self, meta: Dict[str, Any]) -> MetaResult:
        """Basic validation of common fields. Returns MetaResult."""
        required = ["package", "source"]
        pkg = meta.get("package") or {}
        if not pkg.get("name"):
            # allow some flexibility: if top-level name exists, accept
            if meta.get("name"):
                pkg["name"] = meta["name"]
                meta["package"] = pkg
            else:
                return MetaResult(False, "missing package.name", meta)
        # source can be a dict or list
        src = meta.get("source") or {}
        if not src:
            # allow `urls` top-level legacy
            if meta.get("urls") or meta.get("source_urls"):
                meta.setdefault("source", {})["urls"] = meta.get("urls") or meta.get("source_urls") or []
            else:
                # some packages may rely only on git info in sources; allow empty for now
                pass
        return MetaResult(True, "ok", meta)

    # ---------------- resolve & download ----------------
    def resolve_sources(self, meta: Dict[str, Any], destdir: Optional[Union[str, Path]] = None, profile: Optional[str] = None) -> Dict[str, Any]:
        """
        Resolve and download all sources declared in metafile into destdir (or cache).
        Returns metadata about resolved files.
        """
        profile = profile or self.default_profile
        destdir = Path(destdir) if destdir else (self.cache_dir / f"{meta['package']['name']}-{meta['package'].get('version','0')}")
        destdir.mkdir(parents=True, exist_ok=True)
        resolved = {"downloaded": [], "skipped": [], "failed": []}

        # gather urls and git sources
        sources = meta.get("source") or {}
        urls: List[Union[str, Tuple[str, Optional[str]]]] = []
        git_sources: List[Dict[str, Any]] = []

        # support several shapes: urls list, source.urls, source.git[], source.type=git
        if isinstance(sources.get("urls"), list):
            for u in sources.get("urls"):
                # support tuple (url, sha)
                if isinstance(u, (list, tuple)):
                    urls.append((u[0], u[1] if len(u) > 1 else None))
                else:
                    urls.append((u, None))
        # legacy top-level urls
        if isinstance(meta.get("urls"), list):
            for u in meta.get("urls"):
                urls.append((u, None))

        # git entries
        git_raw = sources.get("git") or []
        if isinstance(git_raw, dict):
            git_raw = [git_raw]
        for g in git_raw:
            # expect keys: repo, branch, tag, commit, depth, submodules, clone_dir
            git_sources.append(g)

        # downloader helper
        downloader = self.downloader or (get_downloader(cfg=self.cfg, logger=self.logger, db=self.db) if get_downloader and self.cfg else None)

        # function to attempt candidate urls (consider mirrors from profile)
        def try_download(candidate_url: str, sha: Optional[str], outpath: Path) -> Tuple[bool, Optional[str]]:
            # dry-run
            if self.dry_run:
                self._log("info", "metafile.download.dryrun", f"Would download {candidate_url} -> {outpath}", url=candidate_url, dest=str(outpath))
                return True, None
            try:
                if downloader:
                    res = downloader.download_sync(candidate_url, dest=outpath, sha256=sha, profile=profile)
                    if res.ok:
                        return True, None
                    return False, res.error
                else:
                    # fallback: try curl/wget via subprocess
                    import subprocess, shutil
                    wget = shutil.which("wget")
                    curl = shutil.which("curl")
                    if wget:
                        cmd = [wget, "-O", str(outpath), candidate_url]
                    elif curl:
                        cmd = [curl, "-L", "-o", str(outpath), candidate_url]
                    else:
                        return False, "no-downloader"
                    proc = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if proc.returncode != 0:
                        return False, proc.stderr.strip()
                    # verify sha if provided
                    if sha:
                        got = _sha256_of_path(outpath)
                        if got != sha:
                            return False, f"checksum mismatch: {got}"
                    return True, None
            except Exception as e:
                return False, str(e)

        # download URLs sequentially (could be parallelized)
        for u, sha in urls:
            fname = Path(u).name
            outpath = destdir / fname
            ok, err = try_download(u, sha, outpath)
            if ok:
                resolved["downloaded"].append({"url": u, "path": str(outpath), "sha256": sha})
                self._log("info", "metafile.download.ok", f"Downloaded {u}", url=u, path=str(outpath))
            else:
                resolved["failed"].append({"url": u, "error": err})
                self._log("warning", "metafile.download.fail", f"Failed to download {u}: {err}", url=u, error=err)

        # clone git sources
        for g in git_sources:
            repo = g.get("repo")
            if not repo:
                continue
            clone_dir = g.get("clone_dir") or destdir / (Path(repo).stem)
            clone_dir = Path(clone_dir)
            clone_dir.parent.mkdir(parents=True, exist_ok=True)
            if self.dry_run:
                self._log("info", "metafile.git.dryrun", f"Would clone {repo} -> {clone_dir}", repo=repo, dest=str(clone_dir))
                resolved["downloaded"].append({"git": repo, "path": str(clone_dir), "commit": g.get("commit")})
            else:
                # prefer downloader.git clone
                try:
                    if downloader and isinstance(downloader, NewpkgDownloader):
                        ok, err = downloader.clone_git(repo, dest=clone_dir, branch=g.get("branch"), tag=g.get("tag"),
                                                       commit=g.get("commit"), depth=g.get("depth", 1),
                                                       submodules=bool(g.get("submodules", False)), profile=profile)
                        if ok:
                            resolved["downloaded"].append({"git": repo, "path": str(clone_dir)})
                            self._log("info", "metafile.git.ok", f"Cloned {repo}", repo=repo, path=str(clone_dir))
                        else:
                            resolved["failed"].append({"git": repo, "error": err})
                            self._log("warning", "metafile.git.fail", f"Failed to clone {repo}: {err}", repo=repo, error=err)
                    else:
                        # fallback to git subprocess
                        git_cmd = shutil.which("git") or "git"
                        cmd = [git_cmd, "clone", "--depth", str(g.get("depth", 1))]
                        if g.get("branch"):
                            cmd += ["--branch", g.get("branch")]
                        cmd += [repo, str(clone_dir)]
                        proc = __import__("subprocess").run(cmd, check=False, stdout=__import__("subprocess").PIPE, stderr=__import__("subprocess").PIPE, text=True)
                        if proc.returncode == 0:
                            resolved["downloaded"].append({"git": repo, "path": str(clone_dir)})
                            self._log("info", "metafile.git.ok", f"Cloned {repo}", repo=repo, path=str(clone_dir))
                        else:
                            resolved["failed"].append({"git": repo, "error": proc.stderr.strip()})
                            self._log("warning", "metafile.git.fail", f"Failed to clone {repo}: {proc.stderr.strip()}", repo=repo)
                except Exception as e:
                    resolved["failed"].append({"git": repo, "error": str(e)})
                    self._log("warning", "metafile.git.fail", f"Failed to clone {repo}: {e}", repo=repo, error=str(e))

        # record phase in DB
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=meta.get("package", {}).get("name", "unknown"), phase="metafile.resolve_sources", status="ok", meta={"downloaded": len(resolved["downloaded"]), "failed": len(resolved["failed"])})
        except Exception:
            pass

        # cache manifest
        try:
            manifest = {"meta": meta, "resolved": resolved, "ts": time.time()}
            mfpath = destdir / "newpkg-resolved.json"
            mfpath.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        except Exception:
            pass

        return resolved

    # ---------------- verify sources & patches ----------------
    def verify_sources(self, meta: Dict[str, Any], resolved: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify downloaded files and git clones. If sha256 provided, verify.
        Returns dict {ok: bool, details: [...]}
        """
        details = []
        ok = True

        # files
        for item in resolved.get("downloaded", []):
            if "path" in item:
                p = Path(item["path"])
                exp = item.get("sha256") or (item.get("sha256_hint") if "sha256_hint" in item else None)
                if not p.exists():
                    ok = False
                    details.append({"path": str(p), "status": "missing"})
                    continue
                if exp:
                    try:
                        got = _sha256_of_path(p)
                        if got != exp:
                            ok = False
                            details.append({"path": str(p), "status": "checksum-mismatch", "expected": exp, "got": got})
                        else:
                            details.append({"path": str(p), "status": "ok"})
                    except Exception as e:
                        ok = False
                        details.append({"path": str(p), "status": "error", "error": str(e)})
                else:
                    details.append({"path": str(p), "status": "exists"})
            elif "git" in item:
                # check repo path exists
                p = Path(item.get("path", ""))
                if not p.exists():
                    ok = False
                    details.append({"git": item.get("git"), "status": "missing"})
                else:
                    details.append({"git": item.get("git"), "status": "ok", "path": str(p)})

        # record phase
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=meta.get("package", {}).get("name", "unknown"), phase="metafile.verify_sources", status="ok" if ok else "error", meta={"details": details})
        except Exception:
            pass

        return {"ok": ok, "details": details}

    # ---------------- apply patches ----------------
    def apply_patches(self, meta: Dict[str, Any], workdir: Union[str, Path], use_sandbox: Optional[bool] = None) -> Dict[str, Any]:
        """
        Apply patches declared in meta[[patches]] inside workdir.
        Returns summary dict.
        """
        workdir = Path(workdir)
        patches = meta.get("patches") or []
        if isinstance(patches, dict):
            patches = [patches]

        if not patches:
            return {"status": "noop", "applied": 0, "details": []}

        # prepare patch list (files or urls)
        patch_paths: List[Path] = []
        for p in patches:
            # local file
            if p.get("file"):
                patch_paths.append(Path(p["file"]))
            elif p.get("url"):
                # download to cache
                url = p["url"]
                fname = Path(url).name
                dest = self.cache_dir / fname
                # try download (reusing resolve_sources logic)
                if self.downloader:
                    if self.dry_run:
                        self._log("info", "metafile.patch.dryrun", f"Would download patch {url}", url=url)
                    else:
                        res = self.downloader.download_sync(url, dest=dest, sha256=p.get("sha256"), profile=self.default_profile)
                        if res.ok:
                            patch_paths.append(dest)
                        else:
                            self._log("warning", "metafile.patch.download_fail", f"Failed to download patch {url}: {res.error}", url=url, error=res.error)
                else:
                    # minimal fallback
                    try:
                        import urllib.request
                        if self.dry_run:
                            self._log("info", "metafile.patch.dryrun", f"Would download patch {url}", url=url)
                        else:
                            urllib.request.urlretrieve(url, str(dest))
                            patch_paths.append(dest)
                    except Exception as e:
                        self._log("warning", "metafile.patch.download_fail", f"Failed to download patch {url}: {e}", url=url, error=str(e))

        # optionally verify patch sha256 before applying
        verified_paths: List[Path] = []
        for p in patch_paths:
            expected = None
            # find expected sha in meta patches for this basename
            for pm in patches:
                if pm.get("file") and Path(pm.get("file")).name == p.name:
                    expected = pm.get("sha256")
                if pm.get("url") and Path(pm.get("url")).name == p.name:
                    expected = pm.get("sha256")
            if expected:
                try:
                    got = _sha256_of_path(p)
                    if got != expected:
                        self._log("error", "metafile.patch.sha_mismatch", f"Patch checksum mismatch for {p}", path=str(p), expected=expected, got=got)
                        # do not apply mismatched patch
                        continue
                except Exception as e:
                    self._log("warning", "metafile.patch.sha_error", f"Could not compute sha for patch {p}: {e}", path=str(p))
                    continue
            verified_paths.append(p)

        # apply with patcher
        patcher = self.patcher or (get_patcher(cfg=self.cfg, logger=self.logger, db=self.db, sandbox=self.sandbox) if get_patcher and self.cfg else None)
        if not patcher:
            # fallback: attempt `patch -p1` directly
            results = []
            for p in verified_paths:
                if self.dry_run:
                    self._log("info", "metafile.patch.dryrun", f"Would apply {p}", patch=str(p))
                    results.append({"patch": str(p), "status": "dryrun"})
                    continue
                cmd = f"patch -p1 < {shlex_quote(str(p))}"
                rc = __import__("subprocess").run(cmd, shell=True, cwd=str(workdir)).returncode
                results.append({"patch": str(p), "status": "ok" if rc == 0 else "fail", "rc": rc})
            return {"status": "partial", "details": results}

        # use patcher.apply_all
        try:
            summary = patcher.apply_all([str(x) for x in verified_paths], workdir=workdir, use_sandbox=(use_sandbox if use_sandbox is not None else True))
            return summary
        except Exception as e:
            self._log("error", "metafile.patch.apply_exception", f"Patcher raised: {e}", error=str(e))
            return {"status": "error", "error": str(e)}

    # ---------------- prepare environment & hooks ----------------
    def prepare_environment(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare environment dict suitable to pass to subprocesses/builds.
        Merges config env, metafile env, and profile overrides.
        """
        env = {}
        try:
            if self.cfg and hasattr(self.cfg, "as_env"):
                env.update(self.cfg.as_env())
        except Exception:
            pass
        # file-provided env (strings). Expand simple placeholders via config.expand_all if available.
        mf_env = meta.get("environment") or meta.get("env") or {}
        for k, v in mf_env.items():
            env[k] = str(v)
        # build flags from profiles or meta
        profiles = self._cfg_get("profiles", {}) or {}
        prof_name = meta.get("profile") or self.default_profile
        if prof_name and isinstance(profiles, dict) and profiles.get(prof_name):
            prof_env = profiles.get(prof_name) or {}
            for k, v in prof_env.items():
                # only uppercase keys look appropriate for env
                env[str(k)] = str(v)
        # record in DB
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=meta.get("package", {}).get("name", "unknown"), phase="metafile.prepare_environment", status="ok", meta={"env_keys": list(env.keys())})
        except Exception:
            pass
        return env

    # ---------------- export to DB / manifest ----------------
    def export_to_db(self, meta: Dict[str, Any], resolved: Dict[str, Any], destdir: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
        """
        Save final resolved metadata into DB (packages table + files).
        """
        pkg = meta.get("package") or {"name": meta.get("name", "unknown")}
        pkgname = pkg.get("name")
        pkgver = pkg.get("version")
        try:
            if self.db:
                pid = self.db.add_package(pkgname, version=pkgver, category=meta.get("category"), metadata=meta)
                # record files
                for it in resolved.get("downloaded", []):
                    if "path" in it:
                        try:
                            self.db.record_file(pkgname, it["path"], sha256=it.get("sha256"))
                        except Exception:
                            pass
                self._log("info", "metafile.export_db", f"Exported package {pkgname} to DB", package=pkgname)
            else:
                self._log("warning", "metafile.no_db", "No DB instance available to export metadata", package=pkgname)
        except Exception as e:
            self._log("error", "metafile.export_db_fail", f"Failed to export to DB: {e}", error=str(e))
            return {"ok": False, "error": str(e)}
        return {"ok": True, "package": pkgname}

    # ---------------- orchestrator ----------------
    def process(self, metafile_paths: List[Union[str, Path]], workdir: Optional[Union[str, Path]] = None, download_profile: Optional[str] = None, apply_patches: bool = True) -> Dict[str, Any]:
        """
        High-level convenience: merge metafiles, validate, resolve sources into workdir (or cache),
        verify, apply patches, prepare env and export to DB.
        Returns summary dict with detailed steps.
        """
        start = time.time()
        merged = self.merge_metafiles(metafile_paths)
        v = self.validate(merged)
        if not v.ok:
            self._log("error", "metafile.validate.fail", f"Metafile validation failed: {v.message}", message=v.message)
            return {"ok": False, "error": v.message}

        # determine workdir
        if workdir:
            wd = Path(workdir)
            wd.mkdir(parents=True, exist_ok=True)
        else:
            wd = self.cache_dir / f"{merged['package']['name']}-{merged['package'].get('version','0')}"
            wd.mkdir(parents=True, exist_ok=True)

        # run pre-prepare hooks
        if self.hooks and hasattr(self.hooks, "run_hooks"):
            try:
                self.hooks.run_hooks("pre_prepare", merged)
            except Exception as e:
                self._log("warning", "metafile.hooks.pre_prepare.fail", f"pre_prepare hooks failed: {e}", error=str(e))

        # resolve sources
        resolved = self.resolve_sources(merged, destdir=wd, profile=download_profile)
        # verify
        verification = self.verify_sources(merged, resolved)
        if not verification.get("ok"):
            self._log("error", "metafile.verify.fail", "Source verification failed", details=verification.get("details"))
            return {"ok": False, "error": "verify_failed", "details": verification.get("details")}

        # apply patches
        patch_summary = {"status": "noop", "applied": 0}
        if apply_patches:
            patch_summary = self.apply_patches(merged, workdir=wd, use_sandbox=True)

        # prepare env
        env = self.prepare_environment(merged)

        # post-prepare hooks
        if self.hooks and hasattr(self.hooks, "run_hooks"):
            try:
                self.hooks.run_hooks("post_prepare", merged)
            except Exception as e:
                self._log("warning", "metafile.hooks.post_prepare.fail", f"post_prepare hooks failed: {e}", error=str(e))

        # export to DB
        exported = self.export_to_db(merged, resolved, destdir=wd)

        duration = time.time() - start
        summary = {
            "ok": True,
            "package": merged.get("package", {}),
            "resolved": resolved,
            "verification": verification,
            "patch": patch_summary,
            "env_keys": list(env.keys()),
            "exported": exported,
            "duration": duration,
        }

        # record top-level phase
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=merged.get("package", {}).get("name", "unknown"), phase="metafile.process", status="ok", meta={"duration": duration})
        except Exception:
            pass

        if self.json_out:
            print(json.dumps(summary, indent=2))

        return summary


# small helper: shlex.quote wrapper for older pythons & readability
def shlex_quote(s: str) -> str:
    try:
        import shlex as _sh
        return _sh.quote(s)
    except Exception:
        return "'" + s.replace("'", "'\"'\"'") + "'"


# CLI demo
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(prog="newpkg-metafile", description="Load and resolve newpkg metafiles")
    p.add_argument("metafiles", nargs="+", help="metafile.toml files to merge and process")
    p.add_argument("--workdir", help="workdir to resolve sources into (default: cache)")
    p.add_argument("--no-patches", action="store_true", help="do not apply patches")
    p.add_argument("--profile", help="download profile")
    args = p.parse_args()

    cfg = init_config() if init_config else None
    logger = NewpkgLogger.from_config(cfg, NewpkgDB(cfg)) if NewpkgLogger and cfg else None
    db = NewpkgDB(cfg) if NewpkgDB and cfg else None
    mf = NewpkgMetafile(cfg=cfg, logger=logger, db=db)
    res = mf.process(args.metafiles, workdir=args.workdir, download_profile=args.profile, apply_patches=(not args.no_patches))
    print(json.dumps(res, indent=2))
