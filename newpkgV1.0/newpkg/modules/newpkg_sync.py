#!/usr/bin/env python3
# newpkg_sync.py
"""
newpkg_sync.py — repository synchronization manager (revised)

Features:
 - discover & sync multiple git repositories in parallel
 - integration with newpkg_api (registers api.sync)
 - progress reporting via newpkg_logger.progress (uses rich when available)
 - optional sandboxed execution for safety (uses newpkg_sandbox if available)
 - mirror and shallow clone support
 - incremental sync with backup when local changes are detected
 - retry logic for transient network failures
 - detailed phase recording to DB and hooks integration
 - writes JSON reports (per-run) to configurable dir
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

# fallback simple logger
import logging
_log = logging.getLogger("newpkg.sync")
if not _log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.sync: %(message)s"))
    _log.addHandler(h)
_log.setLevel(logging.INFO)

# constants / defaults
DEFAULT_SYNC_DIR = "/var/cache/newpkg/sync"
DEFAULT_REPORT_DIR = "/var/log/newpkg/sync"
DEFAULT_THREADS = 4
DEFAULT_RETRIES = 3
DEFAULT_RETRY_DELAY = 5  # seconds
DEFAULT_SHALLOW_DEPTH = 1

# dataclasses
@dataclass
class RepoSpec:
    name: str                 # logical name (used for folder)
    url: str                  # git url
    branch: Optional[str] = None
    mirror: bool = False      # mirror clone semantics
    shallow: Optional[int] = None  # depth for shallow clone (None means full)
    path: Optional[str] = None     # optional explicit path
    auth: Optional[Dict[str, Any]] = None  # auth hints (not used directly)
    extra: Optional[Dict[str, Any]] = None # any extra fields

@dataclass
class RepoResult:
    name: str
    url: str
    path: str
    success: bool
    changed: bool
    commit_before: Optional[str]
    commit_after: Optional[str]
    duration_s: float
    error: Optional[str]
    meta: Dict[str, Any]

# utility functions
def _safe_makedirs(p: Path, mode: int = 0o700):
    try:
        p.mkdir(parents=True, exist_ok=True)
        try:
            p.chmod(mode)
        except Exception:
            pass
    except Exception:
        pass

def _shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)

def _run_cmd(cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """
    Run a command and return (rc, stdout, stderr). Accepts env override.
    """
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout.decode("utf-8", errors="ignore")
        err = proc.stderr.decode("utf-8", errors="ignore")
        return proc.returncode, out, err
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout: {e}"
    except Exception as e:
        return 1, "", str(e)

def _sanitize_repo_dir_name(name: str) -> str:
    # Replace path separators, dots etc. Keep it safe and short
    safe = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name)
    return safe[:255]

def _is_transient_git_error(stderr: str) -> bool:
    transient_indicators = [
        "Could not resolve host",
        "Network is unreachable",
        "Connection timed out",
        "Temporary failure",
        "TLS handshake timeout",
        "Connection reset by peer",
        "Failed to connect",
        "503 Service Unavailable",
        "502 Bad Gateway",
        "timed out",
    ]
    s = (stderr or "").lower()
    return any(ind.lower() in s for ind in transient_indicators)

# main class
class SyncManager:
    def __init__(self, cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, hooks: Optional[Any] = None, sandbox: Optional[Any] = None):
        # config + integration
        self.api = None
        if get_api:
            try:
                self.api = get_api()
                # ensure init
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

        # directories & defaults from config
        sync_dir = None
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                sync_dir = self.cfg.get("sync.dir")
        except Exception:
            sync_dir = None
        self.sync_dir = Path(sync_dir or os.environ.get("NEWPKG_SYNC_DIR", DEFAULT_SYNC_DIR)).expanduser()
        _safe_makedirs(self.sync_dir)

        report_dir = None
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                report_dir = self.cfg.get("sync.report_dir")
        except Exception:
            report_dir = None
        self.report_dir = Path(report_dir or os.environ.get("NEWPKG_SYNC_REPORT_DIR", DEFAULT_REPORT_DIR)).expanduser()
        _safe_makedirs(self.report_dir)

        threads = DEFAULT_THREADS
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                threads = int(self.cfg.get("sync.threads") or self.cfg.get("general.threads") or threads)
        except Exception:
            pass
        self.threads = threads

        self.retries = int(os.environ.get("NEWPKG_SYNC_RETRIES", DEFAULT_RETRIES))
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.retries = int(self.cfg.get("sync.retries") or self.retries)
        except Exception:
            pass

        self.retry_delay = int(os.environ.get("NEWPKG_SYNC_RETRY_DELAY", DEFAULT_RETRY_DELAY))
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.retry_delay = int(self.cfg.get("sync.retry_delay") or self.retry_delay)
        except Exception:
            pass

        self.default_shallow = int(os.environ.get("NEWPKG_SYNC_SHALLOW", DEFAULT_SHALLOW_DEPTH))
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.default_shallow = int(self.cfg.get("sync.default_shallow") or self.default_shallow)
        except Exception:
            pass

        # register with api
        try:
            if self.api:
                self.api.sync = self
        except Exception:
            pass

    # ---------------- helpers for git ops ----------------
    def _git_clone(self, spec: RepoSpec, dest: Path, mirror: bool = False, shallow: Optional[int] = None) -> Tuple[bool, str]:
        """
        Clone repository to dest. Returns (ok, message).
        """
        # ensure dest parent exists
        _safe_makedirs(dest.parent)
        cmd = ["git", "clone", "--quiet"]
        if mirror:
            cmd = ["git", "clone", "--mirror", spec.url, str(dest)]
        else:
            if shallow and shallow > 0:
                cmd += ["--depth", str(shallow)]
            if spec.branch:
                cmd += ["-b", spec.branch]
            cmd += [spec.url, str(dest)]
        rc, out, err = _run_cmd(cmd, cwd=None)
        if rc != 0:
            return False, err or out
        return True, out or ""

    def _git_fetch(self, repo_path: Path, spec: RepoSpec) -> Tuple[bool, str, str]:
        """
        Fetch updates in existing repo. Returns (ok, stdout, stderr).
        """
        # ensure repo exists
        if not repo_path.exists():
            return False, "", "repo path does not exist"
        # if mirror repo, run remote update
        if spec.mirror:
            cmd = ["git", "remote", "update"]
            rc, out, err = _run_cmd(cmd, cwd=str(repo_path))
            return (rc == 0), out, err
        # else do fetch on branch
        cmd = ["git", "fetch", "--all", "--quiet"]
        rc, out, err = _run_cmd(cmd, cwd=str(repo_path))
        if rc != 0:
            return False, out, err
        # optionally reset to remote branch head
        if spec.branch:
            cmd2 = ["git", "rev-parse", "--abbrev-ref", "HEAD"]
            _, cur_branch, _ = _run_cmd(cmd2, cwd=str(repo_path))
            cur_branch = cur_branch.strip()
            if cur_branch != spec.branch:
                # try to checkout branch
                rc2, out2, err2 = _run_cmd(["git", "checkout", spec.branch], cwd=str(repo_path))
                if rc2 != 0:
                    return False, out2, err2
            rc3, out3, err3 = _run_cmd(["git", "reset", "--hard", f"origin/{spec.branch}"], cwd=str(repo_path))
            return (rc3 == 0), out3, err3
        return True, out, err

    def _git_get_head(self, repo_path: Path) -> Optional[str]:
        if not repo_path.exists():
            return None
        rc, out, err = _run_cmd(["git", "rev-parse", "HEAD"], cwd=str(repo_path))
        if rc == 0:
            return out.strip()
        return None

    def _repo_has_local_changes(self, repo_path: Path) -> bool:
        rc, out, err = _run_cmd(["git", "status", "--porcelain"], cwd=str(repo_path))
        if rc != 0:
            # assume no changes if error
            return False
        return bool(out.strip())

    def _backup_repo(self, repo_path: Path) -> Optional[str]:
        """
        Create a tarball backup of repo_path, return backup path or None.
        """
        try:
            ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            target = Path(tempfile.mkdtemp(prefix="newpkg-sync-backup-")) / f"{repo_path.name}-{ts}.tar.xz"
            # use tar to compress
            rc, out, err = _run_cmd(["tar", "cJf", str(target), "-C", str(repo_path.parent), repo_path.name])
            if rc == 0:
                return str(target)
            else:
                return None
        except Exception:
            return None

    # ---------------- per-repo worker ----------------
    def _sync_one_repo(self, spec: RepoSpec, use_sandbox: bool = False, timeout: Optional[int] = None) -> RepoResult:
        """
        Sync a single repository described by RepoSpec.
        """
        t0 = time.time()
        name = spec.name or Path(spec.url).stem
        safe_name = _sanitize_repo_dir_name(name)
        repo_path = Path(spec.path) if spec.path else (self.sync_dir / safe_name)
        repo_path = repo_path.expanduser()
        start_commit = None
        end_commit = None
        changed = False
        err_msg = None

        # record pre hook
        if self.hooks:
            try:
                self.hooks.run("pre_clone", {"name": name, "url": spec.url, "path": str(repo_path)})
            except Exception:
                pass

        # ensure parent
        _safe_makedirs(repo_path.parent)

        # clone if missing
        if not repo_path.exists() or not (repo_path / ".git").exists():
            # attempt clone with retries
            attempt = 0
            ok = False
            last_err = ""
            while attempt <= self.retries:
                attempt += 1
                try:
                    if use_sandbox and self.sandbox and hasattr(self.sandbox, "run_in_sandbox"):
                        # perform cloning inside sandbox by running git clone command there
                        try:
                            # create a temp dir inside sync_dir for sandbox to write
                            tmp_parent = repo_path.parent
                            _safe_makedirs(tmp_parent)
                            cmd = ["git", "clone"]
                            if spec.mirror:
                                cmd = ["git", "clone", "--mirror", spec.url, str(repo_path)]
                            else:
                                if spec.shallow is not None:
                                    cmd += ["--depth", str(spec.shallow)]
                                elif spec.shallow is None and self.default_shallow:
                                    # only apply default shallow if specified in config
                                    pass
                                if spec.branch:
                                    cmd += ["-b", spec.branch]
                                cmd += [spec.url, str(repo_path)]
                            res = self.sandbox.run_in_sandbox(cmd, use_fakeroot=False)
                            rc = getattr(res, "rc", None)
                            out = getattr(res, "stdout", "") or ""
                            err = getattr(res, "stderr", "") or ""
                            if rc == 0:
                                ok = True
                                break
                            last_err = err or out
                        except Exception as e:
                            last_err = str(e)
                    else:
                        shallow = spec.shallow if (spec.shallow is not None) else (self.default_shallow if spec.shallow is not None else None)
                        ok, out_err = self._git_clone(spec, repo_path, mirror=spec.mirror, shallow=spec.shallow if spec.shallow is not None else None)
                        if ok:
                            out_err = out_err or ""
                            break
                        last_err = out_err or "clone failed"
                except Exception as e:
                    last_err = str(e)
                # if transient, wait and retry
                if _is_transient_git_error(last_err) and attempt <= self.retries:
                    time.sleep(self.retry_delay)
                    continue
                else:
                    break
            if not ok:
                err_msg = last_err
                # record failure phase
                if self.db:
                    try:
                        self.db.record_phase(name, "sync.clone.fail", "fail", meta={"url": spec.url, "error": err_msg})
                    except Exception:
                        pass
                # post hook
                if self.hooks:
                    try:
                        self.hooks.run("post_clone", {"name": name, "url": spec.url, "path": str(repo_path), "ok": False, "error": err_msg})
                    except Exception:
                        pass
                duration = time.time() - t0
                return RepoResult(name=name, url=spec.url, path=str(repo_path), success=False, changed=False, commit_before=None, commit_after=None, duration_s=duration, error=err_msg, meta={})

        # repo exists: fetch updates
        start_commit = self._git_get_head(repo_path)
        # check local uncommitted changes
        local_changes = self._repo_has_local_changes(repo_path)
        if local_changes:
            # backup before attempting fetch/pull
            if self.hooks:
                try:
                    self.hooks.run("pre_backup_repo", {"name": name, "path": str(repo_path)})
                except Exception:
                    pass
            backup_path = self._backup_repo(repo_path)
            if self.hooks:
                try:
                    self.hooks.run("post_backup_repo", {"name": name, "path": str(repo_path), "backup": backup_path})
                except Exception:
                    pass

        # now perform fetch/pull with retries
        attempt = 0
        fetch_ok = False
        last_err = ""
        while attempt <= self.retries:
            attempt += 1
            try:
                # run pre_pull hook
                if self.hooks:
                    try:
                        self.hooks.run("pre_pull", {"name": name, "path": str(repo_path)})
                    except Exception:
                        pass
                ok, out, err = self._git_fetch(repo_path, spec)
                if ok:
                    fetch_ok = True
                    break
                last_err = err or out
            except Exception as e:
                last_err = str(e)
            if _is_transient_git_error(last_err) and attempt <= self.retries:
                time.sleep(self.retry_delay)
                continue
            else:
                break
        if not fetch_ok:
            err_msg = last_err
            if self.db:
                try:
                    self.db.record_phase(name, "sync.fetch.fail", "fail", meta={"error": err_msg})
                except Exception:
                    pass
            if self.hooks:
                try:
                    self.hooks.run("post_pull", {"name": name, "path": str(repo_path), "ok": False, "error": err_msg})
                except Exception:
                    pass
            duration = time.time() - t0
            return RepoResult(name=name, url=spec.url, path=str(repo_path), success=False, changed=False, commit_before=start_commit, commit_after=None, duration_s=duration, error=err_msg, meta={})

        # post pull hook
        if self.hooks:
            try:
                self.hooks.run("post_pull", {"name": name, "path": str(repo_path), "ok": True})
            except Exception:
                pass

        # after fetch, compute head again
        end_commit = self._git_get_head(repo_path)
        changed = (start_commit != end_commit)

        # record success phase
        try:
            if self.db:
                self.db.record_phase(name, "sync.repo", "ok", meta={"url": spec.url, "changed": changed, "commit_before": start_commit, "commit_after": end_commit})
        except Exception:
            pass

        # post-success hook
        if self.hooks:
            try:
                self.hooks.run("post_sync", {"name": name, "path": str(repo_path), "changed": changed, "commit_before": start_commit, "commit_after": end_commit})
            except Exception:
                pass

        duration = time.time() - t0
        return RepoResult(name=name, url=spec.url, path=str(repo_path), success=True, changed=changed, commit_before=start_commit, commit_after=end_commit, duration_s=duration, error=None, meta={})

    # ---------------- top-level sync ----------------
    def sync_repos(self, specs: List[RepoSpec], parallel: Optional[int] = None, use_sandbox: Optional[bool] = None, timeout_per_repo: Optional[int] = None, report_name: Optional[str] = None, quiet: bool = False) -> Dict[str, Any]:
        """
        Sync a list of RepoSpec in parallel. Returns a report dict.
        """
        if parallel is None:
            parallel = self.threads
        if use_sandbox is None:
            use_sandbox = bool(self.cfg and hasattr(self.cfg, "get") and self.cfg.get("sync.sandbox"))

        if self.logger:
            self.logger.info("sync.start", f"starting sync of {len(specs)} repos", meta={"count": len(specs)})
        else:
            _log.info("starting sync of %d repos", len(specs))

        results: List[RepoResult] = []
        report_meta = {"started_at": time.time(), "spec_count": len(specs), "parallel": parallel}

        # progress context (best-effort)
        progress_ctx = (self.logger.progress if self.logger and hasattr(self.logger, "progress") else None)
        pctx = None
        try:
            if progress_ctx:
                pctx = progress_ctx("Syncing repositories", total=len(specs))
                pctx.__enter__()
                use_progress = True
            else:
                pctx = None
                use_progress = False
        except Exception:
            pctx = None
            use_progress = False

        # run threads
        with ThreadPoolExecutor(max_workers=parallel) as ex:
            futs = {}
            for spec in specs:
                fut = ex.submit(self._sync_one_repo, spec, use_sandbox, timeout_per_repo)
                futs[fut] = spec
            try:
                for fut in as_completed(futs):
                    spec = futs[fut]
                    try:
                        res = fut.result()
                    except Exception as e:
                        # failure in worker
                        res = RepoResult(name=spec.name, url=spec.url, path=str(spec.path if spec.path else (self.sync_dir / _sanitize_repo_dir_name(spec.name))), success=False, changed=False, commit_before=None, commit_after=None, duration_s=0.0, error=str(e), meta={})
                    results.append(res)
                    # update progress
                    if use_progress:
                        try:
                            # try add/update small progress
                            pctx.update(0, advance=1)
                        except Exception:
                            pass
            finally:
                if pctx:
                    try:
                        pctx.__exit__(None, None, None)
                    except Exception:
                        pass

        # build consolidated report
        report = {
            "report_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "count": len(results),
            "results": [asdict(r) for r in results],
            "meta": report_meta,
        }

        # save report to file
        rname = report_name or f"sync-report-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
        try:
            _safe_makedirs(self.report_dir)
            report_path = self.report_dir / rname
            report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            report_meta["report_path"] = str(report_path)
        except Exception:
            try:
                # fallback to tmp
                tmp = Path(tempfile.mkdtemp(prefix="newpkg-sync-")) / rname
                tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
                report_meta["report_path"] = str(tmp)
            except Exception:
                report_meta["report_path"] = None

        # record top-level phase
        try:
            if self.db:
                self.db.record_phase(None, "sync.run", "ok", meta={"count": len(results), "report": report_meta.get("report_path")})
        except Exception:
            pass

        if self.logger:
            self.logger.info("sync.done", f"completed sync of {len(results)} repos", meta={"report": report_meta.get("report_path")})
        else:
            _log.info("completed sync of %d repos", len(results))

        # create quick summary
        summary = {
            "total": len(results),
            "success": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
            "changed": sum(1 for r in results if r.changed),
            "report": report_meta.get("report_path"),
            "results": [asdict(r) for r in results],
        }
        return summary

    # convenience: sync from repo descriptors (dicts)
    def sync_from_descriptors(self, descriptors: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        specs: List[RepoSpec] = []
        for d in descriptors:
            name = d.get("name") or Path(d.get("url", "")).stem
            specs.append(RepoSpec(
                name=name,
                url=d.get("url"),
                branch=d.get("branch"),
                mirror=bool(d.get("mirror", False)),
                shallow=d.get("shallow", None),
                path=d.get("path", None),
                auth=d.get("auth", None),
                extra=d.get("extra", None),
            ))
        return self.sync_repos(specs, **kwargs)

# module-level singleton accessor
_default_sync: Optional[SyncManager] = None
_sync_lock = threading.RLock()

def get_sync(cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, hooks: Optional[Any] = None, sandbox: Optional[Any] = None) -> SyncManager:
    global _default_sync
    with _sync_lock:
        if _default_sync is None:
            _default_sync = SyncManager(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)
        return _default_sync

# CLI runner for debugging
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-sync", description="sync repositories")
    p.add_argument("manifest", nargs="?", help="JSON file with list of descriptors or '-' for stdin")
    p.add_argument("--threads", type=int, help="parallel threads")
    p.add_argument("--report", help="report filename")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    mgr = get_sync()
    descriptors = []
    if args.manifest and args.manifest != "-":
        try:
            text = Path(args.manifest).read_text(encoding="utf-8")
            descriptors = json.loads(text)
        except Exception as e:
            print("failed to read manifest:", e)
            raise SystemExit(2)
    else:
        import sys
        try:
            text = sys.stdin.read()
            descriptors = json.loads(text) if text.strip() else []
        except Exception:
            descriptors = []

    if args.threads:
        mgr.threads = args.threads

    res = mgr.sync_from_descriptors(descriptors, report_name=args.report, quiet=args.quiet)
    pprint.pprint(res)
