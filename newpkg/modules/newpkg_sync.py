#!/usr/bin/env python3
# newpkg_sync.py
"""
newpkg_sync.py

Repository sync manager for Newpkg.

Features:
 - add_repo / remove_repo / list_repos (in-memory + optional persisted config)
 - clone_repo, fetch_repo, sync_repo (clone+fetch+merge+verify)
 - sync_all with parallel limit and progress
 - rollback_repo (reset to commit + optional backup tar)
 - get_repo_info (commit, branch, ahead/behind)
 - verify_repo via GPG tags/commit verification (best-effort)
 - state cache in ~/.cache/newpkg/sync/repos_state.json
 - integration with NewpkgLogger (logger.info/error), NewpkgDB (record_phase),
   HooksManager (pre_sync_all/post_sync_all, pre_sync_repo/post_sync_repo), Sandbox (sandbox.run)
 - structured result objects for CLI / API

Design notes:
 - Best-effort GPG verification: tries 'git verify-commit' and 'git tag -v' where applicable.
 - Network retries configurable via cfg (sync.retries, sync.retry_delay)
 - Dry-run supported (reports actions without executing destructive steps)
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# optional imports from project
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
    from newpkg_hooks import HooksManager
except Exception:
    HooksManager = None

try:
    from newpkg_sandbox import Sandbox
except Exception:
    Sandbox = None

# constants
CACHE_DIR = Path.home() / ".cache" / "newpkg" / "sync"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = CACHE_DIR / "repos_state.json"
REPOS_FILE = CACHE_DIR / "repos_config.json"

DEFAULT_PARALLEL = 4
DEFAULT_RETRIES = 2
DEFAULT_RETRY_DELAY = 3  # seconds


@dataclass
class SyncStep:
    phase: str
    status: str
    msg: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RepoResult:
    name: str
    url: str
    path: Optional[str] = None
    status: str = "unknown"
    commit: Optional[str] = None
    branch: Optional[str] = None
    steps: List[SyncStep] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


class SyncError(Exception):
    pass


class NewpkgSync:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.logger = logger or (NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None)
        self.db = db or (NewpkgDB(cfg) if NewpkgDB and cfg is not None else None)
        self.hooks = hooks or (HooksManager(cfg, self.logger, self.db) if HooksManager and cfg is not None else None)
        self.sandbox = sandbox or (Sandbox(cfg, self.logger, self.db) if Sandbox and cfg is not None else None)

        # settings
        self.repos_dir = Path(self._cfg_get("sync.repos_dir", os.environ.get("NEWPKG_SYNC_REPOS", "./repos")))
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        self.parallel = int(self._cfg_get("sync.parallel", os.environ.get("NEWPKG_SYNC_PARALLEL", DEFAULT_PARALLEL)))
        self.retries = int(self._cfg_get("sync.retries", os.environ.get("NEWPKG_SYNC_RETRIES", DEFAULT_RETRIES)))
        self.retry_delay = int(self._cfg_get("sync.retry_delay", os.environ.get("NEWPKG_SYNC_RETRY_DELAY", DEFAULT_RETRY_DELAY)))
        self.verify_gpg = bool(self._cfg_get("sync.verify_gpg", os.environ.get("NEWPKG_SYNC_VERIFY_GPG", False)))
        self.json_output = bool(self._cfg_get("sync.json_output", False))

        # internal repo registry: name -> dict(url, branch, options)
        self._repos_lock = threading.Lock()
        self.repos: Dict[str, Dict[str, Any]] = self._load_repos_config()
        # state cache loaded from disk
        self.state = self._load_state()

    # ---------------- util / logging ----------------
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        return default

    def _log(self, level: str, event: str, message: str = "", **meta):
        if self.logger:
            try:
                fn = getattr(self.logger, level.lower(), None)
                if fn:
                    fn(event, message, **meta)
                    return
            except Exception:
                pass
        # fallback
        print(f"[{level}] {event}: {message}")

    def _record_db(self, repo: str, phase: str, status: str, meta: Optional[Dict[str, Any]] = None):
        if not self.db:
            return
        try:
            if hasattr(self.db, "record_phase"):
                self.db.record_phase(repo, phase, status, log_path=None)
        except Exception:
            pass

    # ---------------- config/state persistence ----------------
    def _load_repos_config(self) -> Dict[str, Dict[str, Any]]:
        try:
            if REPOS_FILE.exists():
                return json.loads(REPOS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def _save_repos_config(self):
        try:
            REPOS_FILE.parent.mkdir(parents=True, exist_ok=True)
            REPOS_FILE.write_text(json.dumps(self.repos, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _load_state(self) -> Dict[str, Any]:
        try:
            if STATE_FILE.exists():
                return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def _save_state(self):
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            STATE_FILE.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        except Exception:
            pass

    # ---------------- repo registry ----------------
    def add_repo(self, name: str, url: str, branch: Optional[str] = None, options: Optional[Dict[str, Any]] = None) -> bool:
        with self._repos_lock:
            self.repos[name] = {"url": url, "branch": branch or "main", "options": options or {}}
            self._save_repos_config()
        self._log("info", "sync.repo.add", f"Added repo {name} -> {url}", name=name, url=url, branch=branch)
        return True

    def remove_repo(self, name: str) -> bool:
        with self._repos_lock:
            if name in self.repos:
                self.repos.pop(name)
                self._save_repos_config()
                self._log("info", "sync.repo.remove", f"Removed repo {name}", name=name)
                return True
        return False

    def list_repos(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.repos)

    # ---------------- low-level git helpers ----------------
    def _repo_path(self, name: str) -> Path:
        return (self.repos_dir / name).resolve()

    def _run_git(self, args: List[str], cwd: Optional[Path] = None, use_sandbox: bool = True, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        cmd = ["git"] + args
        if use_sandbox and self.sandbox:
            try:
                # sandbox.run expects full argv list
                res = self.sandbox.run(cmd, cwd=str(cwd) if cwd else None, timeout=timeout)
                return res.rc, res.out or "", res.err or ""
            except Exception:
                pass
        # fallback to local subprocess
        try:
            proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout)
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as e:
            return 124, "", f"timeout: {e}"
        except Exception as e:
            return 1, "", str(e)

    def _git_try(self, args: List[str], cwd: Optional[Path], phase: str, repo: str, retries: Optional[int] = None) -> Tuple[int, str, str]:
        retries = self.retries if retries is None else retries
        last = (1, "", "no-run")
        for attempt in range(retries + 1):
            rc, out, err = self._run_git(args, cwd=cwd)
            if rc == 0:
                return rc, out, err
            last = (rc, out, err)
            time.sleep(self.retry_delay)
            self._log("warning", "sync.git.retry", f"Retrying git {' '.join(args)} for {repo} (attempt {attempt+1})", repo=repo, args=args)
        return last

    # ---------------- repo operations ----------------
    def clone_repo(self, name: str, shallow: bool = True, branch: Optional[str] = None, dry_run: bool = False) -> RepoResult:
        meta = self.repos.get(name)
        if not meta:
            raise SyncError(f"unknown repo {name}")
        url = meta["url"]
        branch = branch or meta.get("branch") or "main"
        dst = self._repo_path(name)
        res = RepoResult(name=name, url=url, path=str(dst))
        if dry_run:
            res.status = "dry-run"
            res.steps.append(SyncStep("clone", "skipped", "dry-run", {"dst": str(dst)}))
            return res

        if dst.exists() and any(dst.iterdir()):
            res.steps.append(SyncStep("clone", "skipped", "destination exists", {"dst": str(dst)}))
            res.status = "exists"
            return res

        dst.parent.mkdir(parents=True, exist_ok=True)
        args = ["clone"]
        if shallow:
            args += ["--depth", "1"]
        args += ["--branch", branch, url, str(dst)]
        self._log("info", "sync.clone.start", f"Cloning {name} from {url}", name=name, url=url, dst=str(dst))
        self._record_db(name, "sync.clone", "start")
        rc, out, err = self._git_try(args, cwd=None, phase="clone", repo=name)
        step = SyncStep("clone", "ok" if rc == 0 else "error", err.strip() if rc != 0 else "cloned", {"rc": rc})
        res.steps.append(step)
        res.status = "ok" if rc == 0 else "error"
        if rc == 0:
            # record commit & branch
            c_rc, c_out, _ = self._run_git(["rev-parse", "HEAD"], cwd=dst)
            b_rc, b_out, _ = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=dst)
            res.commit = c_out.strip() if c_rc == 0 else None
            res.branch = b_out.strip() if b_rc == 0 else branch
            self.state[name] = {"last_sync": datetime.utcnow().isoformat() + "Z", "commit": res.commit, "branch": res.branch}
            self._save_state()
            self._record_db(name, "sync.clone", "ok")
            self._log("info", "sync.clone.ok", f"Cloned {name}", name=name, commit=res.commit, branch=res.branch)
        else:
            self._record_db(name, "sync.clone", "error")
            self._log("error", "sync.clone.fail", f"Clone failed for {name}: {err}", name=name, stderr=err)
        return res

    def fetch_repo(self, name: str, dry_run: bool = False) -> RepoResult:
        meta = self.repos.get(name)
        if not meta:
            raise SyncError(f"unknown repo {name}")
        dst = self._repo_path(name)
        res = RepoResult(name=name, url=meta["url"], path=str(dst))
        if not dst.exists():
            res.steps.append(SyncStep("fetch", "missing", "repo not cloned", {"dst": str(dst)}))
            res.status = "missing"
            return res
        if dry_run:
            res.steps.append(SyncStep("fetch", "skipped", "dry-run"))
            res.status = "dry-run"
            return res

        self._log("info", "sync.fetch.start", f"Fetching {name}", name=name)
        self._record_db(name, "sync.fetch", "start")
        rc, out, err = self._git_try(["fetch", "--all", "--tags"], cwd=dst, phase="fetch", repo=name)
        if rc == 0:
            res.steps.append(SyncStep("fetch", "ok", "fetched"))
            # update commit/branch info
            c_rc, c_out, _ = self._run_git(["rev-parse", "HEAD"], cwd=dst)
            b_rc, b_out, _ = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=dst)
            res.commit = c_out.strip() if c_rc == 0 else None
            res.branch = b_out.strip() if b_rc == 0 else None
            self.state[name] = {"last_sync": datetime.utcnow().isoformat() + "Z", "commit": res.commit, "branch": res.branch}
            self._save_state()
            res.status = "ok"
            self._record_db(name, "sync.fetch", "ok")
            self._log("info", "sync.fetch.ok", f"Fetched {name}", name=name)
        else:
            res.steps.append(SyncStep("fetch", "error", err.strip(), {"rc": rc}))
            res.status = "error"
            self._record_db(name, "sync.fetch", "error")
            self._log("error", "sync.fetch.fail", f"Fetch failed for {name}: {err}", name=name, stderr=err)
        return res

    def _fast_forward_merge(self, dst: Path, remote_branch: str = "origin/main") -> Tuple[int, str]:
        # attempt fast-forward merge
        rc, out, err = self._run_git(["merge", "--ff-only", remote_branch], cwd=dst)
        return rc, err

    def sync_repo(self, name: str, dry_run: bool = False, shallow: bool = True, verify_gpg: Optional[bool] = None) -> RepoResult:
        """
        Full sync for a single repo: clone if needed, fetch, merge (fast-forward), verify.
        Returns RepoResult with detailed steps.
        """
        verify_gpg = self.verify_gpg if verify_gpg is None else verify_gpg
        meta = self.repos.get(name)
        if not meta:
            raise SyncError(f"unknown repo {name}")

        self._log("info", "sync.repo.start", f"Starting sync for {name}", name=name)
        result = RepoResult(name=name, url=meta["url"], path=str(self._repo_path(name)))
        # pre-hook
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("pre_sync_repo", pkg_dir=str(self._repo_path(name)))
        except Exception:
            pass

        # clone if necessary
        if not Path(result.path).exists() or not any(Path(result.path).iterdir()):
            clone_res = self.clone_repo(name, shallow=shallow, branch=meta.get("branch"), dry_run=dry_run)
            result.steps.extend(clone_res.steps)
            if clone_res.status == "error":
                result.status = "error"
                return result

        # fetch
        fetch_res = self.fetch_repo(name, dry_run=dry_run)
        result.steps.extend(fetch_res.steps)
        if fetch_res.status == "error":
            result.status = "error"
            return result

        if dry_run:
            result.steps.append(SyncStep("merge", "skipped", "dry-run"))
            result.status = "dry-run"
            return result

        dst = Path(result.path)
        # determine remote tracking branch
        branch = meta.get("branch") or "main"
        remote_branch = f"origin/{branch}"
        # attempt ff-only merge
        rc, err = self._fast_forward_merge(dst, remote_branch)
        if rc == 0:
            result.steps.append(SyncStep("merge", "ok", f"fast-forwarded to {remote_branch}"))
            # update commit
            c_rc, c_out, _ = self._run_git(["rev-parse", "HEAD"], cwd=dst)
            result.commit = c_out.strip() if c_rc == 0 else None
            result.branch = branch
            result.status = "ok"
            self.state[name] = {"last_sync": datetime.utcnow().isoformat() + "Z", "commit": result.commit, "branch": result.branch}
            self._save_state()
            self._log("info", "sync.merge.ok", f"Merged {name} -> {remote_branch}", name=name)
            self._record_db(name, "sync.merge", "ok")
        else:
            # non-fast-forward or conflicts; attempt safe merge strategy: create new branch and merge manually (best-effort)
            result.steps.append(SyncStep("merge", "warn", "fast-forward failed, attempting safe merge", {"err": err}))
            # try to reset to remote branch (safe policy: record but do not force-reset unless config allows)
            allow_force = bool(self._cfg_get("sync.allow_force_reset", False))
            if allow_force:
                # backup current state
                backup = self._backup_repo(dst, name)
                rc2, out2, err2 = self._run_git(["reset", "--hard", remote_branch], cwd=dst)
                if rc2 == 0:
                    result.steps.append(SyncStep("merge", "ok", f"force reset to {remote_branch}", {"backup": backup}))
                    c_rc, c_out, _ = self._run_git(["rev-parse", "HEAD"], cwd=dst)
                    result.commit = c_out.strip() if c_rc == 0 else None
                    result.branch = branch
                    result.status = "ok"
                    self.state[name] = {"last_sync": datetime.utcnow().isoformat() + "Z", "commit": result.commit, "branch": result.branch}
                    self._save_state()
                    self._record_db(name, "sync.merge", "ok")
                else:
                    result.steps.append(SyncStep("merge", "error", "force reset failed", {"err": err2}))
                    result.status = "error"
                    self._record_db(name, "sync.merge", "error")
                    return result
            else:
                result.status = "conflict"
                self._log("warning", "sync.merge.conflict", f"Merge conflict or non-ff for {name}", name=name)
                self._record_db(name, "sync.merge", "conflict")
                return result

        # verification (GPG) if requested
        if verify_gpg:
            try:
                v_ok, v_msg = self.verify_repo(name)
                if v_ok:
                    result.steps.append(SyncStep("verify", "ok", v_msg))
                    self._record_db(name, "sync.verify", "ok")
                else:
                    result.steps.append(SyncStep("verify", "warn", v_msg))
                    self._record_db(name, "sync.verify", "warn")
            except Exception as e:
                result.steps.append(SyncStep("verify", "error", str(e)))
                self._record_db(name, "sync.verify", "error")

        # post-hook
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("post_sync_repo", pkg_dir=str(dst))
        except Exception:
            pass

        return result

    def sync_all(self, dry_run: bool = False, names: Optional[List[str]] = None, parallel: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Sync all configured repos (or subset `names`) in parallel up to `parallel`.
        Returns list of result dicts.
        """
        names = names or list(self.repos.keys())
        parallel = int(parallel or self.parallel or DEFAULT_PARALLEL)
        self._log("info", "sync.all.start", f"Starting sync_all for {len(names)} repos", total=len(names))
        # pre-hooks
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("pre_sync_all")
        except Exception:
            pass

        results: List[Dict[str, Any]] = []

        def _worker(n):
            try:
                r = self.sync_repo(n, dry_run=dry_run)
                return r
            except Exception as e:
                rr = RepoResult(name=n, url=self.repos.get(n, {}).get("url", ""), path=str(self._repo_path(n)))
                rr.status = "error"
                rr.steps.append(SyncStep("sync", "error", str(e)))
                return rr

        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
            futs = {ex.submit(_worker, n): n for n in names}
            for fut in concurrent.futures.as_completed(futs):
                rr: RepoResult = fut.result()
                results.append(self._reporesult_to_dict(rr))

        # post-hooks
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("post_sync_all")
        except Exception:
            pass

        self._log("info", "sync.all.done", f"Sync_all finished (repos={len(results)})")
        return results

    def get_repo_info(self, name: str) -> Dict[str, Any]:
        meta = self.repos.get(name)
        if not meta:
            raise SyncError(f"unknown repo {name}")
        dst = self._repo_path(name)
        info = {"name": name, "url": meta["url"], "path": str(dst)}
        if not dst.exists():
            info["status"] = "missing"
            return info
        c_rc, c_out, _ = self._run_git(["rev-parse", "HEAD"], cwd=dst)
        b_rc, b_out, _ = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=dst)
        info["commit"] = c_out.strip() if c_rc == 0 else None
        info["branch"] = b_out.strip() if b_rc == 0 else None
        # ahead/behind
        ab_rc, ab_out, _ = self._run_git(["rev-list", "--left-right", "--count", f"HEAD...origin/{info.get('branch') or 'main'}"], cwd=dst)
        if ab_rc == 0:
            try:
                left, right = [int(x) for x in ab_out.strip().split()]
                info["ahead"] = left
                info["behind"] = right
            except Exception:
                pass
        return info

    def verify_repo(self, name: str) -> Tuple[bool, str]:
        """
        Best-effort verification: check tags/signatures or verify-commit where possible.
        Returns (ok, message).
        """
        meta = self.repos.get(name)
        if not meta:
            return False, "unknown repo"
        dst = self._repo_path(name)
        if not dst.exists():
            return False, "not cloned"
        # try verify-commit HEAD
        rc, out, err = self._run_git(["verify-commit", "HEAD"], cwd=dst)
        if rc == 0:
            return True, "verify-commit ok"
        # try verify tag on HEAD if tag exists
        # find tags that point to HEAD
        rc2, tags_out, _ = self._run_git(["tag", "--points-at", "HEAD"], cwd=dst)
        tags = tags_out.strip().splitlines() if rc2 == 0 else []
        for t in tags:
            vr, vout, verr = self._run_git(["tag", "-v", t], cwd=dst)
            if vr == 0:
                return True, f"tag {t} verified"
        # fallback: no signatures
        return False, "no-signature-found"

    # ---------------- rollback / backup ----------------
    def _backup_repo(self, dst: Path, name: str) -> Optional[str]:
        # create tar.xz backup of the repository working tree before destructive ops
        try:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            out = CACHE_DIR / f"{name}-backup-{ts}.tar.xz"
            with tarfile.open(out, "w:xz") as tar:
                tar.add(dst, arcname=name)
            self._log("info", "sync.backup", f"Created backup for {name}", path=str(out))
            return str(out)
        except Exception as e:
            self._log("warning", "sync.backup.fail", f"Backup failed for {name}: {e}")
            return None

    def rollback_repo(self, name: str, commit: str, create_backup: bool = True) -> RepoResult:
        meta = self.repos.get(name)
        if not meta:
            raise SyncError(f"unknown repo {name}")
        dst = self._repo_path(name)
        res = RepoResult(name=name, url=meta["url"], path=str(dst))
        if not dst.exists():
            res.steps.append(SyncStep("rollback", "error", "repo not present"))
            res.status = "missing"
            return res

        if create_backup:
            bkp = self._backup_repo(dst, name)
            if bkp:
                res.steps.append(SyncStep("rollback", "info", "backup_created", {"backup": bkp}))

        # perform hard reset to commit
        rc, out, err = self._run_git(["reset", "--hard", commit], cwd=dst)
        if rc == 0:
            res.steps.append(SyncStep("rollback", "ok", f"reset to {commit}"))
            res.status = "ok"
            self.state[name] = {"last_sync": datetime.utcnow().isoformat() + "Z", "commit": commit, "branch": self.state.get(name, {}).get("branch")}
            self._save_state()
            self._record_db(name, "sync.rollback", "ok", {"commit": commit})
            self._log("info", "sync.rollback.ok", f"Rolled back {name} to {commit}", name=name, commit=commit)
        else:
            res.steps.append(SyncStep("rollback", "error", err.strip()))
            res.status = "error"
            self._record_db(name, "sync.rollback", "error", {"commit": commit})
            self._log("error", "sync.rollback.fail", f"Rollback failed for {name}: {err}", name=name, stderr=err)
        return res

    # ---------------- helpers / serialization ----------------
    def _reporesult_to_dict(self, rr: RepoResult) -> Dict[str, Any]:
        return {
            "name": rr.name,
            "url": rr.url,
            "path": rr.path,
            "status": rr.status,
            "commit": rr.commit,
            "branch": rr.branch,
            "steps": [{"phase": s.phase, "status": s.status, "msg": s.msg, "meta": s.meta} for s in rr.steps],
            "meta": rr.meta,
        }

    def export_state(self) -> str:
        self._save_state()
        return str(STATE_FILE)

    # ---------------- CLI convenience ----------------
    @classmethod
    def cli_main(cls, argv: Optional[List[str]] = None):
        import argparse
        import sys

        p = argparse.ArgumentParser(prog="newpkg-sync", description="Sync multiple git repositories for newpkg")
        p.add_argument("cmd", choices=["add", "remove", "list", "clone", "fetch", "sync", "sync-all", "info", "rollback", "export-state"])
        p.add_argument("--name", help="repository logical name")
        p.add_argument("--url", help="git url")
        p.add_argument("--branch", help="branch to track")
        p.add_argument("--dry-run", action="store_true")
        p.add_argument("--parallel", type=int, help="parallel workers for sync-all")
        p.add_argument("--commit", help="commit for rollback")
        p.add_argument("--json", action="store_true")
        args = p.parse_args(argv)

        cfg = None
        if init_config:
            try:
                cfg = init_config()
            except Exception:
                cfg = None

        db = NewpkgDB(cfg) if NewpkgDB and cfg is not None else None
        logger = NewpkgLogger.from_config(cfg, db) if NewpkgLogger and cfg is not None else None
        hooks = HooksManager(cfg, logger, db) if HooksManager and cfg is not None else None
        sandbox = Sandbox(cfg, logger, db) if Sandbox and cfg is not None else None

        sync = cls(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)

        if args.cmd == "add":
            if not args.name or not args.url:
                print("add requires --name and --url")
                return 2
            sync.add_repo(args.name, args.url, branch=args.branch)
            print("added")
            return 0
        if args.cmd == "remove":
            if not args.name:
                print("--name required")
                return 2
            ok = sync.remove_repo(args.name)
            print("removed" if ok else "not found")
            return 0
        if args.cmd == "list":
            print(json.dumps(sync.list_repos(), indent=2))
            return 0
        if args.cmd == "clone":
            if not args.name:
                print("--name required")
                return 2
            rr = sync.clone_repo(args.name, shallow=True, branch=args.branch, dry_run=args.dry_run)
            out = sync._reporesult_to_dict(rr)
            print(json.dumps(out, indent=2) if args.json else out)
            return 0
        if args.cmd == "fetch":
            if not args.name:
                print("--name required")
                return 2
            rr = sync.fetch_repo(args.name, dry_run=args.dry_run)
            print(json.dumps(sync._reporesult_to_dict(rr), indent=2) if args.json else sync._reporesult_to_dict(rr))
            return 0
        if args.cmd == "sync":
            if not args.name:
                print("--name required")
                return 2
            rr = sync.sync_repo(args.name, dry_run=args.dry_run)
            print(json.dumps(sync._reporesult_to_dict(rr), indent=2) if args.json else sync._reporesult_to_dict(rr))
            return 0
        if args.cmd == "sync-all":
            res = sync.sync_all(dry_run=args.dry_run, parallel=args.parallel)
            print(json.dumps(res, indent=2) if args.json else res)
            return 0
        if args.cmd == "info":
            if not args.name:
                print("--name required")
                return 2
            info = sync.get_repo_info(args.name)
            print(json.dumps(info, indent=2))
            return 0
        if args.cmd == "rollback":
            if not args.name or not args.commit:
                print("--name and --commit required")
                return 2
            rr = sync.rollback_repo(args.name, args.commit)
            print(json.dumps(sync._reporesult_to_dict(rr), indent=2) if args.json else sync._reporesult_to_dict(rr))
            return 0
        if args.cmd == "export-state":
            path = sync.export_state()
            print(path)
            return 0
        p.print_help()
        return 1


if __name__ == "__main__":
    NewpkgSync.cli_main()
