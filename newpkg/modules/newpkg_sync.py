#!/usr/bin/env python3
# newpkg_sync.py
"""
newpkg_sync.py — synchronize multiple git repositories for newpkg

Features:
 - Manage a list of repositories (add/remove/list)
 - Clone, fetch, and (optionally) update branches for many repos in parallel
 - Respect global config: general.dry_run, output.quiet, output.json, general.cache_dir
 - Integrates with NewpkgLogger, NewpkgDB, NewpkgHooks and NewpkgSandbox when available
 - Record phases in DB via record_phase
 - Save per-repo JSON reports to /var/log/newpkg/sync/
 - Use logger.perf_timer when available
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
    from newpkg_hooks import NewpkgHooks
except Exception:
    NewpkgHooks = None

try:
    from newpkg_sandbox import NewpkgSandbox
except Exception:
    NewpkgSandbox = None

# fallback stdlib logger for internal fallback
import logging
_logger = logging.getLogger("newpkg.sync")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.sync: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


# small dataclasses for reports
@dataclass
class RepoSpec:
    name: str
    url: str
    branch: Optional[str] = None
    dst: Optional[str] = None  # destination path on disk
    opts: Dict[str, Any] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class RepoReport:
    name: str
    url: str
    dst: str
    action: str
    rc: int
    duration: float
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    meta: Dict[str, Any] = None

    def to_dict(self):
        return asdict(self)


class NewpkgSync:
    DEFAULT_STATE = "~/.cache/newpkg/sync_state.json"
    DEFAULT_REPORT_DIR = "/var/log/newpkg/sync"

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None):
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

        # hooks
        self.hooks = hooks or (NewpkgHooks.from_config(self.cfg, self.logger, self.db) if NewpkgHooks and self.cfg else None)

        # sandbox
        self.sandbox = sandbox or (NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgSandbox and self.cfg else None)

        # runtime flags from config
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))
        # concurrency
        cpu = os.cpu_count() or 1
        self.parallel = int(self._cfg_get("sync.parallel_jobs", min(4, cpu)))
        # retry
        self.retries = int(self._cfg_get("sync.retries", 1))
        self.retry_delay = float(self._cfg_get("sync.retry_delay", 1.0))

        # state and reports
        self.state_file = Path(os.path.expanduser(self._cfg_get("sync.state_file", self.DEFAULT_STATE)))
        self.report_dir = Path(self._cfg_get("sync.report_dir", self.DEFAULT_REPORT_DIR))
        self.report_dir.mkdir(parents=True, exist_ok=True)

        # internal
        self._lock = threading.Lock()
        self._state: Dict[str, Any] = self._load_state()
        # perf_timer decorator if available
        self._perf_timer = getattr(self.logger, "perf_timer", None) if self.logger else None

        # wrapper for logging
        self._log = self._make_logger()

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        env_key = key.upper().replace(".", "_")
        return os.environ.get(env_key, default)

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

    # ---------------- state management ----------------
    def _load_state(self) -> Dict[str, Any]:
        try:
            if self.state_file.exists():
                return json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {"repos": {}}

    def _save_state(self):
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(json.dumps(self._state, indent=2), encoding="utf-8")
            self._log("debug", "sync.state.save", f"Saved state to {self.state_file}", path=str(self.state_file))
        except Exception as e:
            self._log("warning", "sync.state.save_fail", f"Failed saving state: {e}", error=str(e))

    def add_repo(self, name: str, url: str, branch: Optional[str] = None, dst: Optional[str] = None, opts: Optional[Dict[str, Any]] = None):
        """Add or update repository spec to state."""
        with self._lock:
            self._state.setdefault("repos", {})
            repo = {"url": url, "branch": branch, "dst": dst, "opts": opts or {}}
            self._state["repos"][name] = repo
            self._save_state()
        self._log("info", "sync.repo.add", f"Added repo {name}", name=name, url=url)

    def remove_repo(self, name: str):
        with self._lock:
            if "repos" in self._state and name in self._state["repos"]:
                self._state["repos"].pop(name, None)
                self._save_state()
                self._log("info", "sync.repo.remove", f"Removed repo {name}", name=name)
                return True
        return False

    def list_repos(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._state.get("repos", {}))

    # ----------------- low-level helpers -----------------
    def _git_available(self) -> bool:
        return bool(shutil.which("git"))

    def _exec_git(self, args: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, use_sandbox: bool = False, timeout: Optional[float] = None) -> Tuple[int, str, str]:
        """
        Execute git command; if sandbox is available and use_sandbox True, delegate.
        Returns (rc, stdout, stderr).
        """
        cmd = ["git"] + args
        if self.dry_run:
            self._log("info", "sync.git.dryrun", f"DRY-RUN: {' '.join(cmd)}", cmd=cmd, cwd=cwd)
            return 0, "", ""
        if use_sandbox and self.sandbox:
            try:
                res = self.sandbox.run_in_sandbox(cmd, cwd=cwd, captures=True, env=env, timeout=timeout)
                return res.rc, res.stdout or "", res.stderr or ""
            except Exception as e:
                return 255, "", str(e)
        # run locally
        try:
            proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as e:
            return 124, "", f"timeout: {e}"
        except Exception as e:
            return 255, "", str(e)

    def _write_report(self, repo_name: str, report: RepoReport) -> Path:
        ts = int(time.time())
        fname = f"{repo_name}-{ts}.json"
        path = self.report_dir / fname
        try:
            path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
            self._log("info", "sync.report.write", f"Wrote report for {repo_name} to {path}", path=str(path))
        except Exception as e:
            self._log("warning", "sync.report.fail", f"Failed to write report: {e}", error=str(e))
        return path

    # ----------------- repo operations -----------------
    def _sync_single(self, name: str, spec: Dict[str, Any], update: bool = True, use_sandbox: bool = True, timeout: Optional[float] = None) -> RepoReport:
        """
        Clone or fetch and optionally update branch. Returns RepoReport.
        """
        start = time.time()
        repo_url = spec.get("url")
        branch = spec.get("branch") or "master"
        dst = spec.get("dst") or os.path.abspath(os.path.join(self.state_file.parent, "repos", name))
        Path(dst).mkdir(parents=True, exist_ok=True)
        action = "noop"
        rc = 0
        out = ""
        err = ""

        # run pre-sync repo hooks
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("pre_sync_repo", [f"pre_sync_repo:{name}"], cwd=dst, json_output=False)
        except Exception:
            pass

        # determine whether clone needed
        git_dir = Path(dst) / ".git"
        if not git_dir.exists():
            action = "clone"
            self._log("info", "sync.repo.clone.start", f"Cloning {name} from {repo_url} to {dst}", name=name, url=repo_url, dst=dst)
            rc, out, err = self._exec_git(["clone", "--branch", branch, "--", repo_url, dst], cwd=None, use_sandbox=use_sandbox, timeout=timeout)
        else:
            action = "fetch"
            self._log("info", "sync.repo.fetch.start", f"Fetching {name} in {dst}", name=name, dst=dst)
            rc, out, err = self._exec_git(["-C", dst, "fetch", "--all", "--prune"], cwd=dst, use_sandbox=use_sandbox, timeout=timeout)
            # optionally fast-forward branch
            if rc == 0 and update:
                rc2, out2, err2 = self._exec_git(["-C", dst, "checkout", branch], cwd=dst, use_sandbox=use_sandbox, timeout=timeout)
                if rc2 == 0:
                    rc3, out3, err3 = self._exec_git(["-C", dst, "pull", "--ff-only", "origin", branch], cwd=dst, use_sandbox=use_sandbox, timeout=timeout)
                    # prefer last rc
                    rc = rc3
                    out += ("\n" + (out2 or "")) + ("\n" + (out3 or ""))
                    err += ("\n" + (err2 or "")) + ("\n" + (err3 or ""))
                else:
                    # cannot checkout target branch
                    rc = rc2
                    err += "\n" + (err2 or "")

        duration = time.time() - start
        report = RepoReport(name=name, url=repo_url, dst=dst, action=action, rc=rc, duration=duration, stdout=out, stderr=err, meta={"branch": branch})
        # save report file
        self._write_report(name, report)

        # run post-sync hooks
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("post_sync_repo", [f"post_sync_repo:{name}"], cwd=dst, json_output=False)
        except Exception:
            pass

        # record DB phase
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=name, phase="sync.repo", status="ok" if rc == 0 else "error", meta={"action": action, "rc": rc, "duration": duration})
        except Exception:
            pass

        # update stored state (last_sync ts)
        with self._lock:
            self._state.setdefault("repos", {})
            r = self._state["repos"].setdefault(name, {})
            r["last_sync"] = int(time.time())
            r["dst"] = dst
            r["url"] = repo_url
            r["branch"] = branch
            self._save_state()

        # return
        return report

    def sync_repo(self, name: str, update: bool = True, use_sandbox: bool = True, timeout: Optional[float] = None) -> RepoReport:
        """Public wrapper with retries."""
        spec = self._state.get("repos", {}).get(name)
        if not spec:
            self._log("warning", "sync.repo.notfound", f"Repo {name} not found in state", name=name)
            return RepoReport(name=name, url="", dst="", action="missing", rc=127, duration=0.0, stdout="", stderr="not found", meta={})
        last_exc = None
        for attempt in range(max(1, self.retries)):
            report = self._sync_single(name, spec, update=update, use_sandbox=use_sandbox, timeout=timeout)
            if report.rc == 0:
                return report
            last_exc = report
            time.sleep(self.retry_delay)
        # failed after retries
        return last_exc

    def sync_all(self, names: Optional[List[str]] = None, update: bool = True, use_sandbox: bool = True, timeout: Optional[float] = None, parallel: Optional[int] = None) -> Dict[str, Any]:
        """
        Sync multiple repositories in parallel.
        names: list of repo names to sync; if None, sync all known repos.
        Returns dict with per-repo reports.
        """
        if names is None:
            names = list(self._state.get("repos", {}).keys())
        if not names:
            return {"ok": True, "reports": [], "duration": 0.0}

        parallel = parallel or self.parallel
        start = time.time()

        # run pre-sync-all hooks
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("pre_sync_all", [], json_output=False)
        except Exception:
            pass

        reports: List[RepoReport] = []
        with ThreadPoolExecutor(max_workers=parallel) as ex:
            futs = {ex.submit(self.sync_repo, n, update, use_sandbox, timeout): n for n in names}
            for fut in as_completed(futs):
                name = futs[fut]
                try:
                    rep = fut.result()
                except Exception as e:
                    rep = RepoReport(name=name, url="", dst="", action="error", rc=254, duration=0.0, stdout="", stderr=str(e), meta={})
                reports.append(rep)

        duration = time.time() - start

        # run post-sync-all hooks
        try:
            if self.hooks and hasattr(self.hooks, "execute_safe"):
                self.hooks.execute_safe("post_sync_all", [], json_output=False)
        except Exception:
            pass

        # record overall phase
        try:
            if self.db and hasattr(self.db, "record_phase"):
                ok_count = sum(1 for r in reports if r.rc == 0)
                self.db.record_phase(package="system", phase="sync.all", status="ok" if ok_count == len(reports) else "partial", meta={"total": len(reports), "ok": ok_count, "duration": duration})
        except Exception:
            pass

        # prepare structured result and optionally print JSON/human output
        result = {"ok": True, "duration": duration, "reports": [r.to_dict() for r in reports]}
        if self.json_out:
            print(json.dumps(result, indent=2))
        else:
            for r in reports:
                self._log("info", "sync.report.summary", f"{r.name}: {r.action} rc={r.rc} dur={r.duration:.2f}s", repo=r.name, rc=r.rc, duration=r.duration)
        return result

    def verify_repo(self, name: str, use_signature: bool = True, use_sandbox: bool = True, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Verify repository integrity: e.g. check last signed tag/commit.
        Returns dict with verification info.
        """
        spec = self._state.get("repos", {}).get(name)
        if not spec:
            return {"ok": False, "error": "not_found", "name": name}
        dst = spec.get("dst") or os.path.abspath(os.path.join(self.state_file.parent, "repos", name))
        if not Path(dst).exists():
            return {"ok": False, "error": "missing_checkout", "path": dst}

        # try to use git verify-tag or show-signature on last commit
        if not self._git_available():
            return {"ok": False, "error": "git_missing"}

        if self.dry_run:
            self._log("info", "sync.verify.dryrun", f"Would verify {name}", name=name, path=dst)
            return {"ok": True, "simulated": True}

        if use_signature:
            rc, out, err = self._exec_git(["-C", dst, "log", "-1", "--show-signature"], cwd=dst, use_sandbox=use_sandbox, timeout=timeout)
            ok = rc == 0
            res = {"ok": ok, "rc": rc, "stdout": out, "stderr": err}
            self._log("info", "sync.verify", f"Verification for {name}: ok={ok}", name=name, rc=rc)
            return res
        else:
            # fallback: confirm HEAD exists
            rc, out, err = self._exec_git(["-C", dst, "rev-parse", "HEAD"], cwd=dst, use_sandbox=use_sandbox, timeout=timeout)
            ok = rc == 0
            return {"ok": ok, "rc": rc, "stdout": out, "stderr": err}

    def rollback_repo(self, name: str, to_ref: str, use_sandbox: bool = True, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Rollback repository working tree to a given ref (commit/tag). Saves a backup tar.xz before doing it.
        """
        spec = self._state.get("repos", {}).get(name)
        if not spec:
            return {"ok": False, "error": "not_found"}
        dst = spec.get("dst") or os.path.abspath(os.path.join(self.state_file.parent, "repos", name))
        if not Path(dst).exists():
            return {"ok": False, "error": "missing_checkout"}

        backup = None
        try:
            backup = tempfile.NamedTemporaryFile(prefix=f"{name}-backup-", suffix=".tar.xz", delete=False)
            backup.close()
            shutil.make_archive(backup.name.replace(".tar.xz", ""), "xztar", root_dir=dst)
            self._log("info", "sync.rollback.backup", f"Created backup {backup.name}", backup=str(backup.name))
        except Exception as e:
            self._log("warning", "sync.rollback.backup_fail", f"Backup failed: {e}", error=str(e))

        if self.dry_run:
            return {"ok": True, "simulated": True, "backup": backup.name if backup else None}

        # perform reset
        rc, out, err = self._exec_git(["-C", dst, "reset", "--hard", to_ref], cwd=dst, use_sandbox=use_sandbox, timeout=timeout)
        res = {"ok": rc == 0, "rc": rc, "stdout": out, "stderr": err, "backup": backup.name if backup else None}
        self._log("info", "sync.rollback.done", f"Rollback {name} -> {to_ref} rc={rc}", repo=name, rc=rc)
        return res

    # ----------------- CLI -----------------
    @staticmethod
    def cli():
        import argparse
        p = argparse.ArgumentParser(prog="newpkg-sync", description="Sync multiple git repos for newpkg")
        p.add_argument("--add", nargs=2, metavar=("NAME", "URL"), help="add repo")
        p.add_argument("--remove", metavar="NAME", help="remove repo")
        p.add_argument("--list", action="store_true", help="list repos")
        p.add_argument("--sync", nargs="*", metavar="NAME", help="sync named repos (or all if omitted)")
        p.add_argument("--verify", metavar="NAME", help="verify repo")
        p.add_argument("--rollback", nargs=2, metavar=("NAME", "REF"), help="rollback repo to REF")
        p.add_argument("--json", action="store_true", help="print JSON outputs")
        p.add_argument("--quiet", action="store_true", help="quiet mode")
        p.add_argument("--no-sandbox", action="store_true", help="do not use sandbox")
        p.add_argument("--jobs", type=int, help="parallel jobs override")
        args = p.parse_args()

        cfg = init_config() if init_config else None
        logger = NewpkgLogger.from_config(cfg, NewpkgDB(cfg)) if NewpkgLogger and cfg else None
        db = NewpkgDB(cfg) if NewpkgDB and cfg else None
        hooks = NewpkgHooks.from_config(cfg, logger, db) if NewpkgHooks and cfg else None
        sandbox = NewpkgSandbox(cfg=cfg, logger=logger, db=db) if NewpkgSandbox and cfg else None

        syncer = NewpkgSync(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox)

        if args.quiet:
            syncer.quiet = True
        if args.json:
            syncer.json_out = True
        if args.jobs:
            syncer.parallel = args.jobs
        if args.no_sandbox:
            use_sandbox = False
        else:
            use_sandbox = True

        if args.add:
            name, url = args.add
            syncer.add_repo(name, url)
            print(f"Added {name}: {url}")
            raise SystemExit(0)

        if args.remove:
            ok = syncer.remove_repo(args.remove)
            raise SystemExit(0 if ok else 2)

        if args.list:
            repos = syncer.list_repos()
            if syncer.json_out:
                print(json.dumps(repos, indent=2))
            else:
                for n, spec in repos.items():
                    print(f"{n:20} {spec.get('url')} -> {spec.get('dst','<auto>')}")
            raise SystemExit(0)

        if args.sync is not None:
            names = args.sync if len(args.sync) > 0 else None
            res = syncer.sync_all(names=names, update=True, use_sandbox=use_sandbox)
            if syncer.json_out:
                print(json.dumps(res, indent=2))
            raise SystemExit(0)

        if args.verify:
            v = syncer.verify_repo(args.verify, use_sandbox=use_sandbox)
            if syncer.json_out:
                print(json.dumps(v, indent=2))
            else:
                print(v)
            raise SystemExit(0)

        if args.rollback:
            name, ref = args.rollback
            r = syncer.rollback_repo(name, ref, use_sandbox=use_sandbox)
            if syncer.json_out:
                print(json.dumps(r, indent=2))
            else:
                print(r)
            raise SystemExit(0)

        # default: list
        repos = syncer.list_repos()
        if syncer.json_out:
            print(json.dumps(repos, indent=2))
        else:
            for n, spec in repos.items():
                print(f"{n:20} {spec.get('url')} -> {spec.get('dst','<auto>')}")
        raise SystemExit(0)


if __name__ == "__main__":
    NewpkgSync.cli()
