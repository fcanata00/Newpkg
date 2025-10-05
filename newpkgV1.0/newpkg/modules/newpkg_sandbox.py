#!/usr/bin/env python3
# newpkg_sandbox.py (fixed)
"""
newpkg_sandbox.py — Sandbox manager for newpkg (improved)

Improvements applied:
- Lazy imports for get_logger/get_hooks_manager/get_config/get_api/get_db to avoid import circulars
- Fallback tmp dir to ~/.cache/newpkg/sandbox/tmp when /tmp not writable
- Added pre_sandbox_fail and post_sandbox_fail hooks (run before/after fail cleanup)
- Dry-run mode via config: sandbox.dry_run = true (only logs command, does not execute)
- Structured error logging into DB under "sandbox.errors" and consolidated log entries
- Startup log: "SandboxManager initialized"

Public API preserved: SandboxManager, get_sandbox, run_in_sandbox(...)
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# -------------------------
# Fallback logger
# -------------------------
import logging
_module_logger = logging.getLogger("newpkg.sandbox")
if not _module_logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.sandbox: %(message)s"))
    _module_logger.addHandler(h)
_module_logger.setLevel(logging.INFO)


@dataclass
class SandboxResult:
    rc: Optional[int]
    stdout: str
    stderr: str
    duration: float
    timed_out: bool


class SandboxManager:
    DEFAULT_TMP = Path("/tmp/newpkg-sandbox")
    FALLBACK_TMP = Path.home() / ".cache/newpkg/sandbox/tmp"
    DEFAULT_TIMEOUT = 3600  # 1 hour

    def __init__(self, cfg: Any = None, logger: Any = None, hooks: Any = None, api: Any = None, db: Any = None):
        self._cfg = cfg
        self.logger = logger
        self.hooks = hooks
        self.api = api
        self.db = db

        # Lazy imports
        try:
            if self.logger is None:
                from newpkg_logger import get_logger
                self.logger = get_logger(self._cfg)
        except Exception:
            self.logger = None

        try:
            if self.hooks is None:
                from newpkg_hooks import get_hooks_manager
                self.hooks = get_hooks_manager(self._cfg, self.logger, self.db)
        except Exception:
            self.hooks = None

        try:
            if self.api is None:
                from newpkg_api import get_api
                self.api = get_api()
        except Exception:
            self.api = None

        try:
            if self.db is None:
                from newpkg_db import get_db
                self.db = get_db()
        except Exception:
            self.db = None

        try:
            if self._cfg is None:
                from newpkg_config import get_config
                self._cfg = get_config()
        except Exception:
            self._cfg = None

        # TMP dir with fallback
        self._tmp_base = self._resolve_tmp_dir()
        try:
            os.chmod(self._tmp_base, 0o700)
        except Exception:
            pass

        # Dry-run flag
        self.dry_run = False
        try:
            if self._cfg and hasattr(self._cfg, "get"):
                self.dry_run = bool(self._cfg.get("sandbox.dry_run", False))
        except Exception:
            self.dry_run = False

        # Startup log
        try:
            if self.logger:
                self.logger.info("SandboxManager initialized")
            else:
                _module_logger.info("SandboxManager initialized")
        except Exception:
            pass

        self._lock = threading.RLock()

    def _resolve_tmp_dir(self) -> Path:
        try:
            p = self.DEFAULT_TMP
            if self._cfg and hasattr(self._cfg, "get"):
                custom = self._cfg.get("sandbox.tmp_dir")
                if custom:
                    p = Path(custom).expanduser()
            try:
                p.mkdir(parents=True, exist_ok=True)
                test = p / ".writable_check"
                with open(test, "w") as fh:
                    fh.write("ok")
                test.unlink()
                return p
            except Exception:
                fb = self.FALLBACK_TMP
                fb.mkdir(parents=True, exist_ok=True)
                return fb
        except Exception:
            return self.FALLBACK_TMP

    def _sanitize_env(self, env: Optional[Dict[str, str]]) -> Dict[str, str]:
        base = dict(os.environ)
        if env:
            base.update(env)
        sensitive_prefixes = ("GPG_", "SSH_", "AWS_", "AZURE_", "GCLOUD_", "TOKEN", "PASSWORD", "SECRET")
        for k in list(base.keys()):
            if any(k.startswith(pref) for pref in sensitive_prefixes):
                base.pop(k, None)
        return base

    def _run_command(self, cmd: List[str], cwd: Optional[str], env: Dict[str, str], timeout: int) -> SandboxResult:
        t0 = time.time()
        timed_out = False
        try:
            proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                out, err = proc.communicate(timeout=timeout)
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                rc = getattr(proc, "returncode", None)
                timed_out = True
            stdout = out.decode("utf-8", errors="ignore") if out else ""
            stderr = err.decode("utf-8", errors="ignore") if err else ""
            duration = time.time() - t0
            return SandboxResult(rc, stdout, stderr, duration, timed_out)
        except Exception as e:
            tb = traceback.format_exc()
            if self.logger:
                self.logger.error("sandbox.exec_exc", f"{e}\n{tb}")
            else:
                _module_logger.error(f"{e}\n{tb}")
            duration = time.time() - t0
            return SandboxResult(None, "", f"{e}\n{tb}", duration, False)

    def _record_structured_error(self, cmd: List[str], rc: Optional[int], stderr: str, extra: Optional[Dict[str, Any]] = None):
        payload = {
            "ts": int(time.time()),
            "cmd": cmd,
            "rc": rc,
            "stderr": stderr,
            "extra": extra or {}
        }
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase("sandbox", "errors", "fail", meta=payload)
        except Exception:
            pass
        try:
            if self.logger:
                self.logger.error("sandbox.errors", payload)
            else:
                _module_logger.error(f"sandbox.errors {json.dumps(payload)}")
        except Exception:
            pass

    def run_in_sandbox(self, argv: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None, use_fakeroot: bool = False) -> SandboxResult:
        timeout = int(timeout or self._cfg.get("sandbox.timeout", self.DEFAULT_TIMEOUT) if self._cfg and hasattr(self._cfg, "get") else self.DEFAULT_TIMEOUT)
        cmd = list(argv)
        sanitized_env = self._sanitize_env(env)
        tmpdir = Path(tempfile.mkdtemp(prefix="newpkg-sandbox-", dir=str(self._tmp_base)))

        try:
            # Dry-run mode
            if self.dry_run:
                msg = {"cmd": cmd, "cwd": cwd, "tmpdir": str(tmpdir), "dry_run": True}
                if self.logger:
                    self.logger.info("sandbox.dry_run", msg)
                else:
                    _module_logger.info(f"sandbox.dry_run {msg}")
                return SandboxResult(0, "(dry-run)", "", 0.0, False)

            res = self._run_command(cmd, cwd=cwd, env=sanitized_env, timeout=timeout)

            # Hooks
            if (res.rc is None) or (res.rc != 0) or res.timed_out:
                if self.api and hasattr(self.api, "call"):
                    try:
                        self.api.call("sandbox.pre_sandbox_fail", {"cmd": cmd, "rc": res.rc, "stderr": res.stderr})
                    except Exception:
                        pass
                if self.hooks and hasattr(self.hooks, "run"):
                    try:
                        self.hooks.run("pre_sandbox_fail", {"cmd": cmd, "rc": res.rc, "stderr": res.stderr})
                    except Exception:
                        pass
                self._record_structured_error(cmd, res.rc, res.stderr, {"timed_out": res.timed_out})
                if self.hooks and hasattr(self.hooks, "run"):
                    try:
                        self.hooks.run("post_sandbox_fail", {"cmd": cmd, "rc": res.rc, "stderr": res.stderr})
                    except Exception:
                        pass

            return res
        finally:
            shutil.rmtree(str(tmpdir), ignore_errors=True)


# -------------------------
# Singleton accessor
# -------------------------
_default_sandbox: Optional[SandboxManager] = None
_sandbox_lock = threading.RLock()

def get_sandbox(cfg: Any = None, logger: Any = None, hooks: Any = None, api: Any = None, db: Any = None) -> SandboxManager:
    global _default_sandbox
    with _sandbox_lock:
        if _default_sandbox is None:
            _default_sandbox = SandboxManager(cfg, logger, hooks, api, db)
        return _default_sandbox


# -------------------------
# CLI entrypoint
# -------------------------
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-sandbox", description="Run command in sandbox")
    p.add_argument("cmd", nargs="+", help="Command to run")
    p.add_argument("--cwd", help="Working directory")
    p.add_argument("--timeout", type=int, help="Timeout seconds")
    p.add_argument("--dry-run", action="store_true", help="Only log command, don't execute")
    args = p.parse_args()

    sb = get_sandbox()
    if args.dry_run:
        sb.dry_run = True
    res = sb.run_in_sandbox(args.cmd, cwd=args.cwd, timeout=args.timeout)
    pprint.pprint(res.__dict__)
