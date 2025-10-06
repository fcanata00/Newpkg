#!/usr/bin/env python3
# newpkg_core.py (fixed)
"""
newpkg_core.py — Core orchestration for newpkg (improved)

Applied improvements:
- Lazy imports for get_logger/get_db/get_hooks_manager/get_api/get_sandbox/get_config
- Added pre_phase_fail and post_phase_fail hooks (executed when any phase fails)
- Fallback directories for checkpoints and logs to user locations if system dirs not writable
- Global compression config via core.compression (zstd, xz, gzip)
- Dry-run mode via core.dry_run = true (simulates execution and produces BuildReport without running commands)
- Default: sequential execution (1 job). Use --parallel or core.parallel.enabled to enable parallelism.
- Startup log: "CoreManager initialized"

API preserved: CoreManager, get_core_manager, run_pipeline, etc.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# -------------------------
# Fallback logger
# -------------------------
import logging
_module_logger = logging.getLogger("newpkg.core")
if not _module_logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.core: %(message)s"))
    _module_logger.addHandler(h)
_module_logger.setLevel(logging.INFO)

# -------------------------
# Dataclasses
# -------------------------
@dataclass
class PhaseResult:
    name: str
    ok: bool
    rc: Optional[int]
    stdout: str
    stderr: str
    duration: float
    meta: Dict[str, Any]


@dataclass
class BuildReport:
    package: str
    phases: List[PhaseResult]
    success: bool
    duration: float
    meta: Dict[str, Any]


# -------------------------
# CoreManager
# -------------------------
class CoreManager:
    DEFAULT_CHECKPOINT_DIR = Path("/var/lib/newpkg/checkpoints")
    DEFAULT_LOG_DIR = Path("/var/log/newpkg/core")
    FALLBACK_CHECKPOINT_DIR = Path.home() / ".local/share/newpkg/checkpoints"
    FALLBACK_LOG_DIR = Path.home() / ".local/share/newpkg/core"
    DEFAULT_PARALLEL_THREADS = 4

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None, api: Any = None):
        self._cfg = cfg
        self.logger = logger
        self.db = db
        self.hooks = hooks
        self.sandbox = sandbox
        self.api = api

        # -------------------------
        # Lazy imports
        # -------------------------
        try:
            if self.logger is None:
                from newpkg_logger import get_logger
                self.logger = get_logger(self._cfg)
        except Exception:
            self.logger = None

        try:
            if self.db is None:
                from newpkg_db import get_db
                self.db = get_db()
        except Exception:
            self.db = None

        try:
            if self.hooks is None:
                from newpkg_hooks import get_hooks_manager
                self.hooks = get_hooks_manager(self._cfg, self.logger, self.db)
        except Exception:
            self.hooks = None

        try:
            if self.sandbox is None:
                from newpkg_sandbox import get_sandbox
                self.sandbox = get_sandbox(self._cfg, self.logger, self.hooks, self.api, self.db)
        except Exception:
            self.sandbox = None

        try:
            if self.api is None:
                from newpkg_api import get_api
                self.api = get_api()
        except Exception:
            self.api = None

        try:
            if self._cfg is None:
                from newpkg_config import get_config
                self._cfg = get_config()
        except Exception:
            self._cfg = None

        # -------------------------
        # Fallback directories
        # -------------------------
        self.checkpoint_dir = self._resolve_dir(self.DEFAULT_CHECKPOINT_DIR, self.FALLBACK_CHECKPOINT_DIR)
        self.log_dir = self._resolve_dir(self.DEFAULT_LOG_DIR, self.FALLBACK_LOG_DIR)
        try:
            os.chmod(self.checkpoint_dir, 0o700)
            os.chmod(self.log_dir, 0o700)
        except Exception:
            pass

        # -------------------------
        # Compression config
        # -------------------------
        self.compression = str(self._cfg.get("core.compression")) if (self._cfg and hasattr(self._cfg, "get") and self._cfg.get("core.compression")) else None
        if self.compression not in (None, "zstd", "xz", "gzip"):
            self.compression = None

        # -------------------------
        # Dry-run and parallel mode
        # -------------------------
        self.dry_run = bool(self._cfg.get("core.dry_run", False)) if self._cfg and hasattr(self._cfg, "get") else False
        self.parallel_enabled = bool(self._cfg.get("core.parallel.enabled", False)) if self._cfg and hasattr(self._cfg, "get") else False

        # -------------------------
        # Log initialization
        # -------------------------
        try:
            if self.logger:
                self.logger.info("CoreManager initialized")
            else:
                _module_logger.info("CoreManager initialized")
        except Exception:
            pass

        self._lock = threading.RLock()

    # -------------------------
    # Helpers
    # -------------------------
    def _resolve_dir(self, preferred: Path, fallback: Path) -> Path:
        try:
            p = preferred
            try:
                p.mkdir(parents=True, exist_ok=True)
                test = p / ".writable_check"
                with open(test, "w") as fh:
                    fh.write("ok")
                test.unlink()
                return p
            except Exception:
                fb = fallback
                fb.mkdir(parents=True, exist_ok=True)
                return fb
        except Exception:
            return fallback

    def _run_phase_cmd(self, cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> PhaseResult:
        t0 = time.time()
        try:
            if self.dry_run:
                return PhaseResult(cmd[0], True, 0, "(dry-run)", "", 0.0, {})

            if self.sandbox and hasattr(self.sandbox, "run_in_sandbox"):
                res = self.sandbox.run_in_sandbox(cmd, cwd=cwd, env=env, timeout=timeout, use_fakeroot=False)
                return PhaseResult(cmd[0], res.rc == 0, res.rc, res.stdout, res.stderr, res.duration, {})

            proc = subprocess.run(cmd, cwd=cwd, env=env or os.environ, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            out = proc.stdout.decode("utf-8", errors="ignore")
            err = proc.stderr.decode("utf-8", errors="ignore")
            return PhaseResult(cmd[0], proc.returncode == 0, proc.returncode, out, err, time.time() - t0, {})
        except Exception as e:
            tb = traceback.format_exc()
            (_module_logger if not self.logger else self.logger).error("core.phase_exc", f"{e}\n{tb}")
            return PhaseResult(cmd[0], False, None, "", f"{e}\n{tb}", time.time() - t0, {})

    def _pre_phase_fail(self, phase: str, rc: Optional[int], stderr: str):
        try:
            if self.api and hasattr(self.api, "call"):
                self.api.call("core.pre_phase_fail", {"phase": phase, "rc": rc, "stderr": stderr})
            if self.hooks and hasattr(self.hooks, "run"):
                self.hooks.run("pre_phase_fail", {"phase": phase, "rc": rc, "stderr": stderr})
        except Exception:
            tb = traceback.format_exc()
            (_module_logger if not self.logger else self.logger).error("core.pre_phase_fail_exc", tb)

    def _post_phase_fail(self, phase: str, rc: Optional[int], stderr: str):
        try:
            if self.api and hasattr(self.api, "call"):
                self.api.call("core.post_phase_fail", {"phase": phase, "rc": rc, "stderr": stderr})
            if self.hooks and hasattr(self.hooks, "run"):
                self.hooks.run("post_phase_fail", {"phase": phase, "rc": rc, "stderr": stderr})
        except Exception:
            tb = traceback.format_exc()
            (_module_logger if not self.logger else self.logger).error("core.post_phase_fail_exc", tb)

    # -------------------------
    # Pipeline execution
    # -------------------------
    def run_pipeline(self, package: str, phases: List[Dict[str, Any]], parallel: bool = False) -> BuildReport:
        start = time.time()
        results: List[PhaseResult] = []
        use_parallel = bool(parallel and self.parallel_enabled)

        if use_parallel:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=self.DEFAULT_PARALLEL_THREADS) as ex:
                futs = {ex.submit(self._run_phase_cmd, p["cmd"], p.get("cwd"), p.get("env"), p.get("timeout")): p for p in phases}
                for fut in as_completed(futs):
                    try:
                        res = fut.result()
                    except Exception as e:
                        tb = traceback.format_exc()
                        (_module_logger if not self.logger else self.logger).error("core.phase_future_exc", f"{e}\n{tb}")
                        res = PhaseResult("phase", False, None, "", str(e), 0.0, {})
                    results.append(res)
                    if not res.ok:
                        self._pre_phase_fail(res.name, res.rc, res.stderr)
                        self._post_phase_fail(res.name, res.rc, res.stderr)
        else:
            for p in phases:
                res = self._run_phase_cmd(p["cmd"], p.get("cwd"), p.get("env"), p.get("timeout"))
                results.append(res)
                if not res.ok:
                    self._pre_phase_fail(res.name, res.rc, res.stderr)
                    self._post_phase_fail(res.name, res.rc, res.stderr)
                    break

        duration = time.time() - start
        success = all(r.ok for r in results)
        report = BuildReport(package, results, success, duration, {"compression": self.compression, "dry_run": self.dry_run})

        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase("core", "pipeline_done", "ok" if success else "fail", {"package": package, "success": success, "duration": duration})
        except Exception:
            pass

        try:
            ck = self.checkpoint_dir / f"{package}.checkpoint.json"
            tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8", dir=str(self.checkpoint_dir))
            json.dump({"package": package, "report": asdict(report)}, tmp, indent=2)
            tmp.close()
            os.replace(tmp.name, ck)
        except Exception as e:
            tb = traceback.format_exc()
            (_module_logger if not self.logger else self.logger).warning("core.checkpoint_fail", f"{e}\n{tb}")

        return report


# -------------------------
# Singleton accessor
# -------------------------
_default_core: Optional[CoreManager] = None
_core_lock = threading.RLock()

def get_core_manager(cfg=None, logger=None, db=None, hooks=None, sandbox=None, api=None) -> CoreManager:
    global _default_core
    with _core_lock:
        if _default_core is None:
            _default_core = CoreManager(cfg, logger, db, hooks, sandbox, api)
        return _default_core


# -------------------------
# CLI entrypoint
# -------------------------
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-core", description="Run package pipeline")
    p.add_argument("package", help="Package name")
    p.add_argument("--phases", help="JSON file containing phases list")
    p.add_argument("--parallel", action="store_true", help="Run phases in parallel (if allowed)")
    p.add_argument("--dry-run", action="store_true", help="Dry run (simulate only)")
    args = p.parse_args()

    mgr = get_core_manager()
    if args.dry_run:
        mgr.dry_run = True

    phases = []
    if args.phases and Path(args.phases).exists():
        try:
            phases = json.loads(Path(args.phases).read_text())
        except Exception:
            phases = []

    report = mgr.run_pipeline(args.package, phases, parallel=args.parallel)
    pprint.pprint(asdict(report))
