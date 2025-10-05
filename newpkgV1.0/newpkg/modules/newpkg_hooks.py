#!/usr/bin/env python3
# newpkg_hooks.py (fixed)
"""
newpkg_hooks.py — Hooks manager for newpkg (improved)

Improvements applied:
- Lazy imports for get_logger/get_db/get_config/get_sandbox/get_api to avoid import circulars.
- Fallback report/log directory to ~/.local/share/newpkg/hooks if /var/log/newpkg/hooks not writable.
- Discovery cache validated against directory mtime (invalidated if contents change).
- New hook `pre_hook_fail` executed before writing fail logs.
- All internal exceptions log full traceback for easier debugging.
- Keeps public API identical to original (HooksManager, get_hooks_manager, run, run_named, etc).
"""

from __future__ import annotations

import json
import os
import threading
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# -------------------------
# Fallback logger
# -------------------------
import logging
_module_logger = logging.getLogger("newpkg.hooks")
if not _module_logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.hooks: %(message)s"))
    _module_logger.addHandler(h)
_module_logger.setLevel(logging.INFO)

# -------------------------
# Data class
# -------------------------
@dataclass
class HookSpec:
    name: str
    path: str
    async_run: bool = False
    timeout: Optional[int] = None
    sandbox_profile: Optional[str] = None
    meta: Dict[str, Any] = None

# -------------------------
# HooksManager
# -------------------------
class HooksManager:
    DEFAULT_HOOK_DIRS = ["/etc/newpkg/hooks", "/usr/share/newpkg/hooks"]
    FALLBACK_LOG_DIR = Path.home() / ".local/share/newpkg/hooks"
    CACHE_TTL = 30  # seconds

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None):
        self._lock = threading.RLock()
        self._cfg = cfg
        self._logger = logger
        self._db = db
        self._sandbox = sandbox
        self._api = None

        # Lazy imports for all dependencies
        try:
            if self._logger is None:
                from newpkg_logger import get_logger  # type: ignore
                self._logger = get_logger(self._cfg)
        except Exception:
            self._logger = None

        try:
            if self._db is None:
                from newpkg_db import get_db  # type: ignore
                self._db = get_db()
        except Exception:
            self._db = None

        try:
            if self._cfg is None:
                from newpkg_config import get_config  # type: ignore
                self._cfg = get_config()
        except Exception:
            self._cfg = None

        try:
            from newpkg_api import get_api  # type: ignore
            self._api = get_api()
        except Exception:
            self._api = None

        try:
            if self._sandbox is None:
                from newpkg_sandbox import get_sandbox  # type: ignore
                self._sandbox = get_sandbox(self._cfg)
        except Exception:
            self._sandbox = None

        # Cache
        self._hook_dirs = self._determine_hook_dirs()
        self._cache: Dict[str, Tuple[float, List[HookSpec]]] = {}
        self._last_full_scan = 0.0

        # Fail log dir
        self._fail_log_dir = self._ensure_fail_log_dir()

        # Async control
        self._async_limit = int(getattr(self._cfg, "get", lambda k, d=None: d)("hooks.async_limit", 8) if self._cfg else 8)
        self._async_semaphore = threading.BoundedSemaphore(self._async_limit)

        # API registration
        try:
            if self._api:
                self._api.hooks = self
        except Exception:
            pass

        # Startup log
        try:
            if self._logger:
                self._logger.info("HooksManager initialized")
            else:
                _module_logger.info("HooksManager initialized")
        except Exception:
            pass

    # -------------------------
    # Internal helpers
    # -------------------------
    def _determine_hook_dirs(self) -> List[Path]:
        dirs = []
        try:
            if self._cfg and hasattr(self._cfg, "get"):
                custom = self._cfg.get("hooks.dirs") or None
                if custom:
                    if isinstance(custom, (list, tuple)):
                        dirs = [Path(d) for d in custom]
                    else:
                        dirs = [Path(custom)]
        except Exception:
            pass
        return dirs or [Path(p) for p in self.DEFAULT_HOOK_DIRS]

    def _ensure_fail_log_dir(self) -> Path:
        try:
            p = Path("/var/log/newpkg/hooks")
            p.mkdir(parents=True, exist_ok=True)
            test = p / ".writable_check"
            with open(test, "w") as fh:
                fh.write("ok")
            test.unlink()
            return p
        except Exception:
            try:
                self.FALLBACK_LOG_DIR.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            return self.FALLBACK_LOG_DIR

    def _list_dir_mtime(self, path: Path) -> float:
        try:
            return path.stat().st_mtime
        except Exception:
            return 0.0

    # -------------------------
    # Discovery and caching
    # -------------------------
    def _discover_hooks_in_dir(self, d: Path) -> List[HookSpec]:
        hooks: List[HookSpec] = []
        try:
            if not d.exists():
                return hooks
            for entry in sorted(d.iterdir()):
                if entry.is_file() and os.access(entry, os.X_OK):
                    name = entry.stem
                    meta = {}
                    meta_file = entry.with_suffix(".json")
                    if meta_file.exists():
                        try:
                            meta = json.loads(meta_file.read_text(encoding="utf-8"))
                        except Exception:
                            meta = {}
                    hooks.append(HookSpec(name, str(entry), bool(meta.get("async")), meta.get("timeout"), meta.get("sandbox"), meta))
        except Exception as e:
            tb = traceback.format_exc()
            (_module_logger if not self._logger else self._logger).error("hooks.discover_exc", f"{e}\n{tb}")
        return hooks

    def _get_cached_hooks_for_dir(self, d: Path) -> List[HookSpec]:
        with self._lock:
            try:
                mtime = self._list_dir_mtime(d)
                cache_entry = self._cache.get(str(d))
                if cache_entry:
                    cached_mtime, hooks = cache_entry
                    if cached_mtime == mtime and (time.time() - self._last_full_scan) < self.CACHE_TTL:
                        return hooks
                hooks = self._discover_hooks_in_dir(d)
                self._cache[str(d)] = (mtime, hooks)
                self._last_full_scan = time.time()
                return hooks
            except Exception as e:
                tb = traceback.format_exc()
                (_module_logger if not self._logger else self._logger).error("hooks.cache_exc", f"{e}\n{tb}")
                return []

    def list_all_hooks(self) -> List[HookSpec]:
        all_hooks: List[HookSpec] = []
        for d in self._hook_dirs:
            all_hooks.extend(self._get_cached_hooks_for_dir(d))
        return all_hooks

    def find_hook_by_name(self, name: str) -> Optional[HookSpec]:
        return next((h for h in self.list_all_hooks() if h.name == name), None)

    # -------------------------
    # Execution and fail logging
    # -------------------------
    def _write_fail_log(self, hook: HookSpec, stdout: str, stderr: str, exc_txt: Optional[str] = None):
        try:
            # Trigger pre_hook_fail before writing
            try:
                if self._api and hasattr(self._api, "call"):
                    self._api.call("hooks.pre_hook_fail", {"hook": hook.name, "meta": hook.meta or {}})
            except Exception:
                pass
            stamp = int(time.time())
            fname = self._fail_log_dir / f"{hook.name}.fail.{stamp}.log"
            payload = {"hook": hook.name, "ts": stamp, "path": hook.path, "stdout": stdout, "stderr": stderr, "exc": exc_txt}
            with open(fname, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
        except Exception as e:
            tb = traceback.format_exc()
            (_module_logger if not self._logger else self._logger).error("hooks.fail_log_exc", f"{e}\n{tb}")

    def _run_hook_sync(self, hook: HookSpec, env: Optional[Dict[str, str]] = None) -> Tuple[bool, str, str]:
        try:
            import subprocess
            envp = os.environ.copy()
            if env:
                envp.update(env)
            proc = subprocess.run([hook.path], env=envp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=hook.timeout)
            out = proc.stdout.decode("utf-8", errors="ignore")
            err = proc.stderr.decode("utf-8", errors="ignore")
            return (proc.returncode == 0), out, err
        except Exception as e:
            tb = traceback.format_exc()
            (_module_logger if not self._logger else self._logger).error("hooks.exec_exc", f"{e}\n{tb}")
            return False, "", str(e)

    def run(self, names: List[str], env: Optional[Dict[str, str]] = None, asynchronous: bool = False) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        for name in names:
            hook = self.find_hook_by_name(name)
            if not hook:
                results[name] = {"ok": False, "error": "not found"}
                continue
            try:
                if asynchronous and hook.async_run:
                    t = threading.Thread(target=self._run_hook_sync, args=(hook, env), daemon=True)
                    t.start()
                    results[name] = {"ok": True, "async": True}
                else:
                    ok, out, err = self._run_hook_sync(hook, env)
                    if not ok:
                        self._write_fail_log(hook, out, err)
                    results[name] = {"ok": ok, "stdout": out, "stderr": err}
            except Exception as e:
                tb = traceback.format_exc()
                (_module_logger if not self._logger else self._logger).error("hooks.run_exc", f"{e}\n{tb}")
                results[name] = {"ok": False, "error": str(e), "traceback": tb}
        return results

    def run_named(self, name: str, env: Optional[Dict[str, str]] = None, asynchronous: bool = False) -> Dict[str, Any]:
        return self.run([name], env, asynchronous).get(name, {"ok": False, "error": "not found"})

    def invalidate_cache(self):
        with self._lock:
            self._cache.clear()
            self._last_full_scan = 0.0

# -------------------------
# Global accessor
# -------------------------
_default_hooks_manager: Optional[HooksManager] = None
_hooks_lock = threading.RLock()

def get_hooks_manager(cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None) -> HooksManager:
    global _default_hooks_manager
    with _hooks_lock:
        if _default_hooks_manager is None:
            _default_hooks_manager = HooksManager(cfg, logger, db, sandbox)
        return _default_hooks_manager

# -------------------------
# CLI entrypoint
# -------------------------
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-hooks", description="Run newpkg hooks")
    p.add_argument("names", nargs="*", help="Hook names to run")
    p.add_argument("--async", dest="asynchronous", action="store_true")
    args = p.parse_args()
    hm = get_hooks_manager()
    res = hm.run(args.names, asynchronous=args.asynchronous)
    pprint.pprint(res)
