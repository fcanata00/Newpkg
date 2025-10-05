#!/usr/bin/env python3
# newpkg_hooks.py
"""
newpkg_hooks.py — discovery and execution of lifecycle hooks for newpkg

Features:
 - Discover hooks from multiple places (project, user, system) configurable via newpkg_config
 - Execute hooks safely, optionally inside sandbox (NewpkgSandbox) with cfg.as_env()
 - Respect general.dry_run, output.quiet and output.json flags from newpkg_config
 - Record structured hook runs in NewpkgDB (rc, duration, backend, meta)
 - Use NewpkgLogger for structured logging and @perf_timer when available
 - Cache discovered hooks to a small JSON file and automatically prune stale entries
 - Provide CLI for testing and one-off execution with JSON output option
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# Optional integrations (best-effort)
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
    from newpkg_sandbox import NewpkgSandbox
except Exception:
    NewpkgSandbox = None

# fallback stdlib logger for internal warnings
import logging
_logger = logging.getLogger("newpkg.hooks")
if not _logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] newpkg.hooks: %(message)s"))
    _logger.addHandler(handler)
_logger.setLevel(logging.INFO)


@dataclass
class HookResult:
    name: str
    path: str
    rc: int
    duration: float
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    backend: Optional[str] = None
    dry_run: bool = False
    meta: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["meta"] = d.get("meta") or {}
        return d


class NewpkgHooks:
    DEFAULT_HOOK_DIRS = (
        "./hooks",                          # project-local
        os.path.expanduser("~/.config/newpkg/hooks"),  # user hooks
        "/etc/newpkg/hooks",                # system hooks
    )
    CACHE_FILE = ".newpkg/hooks_cache.json"

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        # logger: prefer provided instance else try to create from config
        if logger:
            self.logger = logger
        else:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, db) if NewpkgLogger and self.cfg else None
            except Exception:
                self.logger = None
        # db
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)
        # sandbox
        if sandbox:
            self.sandbox = sandbox
        else:
            try:
                self.sandbox = NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgSandbox and self.cfg else None
            except Exception:
                self.sandbox = None

        # config-driven settings
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))
        self.hook_dirs = list(self._cfg_get("hooks.dirs", self.DEFAULT_HOOK_DIRS) or self.DEFAULT_HOOK_DIRS)
        self.cache_file = Path(self._cfg_get("hooks.cache_file", self.CACHE_FILE))
        # whether to use sandbox by default for hook execution
        self.use_sandbox_default = bool(self._cfg_get("hooks.use_sandbox", True))
        # allowable executable suffixes (scripts, binaries)
        self.exec_suffixes = list(self._cfg_get("hooks.exec_suffixes", [".sh", ".py", ""]))  # '' means no suffix required (binaries)
        # create cache dir if needed
        if self.cache_file.parent and not self.cache_file.parent.exists():
            try:
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

        # wrapper to log
        self._log = self._make_logger()

    @classmethod
    def from_config(cls, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None) -> "NewpkgHooks":
        return cls(cfg=cfg, logger=logger, db=db, sandbox=sandbox)

    # ----------------- internal helpers -----------------
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

    def _cache_load(self) -> Dict[str, Any]:
        if not self.cache_file.exists():
            return {}
        try:
            text = self.cache_file.read_text(encoding="utf-8")
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}

    def _cache_save(self, data: Dict[str, Any]) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _is_executable(self, path: Path) -> bool:
        try:
            st = path.stat()
            return bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) or any(path.name.endswith(suf) for suf in self.exec_suffixes if suf)
        except Exception:
            return False

    # ----------------- discovery -----------------
    def discover_hooks(self, refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Discover available hooks across configured directories.
        Returns mapping: hook_name -> {path, mtime, executable}
        Caches results in self.cache_file; refresh forces re-scan.
        """
        if not refresh:
            cached = self._cache_load()
        else:
            cached = {}

        discovered: Dict[str, Dict[str, Any]] = {}
        for d in self.hook_dirs:
            try:
                base = Path(d)
                if not base.exists() or not base.is_dir():
                    continue
                for entry in sorted(base.iterdir()):
                    if not entry.is_file():
                        continue
                    name = entry.name
                    mtime = int(entry.stat().st_mtime)
                    exec_ok = self._is_executable(entry)
                    discovered[name] = {"path": str(entry.resolve()), "mtime": mtime, "executable": exec_ok}
            except Exception:
                continue

        # prune cached entries not present anymore
        if cached:
            for k in list(cached.keys()):
                if k not in discovered:
                    cached.pop(k, None)

        # merge and save (fresh discovered overrides cached)
        merged = {**cached, **discovered}
        try:
            self._cache_save(merged)
        except Exception:
            pass

        return merged

    # ----------------- execution helpers -----------------
    def _build_env(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = dict(os.environ)
        try:
            if self.cfg and hasattr(self.cfg, "as_env"):
                env.update(self.cfg.as_env())
        except Exception:
            pass
        if extra:
            env.update({k: str(v) for k, v in extra.items()})
        # blacklist dangerous vars
        for k in ("LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
            env.pop(k, None)
        return env

    def _run_via_subprocess(self, cmd: Union[str, List[str]], cwd: Optional[Union[str, Path]] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Run command via subprocess and capture stdout/stderr. cmd may be str or list.
        """
        if isinstance(cmd, (list, tuple)):
            shell = False
            cmd_list = [str(x) for x in cmd]
        else:
            shell = True
            cmd_list = cmd
        proc = subprocess.run(cmd_list, cwd=str(cwd) if cwd else None, env=env, shell=shell,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""

    def _record_hook_db(self, name: str, rc: int, duration: float, backend: Optional[str], meta: Dict[str, Any]):
        try:
            if self.db and hasattr(self.db, "record_hook"):
                # if db provides record_hook - call it
                try:
                    self.db.record_hook(name, rc=rc, duration=duration, backend=backend, meta=meta)
                    return
                except Exception:
                    pass
            # fallback to record_phase to store hook info
            if self.db and hasattr(self.db, "record_phase"):
                try:
                    self.db.record_phase(package=meta.get("package", "global"), phase=f"hook:{name}", status=("ok" if rc == 0 else "error"), meta={"rc": rc, "duration": duration, "backend": backend, **meta})
                except Exception:
                    pass
        except Exception:
            pass

    # ----------------- single hook run -----------------
    def run_hook(self,
                 name: str,
                 cwd: Optional[Union[str, Path]] = None,
                 env_extra: Optional[Dict[str, str]] = None,
                 use_sandbox: Optional[bool] = None,
                 timeout: Optional[int] = None) -> HookResult:
        """
        Run a single discovered hook by name.
        - cwd: working directory to run in (host path)
        - env_extra: extra env vars (merged onto cfg.as_env())
        - use_sandbox: override default sandbox usage for this hook
        - timeout: seconds to wait before kill
        """
        hooks = self.discover_hooks(refresh=False)
        if name not in hooks:
            self._log("warning", "hook.not_found", f"Hook {name} not found", name=name)
            return HookResult(name=name, path="", rc=127, duration=0.0, stdout="", stderr="not found", backend=None, dry_run=self.dry_run, meta={})

        entry = hooks[name]
        path = Path(entry["path"])
        if not path.exists():
            self._log("warning", "hook.missing", f"Hook {name} missing on disk", name=name, path=str(path))
            return HookResult(name=name, path=str(path), rc=127, duration=0.0, stdout="", stderr="missing", backend=None, dry_run=self.dry_run, meta={})

        env = self._build_env(env_extra)
        backend_used = "none"
        if use_sandbox is None:
            use_sandbox = self.use_sandbox_default

        # dry-run early return
        if self.dry_run:
            self._log("info", "hook.dryrun", f"DRY-RUN executing hook {name}", name=name, path=str(path))
            return HookResult(name=name, path=str(path), rc=0, duration=0.0, stdout="", stderr="", backend="dryrun", dry_run=True, meta={})

        start = time.perf_counter()
        try:
            # if sandbox requested and available -> delegate
            if use_sandbox and self.sandbox:
                # sandbox.run_in_sandbox accepts command list or string
                cmd = [str(path)]
                self._log("debug", "hook.sandbox_exec", f"Running hook in sandbox {name}", name=name, path=str(path))
                res = self.sandbox.run_in_sandbox(cmd, cwd=cwd, captures=True, env=env, timeout=timeout)
                rc = res.rc
                stdout = res.stdout or ""
                stderr = res.stderr or ""
                backend_used = res.backend or "sandbox"
            else:
                # run directly
                rc, stdout, stderr = self._run_via_subprocess(str(path), cwd=cwd, env=env, timeout=timeout)
                backend_used = "direct"
            duration = time.perf_counter() - start

            # log result
            if rc == 0:
                self._log("info", "hook.ok", f"Hook {name} succeeded (rc=0) in {duration:.3f}s", name=name, path=str(path), duration=duration)
            else:
                self._log("error", "hook.fail", f"Hook {name} failed rc={rc}", name=name, path=str(path), rc=rc, stderr=stderr)

            # record in DB
            try:
                meta = {"path": str(path), "timestamp": int(time.time())}
                self._record_hook_db(name, rc, duration, backend_used, meta)
            except Exception:
                pass

            return HookResult(name=name, path=str(path), rc=rc, duration=duration, stdout=stdout, stderr=stderr, backend=backend_used, dry_run=False, meta={"cached_entry": entry})
        except subprocess.TimeoutExpired:
            duration = time.perf_counter() - start
            self._log("error", "hook.timeout", f"Hook {name} timed out after {timeout}s", name=name, timeout=timeout)
            try:
                self._record_hook_db(name, 124, duration, "timeout", {"path": str(path)})
            except Exception:
                pass
            return HookResult(name=name, path=str(path), rc=124, duration=duration, stdout="", stderr=f"timeout after {timeout}s", backend="timeout", dry_run=False, meta={})
        except Exception as e:
            duration = time.perf_counter() - start
            self._log("error", "hook.exception", f"Hook {name} raised exception: {e}", name=name, exc=str(e))
            try:
                self._record_hook_db(name, 255, duration, "exception", {"path": str(path), "error": str(e)})
            except Exception:
                pass
            return HookResult(name=name, path=str(path), rc=255, duration=duration, stdout="", stderr=str(e), backend="exception", dry_run=False, meta={})

    # ----------------- run many / safe execution -----------------
    def run_hooks(self, names: Iterable[str], cwd: Optional[Union[str, Path]] = None, env_extra: Optional[Dict[str, str]] = None,
                  use_sandbox: Optional[bool] = None, stop_on_fail: bool = True, timeout: Optional[int] = None) -> List[HookResult]:
        """
        Run multiple hooks sequentially. Returns list of HookResult.
        stop_on_fail: if True, abort on first non-zero rc.
        """
        out: List[HookResult] = []
        for n in names:
            r = self.run_hook(n, cwd=cwd, env_extra=env_extra, use_sandbox=use_sandbox, timeout=timeout)
            out.append(r)
            if r.rc != 0 and stop_on_fail:
                break
        return out

    def execute_safe(self, phase: str, names: Iterable[str], cwd: Optional[Union[str, Path]] = None, env_extra: Optional[Dict[str, str]] = None,
                     use_sandbox: Optional[bool] = None, stop_on_fail: bool = True, timeout: Optional[int] = None, json_output: Optional[bool] = None) -> Union[List[Dict[str, Any]], str]:
        """
        High-level safe executor used by other modules:
         - phase: logical name (e.g. 'pre_configure', 'post_install')
         - names: iterable of hook filenames (as discovered)
         - returns JSON string if json_output True or self.json_out True, else Python structures
        """
        json_output = self.json_out if json_output is None else bool(json_output)
        # discover and filter names existing
        all_hooks = self.discover_hooks(refresh=False)
        valid = [n for n in names if n in all_hooks]
        if not valid:
            self._log("debug", "hooks.execute_empty", f"No hooks to execute for phase {phase}", phase=phase)
            return json.dumps([]) if json_output else []

        # set contextual logging
        try:
            if self.logger and hasattr(self.logger, "set_context"):
                self.logger.set_context(phase=phase)
        except Exception:
            pass

        results = self.run_hooks(valid, cwd=cwd, env_extra=env_extra, use_sandbox=use_sandbox, stop_on_fail=stop_on_fail, timeout=timeout)
        out = [r.to_dict() for r in results]

        # record top-level phase in DB
        try:
            if self.db and hasattr(self.db, "record_phase"):
                status = "ok" if all(r.rc == 0 for r in results) else "error"
                self.db.record_phase(package=self._cfg_get("general.default_package") or "global", phase=f"hooks.{phase}", status=status, meta={"count": len(results), "success": sum(1 for r in results if r.rc == 0)})
        except Exception:
            pass

        # reset context
        try:
            if self.logger and hasattr(self.logger, "clear_context"):
                self.logger.clear_context()
        except Exception:
            pass

        if json_output:
            return json.dumps(out, indent=2)
        return out

    # ----------------- CLI -----------------
    @staticmethod
    def _cli_main():
        import argparse
        p = argparse.ArgumentParser(prog="newpkg-hooks", description="Discover and execute newpkg hooks")
        p.add_argument("--list", action="store_true", help="list discovered hooks")
        p.add_argument("--refresh", action="store_true", help="refresh discovery cache")
        p.add_argument("--run", nargs="+", help="run listed hook names")
        p.add_argument("--cwd", help="working directory for hook execution")
        p.add_argument("--no-sandbox", action="store_true", help="do not use sandbox")
        p.add_argument("--json", action="store_true", help="output JSON")
        args = p.parse_args()

        cfg = init_config() if init_config else None
        logger = NewpkgLogger.from_config(cfg, NewpkgDB(cfg)) if NewpkgLogger and cfg else None
        hooks = NewpkgHooks(cfg=cfg, logger=logger, db=NewpkgDB(cfg) if NewpkgDB and cfg else None)
        if args.list:
            discovered = hooks.discover_hooks(refresh=args.refresh)
            if args.json:
                print(json.dumps(discovered, indent=2))
            else:
                for name, meta in discovered.items():
                    print(f"{name:40} {meta.get('path')}")
            raise SystemExit(0)

        if args.run:
            use_sandbox = not args.no_sandbox
            res = hooks.execute_safe("cli", args.run, cwd=args.cwd, use_sandbox=use_sandbox, json_output=args.json)
            if args.json:
                print(res)
            else:
                for item in (json.loads(res) if isinstance(res, str) else res):
                    print(f"{item['name']}: rc={item['rc']} duration={item['duration']:.3f}s")
            # non-zero exit code if any hook failed
            ok = True
            for item in (json.loads(res) if isinstance(res, str) else res):
                if item.get("rc", 0) != 0:
                    ok = False
                    break
            raise SystemExit(0 if ok else 2)

    # expose CLI convenience
    run_cli = _cli_main


# If executed as script
if __name__ == "__main__":
    NewpkgHooks._cli_main()
