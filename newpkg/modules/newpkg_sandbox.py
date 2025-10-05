#!/usr/bin/env python3
# newpkg_sandbox.py
"""
newpkg_sandbox.py — sandbox runner for newpkg

Responsibilities:
 - Provide secure sandboxed execution using bubblewrap (bwrap), proot or 'none' (no sandbox)
 - Respect configuration from newpkg_config (sandbox.* and sandbox.layout.*)
 - Propagate cfg.as_env() into subprocess environments
 - Respect general.dry_run, output.quiet, output.json
 - Register runs and metrics into newpkg_db via record_phase when available
 - Return structured SandboxResult for programmatic use (and JSON serializable)
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# optional project imports
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

# fallback stdlib logger for internal fallback messages (not main structured logger)
import logging
_logger = logging.getLogger("newpkg.sandbox")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.sandbox: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


@dataclass
class SandboxResult:
    backend: str
    command: Union[str, List[str]]
    cwd: Optional[str]
    rc: int
    stdout: Optional[str]
    stderr: Optional[str]
    duration: float
    dry_run: bool = False
    meta: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # ensure meta is JSON-serializable
        d["meta"] = d.get("meta") or {}
        return d


class NewpkgSandbox:
    SUPPORTED_BACKENDS = ("bwrap", "proot", "none")

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None):
        # load config / logger / db (best-effort)
        self.cfg = cfg or (init_config() if init_config else None)
        # instantiate logger if provided or available
        if logger:
            self.logger = logger
        else:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, db) if NewpkgLogger and self.cfg else None
            except Exception:
                self.logger = None
        # db instance
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)

        # config defaults
        self.backend = (self._cfg_get("sandbox.backend") or "bwrap").lower()
        if self.backend not in self.SUPPORTED_BACKENDS:
            self.backend = "none"
        self.enabled = bool(self._cfg_get("sandbox.enabled", True))
        self.bind_ro = list(self._cfg_get("sandbox.default_bind_ro", ["/usr", "/lib", "/bin", "/etc"]) or [])
        self.bind_rw = list(self._cfg_get("sandbox.default_bind_rw", ["/tmp", "/var/tmp"]) or [])
        self.fakeroot = bool(self._cfg_get("sandbox.fakeroot", True))
        self.network = bool(self._cfg_get("sandbox.network", False))
        self.preserve_tmp = bool(self._cfg_get("sandbox.preserve_tmp", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))
        self.dry_run = bool(self._cfg_get("general.dry_run", False))

        # resource-limits config (optional)
        self.max_mem_mb = self._cfg_get("sandbox.max_mem_mb", None)
        self.max_cpu_time = self._cfg_get("sandbox.max_cpu_seconds", None)

        # layouts per profile (optional)
        self.layouts = self._cfg_get("sandbox.layout") or {}

        # find binaries
        self._bwrap_bin = shutil.which("bwrap")
        self._proot_bin = shutil.which("proot") or shutil.which("proot-static")

        # prepare logger wrapper
        self._log = self._make_logger()

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        # fall back to environment variables
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
            # fallback to module logger
            getattr(_logger, level.lower(), _logger.info)(f"{event}: {msg} - {meta}")
        return _fn

    # ----------------- helpers -----------------
    def _build_env(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Combine host env, cfg.as_env() and extra overrides. Blacklist critical envs."""
        env = dict(os.environ)
        try:
            if self.cfg and hasattr(self.cfg, "as_env"):
                env.update(self.cfg.as_env())
        except Exception:
            pass
        if extra:
            env.update({k: str(v) for k, v in (extra.items())})
        # remove dangerous envs that may bypass sandbox (best-effort)
        for k in ("LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
            if k in env:
                env.pop(k, None)
        return env

    def _layout_for_profile(self, profile: Optional[str]) -> Dict[str, Any]:
        """Return layout settings merged with defaults for the requested profile."""
        base = {
            "bind_ro": list(self.bind_ro),
            "bind_rw": list(self.bind_rw),
            "network": self.network,
            "fakeroot": self.fakeroot,
        }
        if profile and isinstance(self.layouts, dict):
            prof = self.layouts.get(profile) or {}
            # merge arrays carefully
            if "bind_ro" in prof:
                base["bind_ro"] = list(prof.get("bind_ro", [])) + base["bind_ro"]
            if "bind_rw" in prof:
                base["bind_rw"] = list(prof.get("bind_rw", [])) + base["bind_rw"]
            for k, v in prof.items():
                if k not in ("bind_ro", "bind_rw"):
                    base[k] = v
        return base

    def _backend_available(self, backend: str) -> bool:
        if backend == "bwrap":
            return bool(self._bwrap_bin)
        if backend == "proot":
            return bool(self._proot_bin)
        if backend == "none":
            return True
        return False

    # ----------------- core API -----------------
    def run_in_sandbox(self,
                       command: Union[str, Sequence[str]],
                       cwd: Optional[Union[str, Path]] = None,
                       profile: Optional[str] = None,
                       captures: bool = True,
                       env: Optional[Dict[str, str]] = None,
                       timeout: Optional[int] = None) -> SandboxResult:
        """
        Run a command inside the configured sandbox.
        - command: str or list.
        - cwd: working directory inside sandbox (host path bound or path inside sysroot).
        - profile: sandbox layout profile to apply (reads sandbox.layout.<profile>).
        - captures: if True capture stdout/stderr and include in result.
        - env: extra environment variables (merged with cfg.as_env()).
        - timeout: seconds to wait before kill (best-effort).
        """
        # normalize command
        if isinstance(command, (list, tuple)):
            cmd_list = [str(x) for x in command]
            cmd_str = " ".join(shlex.quote(x) for x in cmd_list)
        else:
            cmd_str = str(command)
            cmd_list = None  # will be used only when no sandboxing wrapper needed

        # early dry-run behavior
        if self.dry_run:
            self._log("info", "sandbox.dryrun", f"DRY-RUN sandbox {self.backend}: {cmd_str}", command=cmd_str, backend=self.backend)
            return SandboxResult(
                backend=self.backend,
                command=command,
                cwd=str(cwd) if cwd else None,
                rc=0,
                stdout="",
                stderr="",
                duration=0.0,
                dry_run=True,
                meta={"simulated": True},
            )

        # choose backend (respect enabled + availability)
        backend = self.backend if self.enabled else "none"
        if not self._backend_available(backend):
            self._log("warning", "sandbox.backend_missing", f"Backend {backend} not available, falling back to none", backend=backend)
            backend = "none"

        # prepare layout and env
        layout = self._layout_for_profile(profile)
        exec_env = self._build_env(env)

        # make temporary working directory for sandbox (host path)
        tmpdir = Path(tempfile.mkdtemp(prefix="newpkg-sbox-"))
        workdir = tmpdir if cwd is None else Path(cwd)
        # if cwd provided and not absolute, consider inside tmpdir
        if cwd and not Path(cwd).is_absolute():
            workdir = tmpdir.joinpath(cwd)
            workdir.mkdir(parents=True, exist_ok=True)
        # else if absolute ensure directory exists (best-effort)
        if workdir.is_absolute():
            try:
                workdir.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

        # build command wrapper for backends
        cmd_wrapper: List[str] = []
        if backend == "bwrap":
            # compose bwrap command
            bwrap = self._bwrap_bin
            cmd_wrapper = [bwrap, "--unshare-all", "--share-net"] if not layout.get("network", False) else [bwrap, "--unshare-all"]
            # add readonly binds
            for d in layout.get("bind_ro", []):
                cmd_wrapper += ["--ro-bind", d, d]
            # add writable binds
            for d in layout.get("bind_rw", []):
                cmd_wrapper += ["--bind", d, d]
            # mount /tmp inside sandbox to tmpdir
            cmd_wrapper += ["--tmpfs", "/tmp"]
            # optionally set working directory inside sandbox to same host path
            if workdir:
                cmd_wrapper += ["--chdir", str(workdir)]
            # fakeroot support: if enabled and installed, prefix with fakeroot (best-effort)
            if layout.get("fakeroot", False):
                # some systems have fakeroot binary; prefer fakeroot -s
                fakeroot_bin = shutil.which("fakeroot")
                if fakeroot_bin:
                    cmd_wrapper = [fakeroot_bin, "--"] + cmd_wrapper
            # resource limits: bubblewrap does not directly enforce mem limits; we leave to ulimit via shell if desired
            # append command
            if cmd_list:
                cmd_wrapper += cmd_list
            else:
                cmd_wrapper += ["sh", "-lc", cmd_str]
        elif backend == "proot":
            proot = self._proot_bin
            cmd_wrapper = [proot]
            # map binds
            for d in layout.get("bind_ro", []):
                cmd_wrapper += ["-b", f"{d}:{d}"]
            for d in layout.get("bind_rw", []):
                cmd_wrapper += ["-b", f"{d}:{d}"]
            # set cwd
            if workdir:
                cmd_wrapper += ["-w", str(workdir)]
            if cmd_list:
                cmd_wrapper += cmd_list
            else:
                cmd_wrapper += ["sh", "-lc", cmd_str]
        else:  # none
            if cmd_list:
                cmd_wrapper = cmd_list
            else:
                cmd_wrapper = ["sh", "-lc", cmd_str]

        # run and measure
        start = time.perf_counter()
        try:
            self._log("info", "sandbox.exec.start", f"Running sandbox command with backend={backend}", backend=backend, command=cmd_str, cwd=str(workdir))
            proc = subprocess.run(
                cmd_wrapper,
                cwd=str(workdir) if workdir else None,
                env=exec_env,
                stdout=subprocess.PIPE if captures else None,
                stderr=subprocess.PIPE if captures else None,
                text=True,
                timeout=timeout,
            )
            duration = time.perf_counter() - start
            stdout = proc.stdout if captures else None
            stderr = proc.stderr if captures else None
            rc = proc.returncode
            result = SandboxResult(
                backend=backend,
                command=cmd_str,
                cwd=str(workdir),
                rc=rc,
                stdout=stdout,
                stderr=stderr,
                duration=duration,
                dry_run=False,
                meta={"backend_bin": (self._bwrap_bin if backend == "bwrap" else self._proot_bin if backend == "proot" else "none")}
            )
            # logging
            if rc == 0:
                self._log("info", "sandbox.exec.ok", f"Sandbox command finished rc=0 in {duration:.3f}s", backend=backend, duration=duration, rc=rc)
            else:
                self._log("error", "sandbox.exec.fail", f"Sandbox command rc={rc} (took {duration:.3f}s)", backend=backend, duration=duration, rc=rc, stderr=stderr)
            # record to DB phases when available
            try:
                if self.db and hasattr(self.db, "record_phase"):
                    self.db.record_phase(package=self._context_package(), phase="sandbox.exec", status="ok" if rc == 0 else "error", meta={"backend": backend, "rc": rc, "duration": duration})
            except Exception:
                pass
            return result
        except subprocess.TimeoutExpired as e:
            duration = time.perf_counter() - start
            self._log("error", "sandbox.exec.timeout", f"Sandbox command timed out after {duration:.1f}s", timeout=timeout)
            try:
                if self.db and hasattr(self.db, "record_phase"):
                    self.db.record_phase(package=self._context_package(), phase="sandbox.exec", status="timeout", meta={"backend": backend, "timeout": timeout})
            except Exception:
                pass
            return SandboxResult(
                backend=backend,
                command=cmd_str,
                cwd=str(workdir),
                rc=124,
                stdout=None,
                stderr=f"timeout after {timeout}s",
                duration=duration,
                dry_run=False,
                meta={"timeout": timeout}
            )
        except Exception as e:
            duration = time.perf_counter() - start
            self._log("error", "sandbox.exec.error", f"Sandbox command raised exception: {e}", error=str(e))
            try:
                if self.db and hasattr(self.db, "record_phase"):
                    self.db.record_phase(package=self._context_package(), phase="sandbox.exec", status="error", meta={"backend": backend, "exception": str(e)})
            except Exception:
                pass
            return SandboxResult(
                backend=backend,
                command=cmd_str,
                cwd=str(workdir),
                rc=255,
                stdout=None,
                stderr=str(e),
                duration=duration,
                dry_run=False,
                meta={"exception": str(e)}
            )
        finally:
            # cleanup unless preserve_tmp requested
            try:
                if not self.preserve_tmp:
                    shutil.rmtree(tmpdir, ignore_errors=True)
                    self._log("debug", "sandbox.cleanup", f"Removed temporary sandbox dir {tmpdir}")
                else:
                    self._log("debug", "sandbox.preserve", f"Preserving temporary sandbox dir {tmpdir}")
            except Exception:
                pass

    # ----------------- convenience / helpers -----------------
    def _context_package(self) -> str:
        """Try to extract package context from logger context or cfg, fallback to 'global'."""
        try:
            if self.logger and hasattr(self.logger, "_context"):
                pkg = getattr(self.logger, "_context", {}).get("package")
                if pkg:
                    return pkg
        except Exception:
            pass
        # fallback
        try:
            return str(self._cfg_get("general.default_package") or "global")
        except Exception:
            return "global"

    # sugar for JSON-friendly call
    def run_in_sandbox_json(self, *args, **kwargs) -> str:
        res = self.run_in_sandbox(*args, **kwargs)
        return json.dumps(res.to_dict(), indent=2)

# Example usage when run directly
if __name__ == "__main__":
    cfg = init_config() if init_config else None
    sbox = NewpkgSandbox(cfg=cfg)
    # demo: run a simple command
    r = sbox.run_in_sandbox(["/bin/echo", "hello sandbox"], captures=True, timeout=10)
    print(json.dumps(r.to_dict(), indent=2))
