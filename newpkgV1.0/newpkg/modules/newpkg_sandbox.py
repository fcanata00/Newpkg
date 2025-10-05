#!/usr/bin/env python3
# newpkg_sandbox.py
"""
Revised newpkg_sandbox.py

Responsibilities:
 - Provide a safe sandbox wrapper for running arbitrary commands used by newpkg.
 - Backends: bubblewrap (bwrap), proot, none (no isolation).
 - Support fakeroot (if available) to emulate root for packaging operations.
 - Optional overlay support for bwrap.
 - Timeout model: soft timeout (warning) and hard timeout (kill).
 - Environment sanitization and expansion caching.
 - Perf logging (duration, optional cpu/mem sampling) via newpkg_logger.perf_timer and db phases.
 - Registers itself with newpkg_api as api.sandbox if available.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional integrations (best-effort)
try:
    from newpkg_api import get_api  # type: ignore
except Exception:
    get_api = None

try:
    from newpkg_config import get_config  # type: ignore
except Exception:
    get_config = None

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

# fallback logger
import logging
_logger = logging.getLogger("newpkg.sandbox")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.sandbox: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# sensitive env keys to remove prior to sandboxing
_DEFAULT_SENSITIVE_PREFIXES = ("GPG_", "SSH_", "AWS_", "AZURE_", "DOCKER_", "SECRET", "TOKEN", "API_KEY", "APIKEY")
_DEFAULT_SENSITIVE_KEYS = {"PASSWORD", "PASS", "SECRET", "TOKEN", "API_KEY", "APIKEY", "SSH_AUTH_SOCK"}

# helper
def _which(binname: str) -> Optional[str]:
    p = shutil.which(binname)
    return p

def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

# dataclasses
@dataclass
class SandboxResult:
    rc: int
    stdout: str
    stderr: str
    duration: float
    killed_by: Optional[str] = None
    timed_out: bool = False
    tmp_dir: Optional[str] = None

class Sandbox:
    """
    Sandbox orchestrator.

    Typical usage:
        sb = Sandbox(cfg=get_config(), logger=get_logger())
        res = sb.run_in_sandbox(["make", "-j4"], cwd="/work/build", env={"CFLAGS":"-O2"}, timeout_hard=3600)
    """

    def __init__(self, cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, hooks: Optional[Any] = None):
        # Prefer singletons from API if available
        self.api = None
        if get_api:
            try:
                self.api = get_api()
                try:
                    self.api.init_all()
                except Exception:
                    pass
            except Exception:
                self.api = None

        self.cfg = cfg or (self.api.cfg if self.api and getattr(self.api, "cfg", None) else (get_config() if get_config else None))
        self.logger = logger or (self.api.logger if self.api and getattr(self.api, "logger", None) else (get_logger(self.cfg) if get_logger else None))
        self.db = db or (self.api.db if self.api and getattr(self.api, "db", None) else (get_db() if get_db else None))
        self.hooks = hooks or (self.api.hooks if self.api and getattr(self.api, "hooks", None) else (get_hooks_manager(self.cfg) if get_hooks_manager else None))

        # Register to API
        try:
            if self.api:
                self.api.sandbox = self
        except Exception:
            pass

        # backend selection from cfg or env (default bwrap)
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.backend = self.cfg.get("sandbox.backend") or os.environ.get("NEWPKG_SANDBOX_BACKEND", "bwrap")
                self.use_fakeroot_cfg = bool(self.cfg.get("sandbox.fakeroot", True))
                self.overlay_cfg = bool(self.cfg.get("sandbox.overlay", False))
                self.env_sanitize_extra = set([k.upper() for k in (self.cfg.get("sandbox.sanitize_keys") or [])])
            else:
                self.backend = os.environ.get("NEWPKG_SANDBOX_BACKEND", "bwrap")
                self.use_fakeroot_cfg = True
                self.overlay_cfg = False
                self.env_sanitize_extra = set()
        except Exception:
            self.backend = "bwrap"
            self.use_fakeroot_cfg = True
            self.overlay_cfg = False
            self.env_sanitize_extra = set()

        # availability detection
        self._bin_bwrap = _which("bwrap")
        self._bin_proot = _which("proot")
        self._bin_fakeroot = _which("fakeroot")
        # environment expansion cache (OrderedDict to limit size)
        self._env_cache: "OrderedDict[int, Dict[str,str]]" = OrderedDict()
        self._env_cache_lock = threading.RLock()
        self._env_cache_max = int(self.cfg.get("sandbox.env_cache_max", 64) if (self.cfg and hasattr(self.cfg, "get")) else 64)

    # ---------------- env sanitization and expansion ----------------
    def _sanitize_env(self, env: Optional[Dict[str, str]]) -> Dict[str, str]:
        """
        Remove potentially sensitive or host-specific variables before passing to the sandbox.
        Keeps basic PATH and minimal necessary vars if present.
        """
        out = {}
        if not env:
            env = {}
        # start from minimal base
        base_keep = ["PATH", "HOME", "LANG", "LC_ALL", "USER", "LOGNAME", "TMPDIR"]
        for k in base_keep:
            v = os.environ.get(k)
            if v:
                out[k] = v
        # then overlay provided env but sanitize keys
        for k, v in env.items():
            ku = k.upper()
            if ku in _DEFAULT_SENSITIVE_KEYS or ku in self.env_sanitize_extra:
                continue
            if any(ku.startswith(pref) for pref in _DEFAULT_SENSITIVE_PREFIXES):
                continue
            out[k] = v
        return out

    def _env_hash(self, env: Dict[str, str]) -> int:
        """
        Compute a small deterministic hash to use as key in env cache.
        """
        items = tuple(sorted(env.items()))
        return hash(items)

    def _expand_env_cached(self, env: Dict[str, str]) -> Dict[str, str]:
        """
        Expand environment variables (like ${VAR}) and cache results to avoid repeated work.
        """
        key = self._env_hash(env)
        with self._env_cache_lock:
            if key in self._env_cache:
                return dict(self._env_cache[key])
        # expand
        expanded = {}
        for k, v in env.items():
            if isinstance(v, str):
                try:
                    expanded[k] = os.path.expandvars(v)
                except Exception:
                    expanded[k] = v
            else:
                expanded[k] = str(v)
        # store in cache with simple eviction
        with self._env_cache_lock:
            self._env_cache[key] = expanded
            if len(self._env_cache) > self._env_cache_max:
                # pop oldest
                self._env_cache.popitem(last=False)
        return dict(expanded)

    # ---------------- helper to build command wrapper ----------------
    def _build_wrapper_cmd(self,
                           cmd: List[str],
                           cwd: Optional[str],
                           env: Optional[Dict[str, str]],
                           use_fakeroot: bool,
                           overlay: bool,
                           tmp_dir: Optional[str]) -> Tuple[List[str], Dict[str,str], Optional[str]]:
        """
        Returns (final_cmd, final_env, debug_note)
        """
        final_env = dict(env or {})
        final_env = self._sanitize_env(final_env)
        final_env = self._expand_env_cached(final_env)

        debug_note = None

        backend = (self.backend or "bwrap").lower()
        if backend == "bwrap":
            if not self._bin_bwrap:
                return [], final_env, "bwrap-not-found"
            bargs = [self._bin_bwrap]
            # common bwrap options for safe limited sandbox
            # mount minimal /proc and /dev
            bargs += ["--die-with-parent", "--unshare-pid", "--unshare-user", "--unshare-uts"]
            # bind /bin /lib /usr as read-only to allow execution
            # allow writable temp dir
            safe_tmp = tmp_dir or tempfile.mkdtemp(prefix="newpkg-bwrap-")
            # create tmp dir perms
            try:
                Path(safe_tmp).mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            # overlay support: create tmp overlay if requested
            if overlay or self.overlay_cfg:
                # create overlay tmp
                overlay_tmp = Path(safe_tmp) / "overlay"
                try:
                    overlay_tmp.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
                # mount overlay tmp as writable /build (user will chdir into cwd)
                bargs += ["--tmpfs", str(overlay_tmp)]
                # note: this is a light overlay simulation; for full overlayfs root privileges needed
                debug_note = "bwrap+overlay"
            else:
                debug_note = "bwrap"
            # common read-only binds (best-effort)
            for d in ("/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib"):
                if Path(d).exists():
                    bargs += ["--ro-bind", d, d]
            # bind /proc /dev minimal
            bargs += ["--proc", "/proc", "--dev", "/dev"]
            # preserve working dir
            if cwd:
                # make sure the cwd path exists on host and bind it inside sandbox
                try:
                    Path(cwd)  # no-op
                    # use same path inside
                    bargs += ["--bind", cwd, cwd]
                except Exception:
                    pass
            # do not preserve other mounts; set as env and run sh -c
            # wrapper: use -- to end bwrap args and then run command
            # if fakeroot requested and available, prefix command accordingly
            inner_cmd = cmd
            if use_fakeroot and self._bin_fakeroot:
                # use fakeroot to get fake root behavior inside bwrap
                inner_cmd = [self._bin_fakeroot, "--"] + inner_cmd
                debug_note += "+fakeroot"
            bargs += ["--"] + inner_cmd
            return bargs, final_env, debug_note

        elif backend == "proot":
            if not self._bin_proot:
                return [], final_env, "proot-not-found"
            pargs = [self._bin_proot]
            # proot options: -S (rootfs) not used here; just run in proot with cwd bind
            if cwd:
                pargs += ["-R", cwd]
            inner_cmd = cmd
            if use_fakeroot and self._bin_fakeroot:
                inner_cmd = [self._bin_fakeroot, "--"] + inner_cmd
                debug_note = "proot+fakeroot"
            else:
                debug_note = "proot"
            pargs += inner_cmd
            return pargs, final_env, debug_note

        elif backend in ("none", "host"):
            # run directly on host, optionally under fakeroot
            final_cmd = cmd
            if use_fakeroot and self._bin_fakeroot:
                final_cmd = [self._bin_fakeroot, "--"] + final_cmd
                debug_note = "host+fakeroot"
            else:
                debug_note = "host"
            return final_cmd, final_env, debug_note

        else:
            # unknown backend
            return [], final_env, f"backend-{backend}-unknown"

    # ---------------- CPU/memory sampling (best-effort) ----------------
    def _sample_usage(self, pid: int, interval: float, stop_event: threading.Event, out_list: List[Dict[str,Any]]):
        """
        Sample basic CPU/memory usage periodically for a pid (best-effort).
        Stores samples in out_list.
        """
        try:
            import psutil  # optional
        except Exception:
            return
        try:
            p = psutil.Process(pid)
        except Exception:
            return
        while not stop_event.wait(interval):
            try:
                cpu = p.cpu_percent(interval=None)
                mem = p.memory_info().rss
                out_list.append({"ts": _now_ts(), "cpu_percent": cpu, "rss": mem})
            except Exception:
                break

    # ---------------- run command with timeout soft/hard and hooks ----------------
    def run_in_sandbox(self,
                       cmd: List[str],
                       cwd: Optional[str] = None,
                       env: Optional[Dict[str,str]] = None,
                       timeout_soft: Optional[int] = None,
                       timeout_hard: Optional[int] = None,
                       use_fakeroot: Optional[bool] = None,
                       overlay: Optional[bool] = None,
                       reuse_tmp: bool = False,
                       sample_usage: bool = False,
                       use_perf_timer: bool = True) -> SandboxResult:
        """
        Run the given command in the configured sandbox backend.

        - timeout_soft: seconds before soft warning (logged). If None -> no soft.
        - timeout_hard: seconds to kill process. If None -> no hard timeout.
        - use_fakeroot: override cfg decision (True/False).
        - overlay: override cfg overlay behavior (True/False).
        - reuse_tmp: when False, a temporary directory will be created and cleaned after run.
        - sample_usage: if True and psutil available, sample cpu/memory.
        - use_perf_timer: if logger.perf_timer exists, we will record perf.
        """
        start = time.time()
        use_fakeroot = bool(self.use_fakeroot_cfg if use_fakeroot is None else use_fakeroot)
        overlay = bool(self.overlay_cfg if overlay is None else overlay)
        tmp_dir = None if reuse_tmp else tempfile.mkdtemp(prefix="newpkg-sandbox-")
        tmp_dir_path = str(tmp_dir) if tmp_dir else None

        # build wrapper command
        final_cmd, final_env, debug_note = self._build_wrapper_cmd(cmd, cwd, env, use_fakeroot, overlay, tmp_dir_path)
        if not final_cmd:
            # backend missing or unknown
            msg = f"sandbox backend unavailable: note={debug_note}"
            if self.logger:
                self.logger.error("sandbox.backend.missing", msg, meta={"backend": self.backend, "debug": debug_note})
            else:
                _logger.error(msg)
            return SandboxResult(rc=1, stdout="", stderr=msg, duration=0.0, tmp_dir=tmp_dir_path)

        # prepare process
        shell_mode = False  # we pass list directly
        proc = None
        killed_by = None
        timed_out = False
        stdout = ""
        stderr = ""
        usage_samples: List[Dict[str,Any]] = []
        stop_event = threading.Event()
        sampler_thread = None

        # pre-run hook
        try:
            if self.hooks:
                self.hooks.run("pre_sandbox_run", {"cmd": final_cmd, "cwd": cwd, "env_keys": list(final_env.keys()), "tmp_dir": tmp_dir_path})
        except Exception:
            pass

        # perf timer integration
        perf_ctx = None
        try:
            if use_perf_timer and self.logger and hasattr(self.logger, "perf_timer"):
                perf_ctx = self.logger.perf_timer("sandbox.exec", {"cmd": " ".join(final_cmd), "cwd": cwd})
                perf_ctx.__enter__()
        except Exception:
            perf_ctx = None

        try:
            # start proc
            proc = subprocess.Popen(final_cmd, cwd=cwd, env=final_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=shell_mode, preexec_fn=os.setsid)
            pid = proc.pid

            # optional usage sampler
            if sample_usage:
                stop_event.clear()
                sampler_thread = threading.Thread(target=self._sample_usage, args=(pid, 2.0, stop_event, usage_samples), daemon=True)
                sampler_thread.start()

            # soft timeout watcher
            soft_timer = None
            hard_timer = None
            soft_fired = threading.Event()

            def _soft_action():
                if proc and proc.poll() is None:
                    soft_fired.set()
                    msg = f"sandbox.soft_timeout fired after {timeout_soft}s for cmd={cmd}"
                    if self.logger:
                        self.logger.warning("sandbox.timeout.soft", msg, meta={"cmd": cmd, "cwd": cwd})
                    else:
                        _logger.warning(msg)

            def _hard_action():
                nonlocal killed_by, timed_out
                if proc and proc.poll() is None:
                    try:
                        # kill process group
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    timed_out = True
                    killed_by = "hard_timeout"
                    if self.logger:
                        self.logger.error("sandbox.timeout.hard", f"killed process after {timeout_hard}s", meta={"cmd": cmd})
                    else:
                        _logger.error("killed process after hard timeout")

            if timeout_soft:
                soft_timer = threading.Timer(timeout_soft, _soft_action)
                soft_timer.daemon = True
                soft_timer.start()
            if timeout_hard:
                hard_timer = threading.Timer(timeout_hard, _hard_action)
                hard_timer.daemon = True
                hard_timer.start()

            # wait for completion
            out, err = proc.communicate()
            stdout = out or ""
            stderr = err or ""
            rc = proc.returncode if proc.returncode is not None else (124 if timed_out else 1)

        except Exception as e:
            rc = 1
            stdout = ""
            stderr = str(e)
        finally:
            # cleanup timers and sampler
            try:
                if soft_timer:
                    soft_timer.cancel()
                if hard_timer:
                    hard_timer.cancel()
            except Exception:
                pass
            if sampler_thread:
                stop_event.set()
                try:
                    sampler_thread.join(timeout=1.0)
                except Exception:
                    pass
            # perf exit
            try:
                if perf_ctx:
                    perf_ctx.__exit__(None, None, None)
            except Exception:
                pass

        duration = time.time() - start

        # record DB phases & hooks
        try:
            if self.db:
                self.db.record_phase(None, "sandbox.exec", "ok" if rc == 0 else "fail", meta={"cmd": final_cmd, "cwd": cwd, "duration_s": duration, "rc": rc, "note": debug_note})
        except Exception:
            pass

        try:
            if self.hooks:
                self.hooks.run("post_sandbox_run", {"cmd": final_cmd, "cwd": cwd, "rc": rc, "duration": duration, "tmp_dir": tmp_dir_path})
        except Exception:
            pass

        # add usage samples in logs if any
        if usage_samples and self.logger:
            try:
                self.logger.info("sandbox.usage.samples", "usage samples collected", meta={"samples": usage_samples, "cmd": final_cmd})
            except Exception:
                pass

        # cleanup tmp dir if we created it and reuse_tmp=False
        if tmp_dir and not reuse_tmp:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass

        return SandboxResult(rc=rc, stdout=stdout, stderr=stderr, duration=duration, killed_by=killed_by, timed_out=timed_out, tmp_dir=tmp_dir_path)

# module-level accessor
_default_sandbox: Optional[Sandbox] = None
_sandbox_lock = threading.RLock()

def get_sandbox(cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, hooks: Optional[Any] = None) -> Sandbox:
    global _default_sandbox
    with _sandbox_lock:
        if _default_sandbox is None:
            _default_sandbox = Sandbox(cfg=cfg, logger=logger, db=db, hooks=hooks)
        return _default_sandbox

# simple CLI for testing
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-sandbox", description="test sandbox runner")
    p.add_argument("cmd", nargs="+", help="command to run inside sandbox (pass as separate args)")
    p.add_argument("--cwd", help="working directory")
    p.add_argument("--soft", type=int, help="soft timeout seconds")
    p.add_argument("--hard", type=int, help="hard timeout seconds")
    p.add_argument("--no-fakeroot", action="store_true", help="disable fakeroot wrapper")
    p.add_argument("--overlay", action="store_true", help="enable overlay for bwrap")
    p.add_argument("--sample", action="store_true", help="sample cpu/mem while running")
    args = p.parse_args()

    sb = get_sandbox()
    res = sb.run_in_sandbox(args.cmd, cwd=args.cwd, timeout_soft=args.soft, timeout_hard=args.hard, use_fakeroot=(not args.no_fakeroot), overlay=args.overlay, sample_usage=args.sample)
    pprint.pprint(res.__dict__)
