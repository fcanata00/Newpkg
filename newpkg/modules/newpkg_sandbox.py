#!/usr/bin/env python3
# newpkg_sandbox.py
"""
Revised newpkg_sandbox.py

Improvements included:
1. Dynamic backends: bubblewrap (bwrap), proot, fallback 'none'
2. Use --unshare-net for bwrap when network=False (stronger isolation)
3. perf_timer-like timing recorded via logger (and recorded in DB as phase)
4. Hooks: pre_sandbox_exec and post_sandbox_exec
5. Audit reporting on failures/timeouts (if newpkg_audit present)
6. Expand config variables into env via cfg.expand_all()
7. Ulimits support (max_cpu_time, max_mem_mb)
8. include start_time, end_time, backend_bin in result.meta
9. Option sandbox.reuse_tmp to reuse tmpdir between runs
10. Better logging and fail-safe fallbacks
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Optional integrations (best-effort)
try:
    from newpkg_config import init_config, get_config  # type: ignore
except Exception:
    init_config = None
    get_config = None

try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_db import NewpkgDB  # type: ignore
except Exception:
    NewpkgDB = None

try:
    from newpkg_hooks import HooksManager  # type: ignore
except Exception:
    HooksManager = None

try:
    from newpkg_audit import NewpkgAudit  # type: ignore
except Exception:
    NewpkgAudit = None

# fallback logger
import logging
_logger = logging.getLogger("newpkg.sandbox")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.sandbox: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


@dataclass
class SandboxResult:
    ok: bool
    rc: int
    stdout: str
    stderr: str
    start_time: float
    end_time: float
    duration: float
    backend: str
    backend_bin: Optional[str]
    meta: Dict[str, Any]


class Sandbox:
    """
    Sandbox manager: runs commands under bubblewrap (bwrap), proot, or directly (none).
    Provides safe env construction, ulimits, hooks, perf logging, DB recording and audit.
    """

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, audit: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        # logger
        self.logger = logger or (get_logger(self.cfg) if get_logger else None)
        # DB
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)
        # hooks
        self.hooks = hooks or (HooksManager(self.cfg) if HooksManager else None)
        # audit
        self.audit = audit or (NewpkgAudit(self.cfg) if NewpkgAudit else None)

        # detect available backends
        self.bwrap_bin = shutil.which("bwrap")
        self.proot_bin = shutil.which("proot")
        # default backend preference (config: sandbox.backend -> 'bwrap'|'proot'|'none'|'auto')
        self.backend_cfg = (self.cfg.get("sandbox.backend") if self.cfg and hasattr(self.cfg, "get") else None) or "auto"

        # prepare tmp reuse option
        self.reuse_tmp = bool(self._cfg_get("sandbox.reuse_tmp", False))
        self._shared_tmpdir: Optional[Path] = None

        # default allowed ulimits (None means not set)
        self.max_cpu_time = int(self._cfg_get("sandbox.max_cpu_time", 0)) or None  # seconds
        self.max_mem_mb = int(self._cfg_get("sandbox.max_mem_mb", 0)) or None  # MB

        # default to disabling network unless config requests it
        self.allow_network = bool(self._cfg_get("sandbox.network", False))

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

    # ---------------- tmpdir management ----------------
    @contextmanager
    def _tmpdir(self, prefix: str = "newpkg-sandbox-"):
        """
        Context manager for temporary directory allocation. Respects reuse_tmp option.
        """
        if self.reuse_tmp:
            if self._shared_tmpdir is None:
                base = Path(self._cfg_get("sandbox.tmp_base", "/tmp")).expanduser()
                base.mkdir(parents=True, exist_ok=True)
                self._shared_tmpdir = Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))
            yield self._shared_tmpdir
        else:
            td = Path(tempfile.mkdtemp(prefix=prefix))
            try:
                yield td
            finally:
                # cleanup unless reuse requested
                try:
                    shutil.rmtree(td)
                except Exception:
                    pass

    # ---------------- utilities ----------------
    def _which(self, exe: str) -> Optional[str]:
        return shutil.which(exe)

    def _expand_env_spec(self, env_spec: Dict[str, Any]) -> Dict[str, str]:
        """
        Expand variables in env_spec using cfg.expand_all() if available; convert non-str to JSON.
        """
        out = {}
        try:
            # if config has expansion helpers, use them
            if self.cfg and hasattr(self.cfg, "expand_all"):
                # apply shallow expansion of strings via cfg._expand_str if exists, else fallback
                def expand_val(v):
                    if isinstance(v, str):
                        if hasattr(self.cfg, "_expand_str"):
                            return self.cfg._expand_str(v, 10)
                        return v
                    if isinstance(v, dict):
                        return {k: expand_val(x) for k, x in v.items()}
                    if isinstance(v, list):
                        return [expand_val(x) for x in v]
                    return v
                env_spec = expand_val(env_spec)
        except Exception:
            pass
        for k, v in env_spec.items():
            if isinstance(v, (dict, list)):
                try:
                    out[k] = json.dumps(v, ensure_ascii=False)
                except Exception:
                    out[k] = str(v)
            else:
                out[k] = "" if v is None else str(v)
        return out

    # ---------------- build sandbox command ----------------
    def _build_bwrap_cmd(self,
                         cmd: List[str],
                         workdir: Optional[str],
                         tmpdir: Path,
                         binds: Optional[Iterable[Tuple[str, str]]] = None,
                         ro_binds: Optional[Iterable[Tuple[str, str]]] = None,
                         env: Optional[Dict[str, str]] = None,
                         use_fakeroot: bool = False) -> Tuple[List[str], Optional[str]]:
        """
        Construct a bubblewrap command list safely. Return (cmd_list, bwrap_binary)
        """
        bwrap = self.bwrap_bin
        if not bwrap:
            return (cmd, None)
        c = [bwrap, "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--die-with-parent"]
        # network isolation: if not allowed, unshare net; otherwise allow share-net
        if not self.allow_network:
            # prefer explicit unshare-net (stronger)
            c += ["--unshare-net"]
        else:
            # if user requested network, allow network namespace share (or nothing)
            c += ["--share-net"]

        # set working directories and tmp
        c += ["--tmpfs", "/tmp", "--bind", str(tmpdir), "/var/tmp"]
        # ensure working directory exists inside
        if workdir:
            c += ["--bind", workdir, workdir]
        # read-only binds
        if ro_binds:
            for src, dst in ro_binds:
                c += ["--ro-bind", src, dst]
        if binds:
            for src, dst in binds:
                c += ["--bind", src, dst]

        # fakeroot (if requested)
        if use_fakeroot:
            c += ["--dev", "/dev", "--proc", "/proc"]

        # pass environment via --setenv
        if env:
            for k, v in env.items():
                c += ["--setenv", k, v]

        # finally the command to run (use -- to separate)
        c += ["--"] + cmd
        return (c, bwrap)

    def _build_proot_cmd(self,
                        cmd: List[str],
                        workdir: Optional[str],
                        tmpdir: Path,
                        binds: Optional[Iterable[Tuple[str, str]]] = None,
                        ro_binds: Optional[Iterable[Tuple[str, str]]] = None,
                        env: Optional[Dict[str, str]] = None,
                        use_fakeroot: bool = False) -> Tuple[List[str], Optional[str]]:
        """
        Construct a proot command list. Simpler fallback than bwrap.
        """
        proot = self.proot_bin
        if not proot:
            return (cmd, None)
        c = [proot]
        # add binds
        if binds:
            for src, dst in binds:
                c += ["-b", f"{src}:{dst}"]
        if ro_binds:
            for src, dst in ro_binds:
                c += ["-b", f"{src}:{dst}:ro"]
        # env via -S or -e? proot doesn't have standard env flags; use env wrapper
        if env:
            env_cmd = []
            for k, v in env.items():
                env_cmd += [f"{k}={shlex.quote(v)}"]
            if env_cmd:
                # prefix command with env VAR=... sh -c 'cmd'
                cmd = ["/bin/sh", "-c", " ".join(env_cmd) + " " + " ".join(shlex.quote(x) for x in cmd)]
        c += ["--"] + cmd
        return (c, proot)

    # ---------------- ulimit wrapper ----------------
    def _wrap_with_ulimit(self, cmd: List[str]) -> List[str]:
        """
        Wrap a command with shell ulimit preface if ulimits configured.
        Returns a shell invocation list: ['/bin/sh', '-c', 'ulimit ... && exec ...']
        """
        ulimit_parts = []
        if self.max_cpu_time:
            ulimit_parts.append(f"ulimit -t {int(self.max_cpu_time)}")
        if self.max_mem_mb:
            # convert MB to KB for ulimit -v (virtual memory)
            kb = int(self.max_mem_mb) * 1024
            ulimit_parts.append(f"ulimit -v {kb}")
        if not ulimit_parts:
            return cmd
        # construct safe shell command
        cmd_line = " && ".join(ulimit_parts) + " && exec " + " ".join(shlex.quote(x) for x in cmd)
        return ["/bin/sh", "-c", cmd_line]

    # ---------------- call hooks safely ----------------
    def _call_hook(self, name: str, context: Dict[str, Any]) -> None:
        if not self.hooks:
            return
        try:
            self.hooks.run(name, context)
        except Exception as e:
            # don't let hooks break execution; log and continue
            if self.logger:
                self.logger.warning("sandbox.hook.fail", f"hook {name} failed: {e}", hook=name)
            else:
                _logger.warning(f"hook {name} failed: {e}")

    # ---------------- run command in sandbox ----------------
    def run_in_sandbox(self,
                       cmd: List[str],
                       workdir: Optional[str] = None,
                       env: Optional[Dict[str, Any]] = None,
                       binds: Optional[Iterable[Tuple[str, str]]] = None,
                       ro_binds: Optional[Iterable[Tuple[str, str]]] = None,
                       backend: Optional[str] = None,
                       use_fakeroot: bool = False,
                       timeout: Optional[int] = None,
                       record_phase_name: Optional[str] = "sandbox.exec") -> SandboxResult:
        """
        Run a command in the configured sandbox backend.
        - cmd: list of command tokens
        - workdir: filesystem path to bind as working directory
        - env: mapping to be applied (strings or structured)
        - binds / ro_binds: iterable of (src, dst) tuples for bind mounts
        - backend: override detected backend ('bwrap','proot','none','auto')
        - use_fakeroot: enable fakeroot-style binds
        - timeout: seconds
        Returns SandboxResult with metadata and stdout/stderr.
        """
        # prepare metadata
        chosen_backend = backend or self.backend_cfg or "auto"
        timeout = timeout or int(self._cfg_get("sandbox.timeout", 0)) or None
        start_time = time.time()

        # call pre hook
        self._call_hook("pre_sandbox_exec", {"cmd": cmd, "workdir": workdir})

        # expand env
        final_env = os.environ.copy()
        if env:
            try:
                expanded = self._expand_env_spec(env)
                final_env.update(expanded)
            except Exception:
                # fallback: cast to strings
                for k, v in (env or {}).items():
                    final_env[k] = "" if v is None else str(v)

        # wrap with ulimit if configured
        cmd_wrapped = self._wrap_with_ulimit(cmd)

        # pick backend binary
        backend_used = "none"
        backend_bin = None
        b_cmd: List[str] = cmd_wrapped

        # choose backend: bwrap preferred, then proot, else none
        if chosen_backend == "auto":
            if self.bwrap_bin:
                chosen_backend = "bwrap"
            elif self.proot_bin:
                chosen_backend = "proot"
            else:
                chosen_backend = "none"

        if chosen_backend == "bwrap":
            b_cmd, backend_bin = self._build_bwrap_cmd(cmd_wrapped, workdir, Path(self._cfg_get("sandbox.tmp_base", "/tmp")), binds=binds, ro_binds=ro_binds, env=final_env, use_fakeroot=use_fakeroot)
            backend_used = "bwrap"
        elif chosen_backend == "proot":
            b_cmd, backend_bin = self._build_proot_cmd(cmd_wrapped, workdir, Path(self._cfg_get("sandbox.tmp_base", "/tmp")), binds=binds, ro_binds=ro_binds, env=final_env, use_fakeroot=use_fakeroot)
            backend_used = "proot"
        else:
            # none: run directly
            b_cmd = cmd_wrapped
            backend_used = "none"
            backend_bin = None

        # perform the run in a tmpdir context (reuse if configured)
        with self._tmpdir() as td:
            td = Path(td)
            # ensure working directory exists and bind if necessary
            if workdir:
                try:
                    Path(workdir).mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass

            # record prepare phase
            try:
                if self.db:
                    self.db.record_phase(None, "sandbox.prepare", "ok", meta={"backend": backend_used, "workdir": workdir})
            except Exception:
                pass

            # run
            rc = 0
            stdout = ""
            stderr = ""
            ok = False
            exc_info = None

            # if logging/perf available, measure
            perf_start = time.time()
            try:
                # logs
                if self.logger:
                    try:
                        self.logger.info("sandbox.run.start", f"Running command in sandbox", backend=backend_used, cmd=" ".join(cmd), workdir=workdir)
                    except Exception:
                        pass
                # execute subprocess with capture
                proc = subprocess.Popen(b_cmd, cwd=(workdir or None), env=final_env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    out_bytes, err_bytes = proc.communicate(timeout=timeout)
                    rc = proc.returncode
                    stdout = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""
                    stderr = err_bytes.decode("utf-8", errors="replace") if err_bytes else ""
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out_bytes, err_bytes = proc.communicate()
                    stdout = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""
                    stderr = err_bytes.decode("utf-8", errors="replace") if err_bytes else ""
                    rc = 124
                    stderr += "\n[timeout]"
                ok = (rc == 0)
            except Exception as e:
                exc_info = e
                rc = 1
                stderr += f"\n[exception] {e}"
                ok = False
            perf_end = time.time()

            # record exec phase in DB and logger
            try:
                meta = {"backend": backend_used, "backend_bin": backend_bin, "start_time": perf_start, "end_time": perf_end, "duration": round(perf_end - perf_start, 3)}
                if self.db:
                    # record a sandbox.exec phase
                    self.db.record_phase(None, record_phase_name or "sandbox.exec", "ok" if ok else "fail", meta=meta)
                if self.logger:
                    if ok:
                        self.logger.info("sandbox.run.ok", f"Sandbox run finished", backend=backend_used, duration=round(perf_end - perf_start, 3))
                    else:
                        # include stderr in logs for debug
                        self.logger.error("sandbox.run.fail", f"Sandbox run failed rc={rc}", backend=backend_used, rc=rc, stderr=(stderr[:4000] if stderr else ""))
            except Exception:
                pass

            # audit on failure/timeouts
            if not ok:
                try:
                    if self.audit:
                        self.audit.report("sandbox", "failed", {"backend": backend_used, "rc": rc, "stderr": stderr[:4000]})
                except Exception:
                    pass

            end_time = time.time()
            duration = end_time - start_time

            # call post hook
            try:
                self._call_hook("post_sandbox_exec", {"cmd": cmd, "workdir": workdir, "ok": ok, "rc": rc, "stdout": stdout, "stderr": stderr})
            except Exception:
                pass

            result = SandboxResult(
                ok=ok,
                rc=rc,
                stdout=stdout,
                stderr=stderr,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                backend=backend_used,
                backend_bin=backend_bin,
                meta={"backend": backend_used, "backend_bin": backend_bin, "start": start_time, "end": end_time, "duration": round(duration, 3)}
            )

            return result

    # ---------------- convenience wrappers ----------------
    def run_shell(self,
                  sh_cmd: str,
                  **kwargs) -> SandboxResult:
        """
        Convenience: run a shell command string via /bin/sh -c
        """
        return self.run_in_sandbox(["/bin/sh", "-c", sh_cmd], **kwargs)

    # ---------------- finalize / cleanup ----------------
    def cleanup_shared_tmp(self) -> bool:
        """
        Remove shared tmpdir if reuse_tmp was set.
        """
        if self.reuse_tmp and self._shared_tmpdir:
            try:
                shutil.rmtree(self._shared_tmpdir)
                self._shared_tmpdir = None
                return True
            except Exception:
                return False
        return True


# ---------------- module-level convenience ----------------
_default_sandbox: Optional[Sandbox] = None


def get_sandbox(cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, audit: Any = None) -> Sandbox:
    global _default_sandbox
    if _default_sandbox is None:
        _default_sandbox = Sandbox(cfg=cfg, logger=logger, db=db, hooks=hooks, audit=audit)
    return _default_sandbox


# ---------------- quick self-test CLI ----------------
if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser(prog="newpkg-sandbox-test", description="Test sandbox runner")
    parser.add_argument("--cmd", "-c", help="command to run", default="echo hello; sleep 0.1; echo done")
    parser.add_argument("--backend", help="backend override (bwrap/proot/none/auto)", default=None)
    parser.add_argument("--workdir", help="working directory", default=None)
    parser.add_argument("--reuse", action="store_true", help="reuse tmpdir between runs")
    args = parser.parse_args()
    cfg = init_config() if init_config else None
    sb = get_sandbox(cfg=cfg)
    sb.reuse_tmp = bool(args.reuse)
    res = sb.run_shell(args.cmd, backend=args.backend, workdir=args.workdir, timeout=30)
    print(json.dumps(asdict(res), indent=2, default=str))
