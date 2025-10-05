"""
newpkg_sandbox.py

Módulo de sandbox para newpkg — backend baseado em bubblewrap (bwrap) com suporte rootless,
integração com NewpkgLogger e NewpkgDB, e helpers para montar ambientes de build por pacote.

Funcionalidades principais:
- criar sandbox temporário persistente ou efêmero
- executar comandos (captura stdout/stderr)
- bind mounts controlados (apenas paths permitidos)
- método sandbox_for_package(pkg_name) que prepara /sources, /build, /dest
- registro de execuções no NewpkgDB (opcional)

Observações de segurança:
- exige bwrap disponível no PATH quando backend == 'bwrap'
- tenta executar em modo rootless (user namespaces) sem sudo

"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from contextlib import contextmanager


class SandboxError(Exception):
    pass


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    duration: float
    started_at: str
    finished_at: str


@dataclass
class NewpkgSandbox:
    cfg: Any = None
    logger: Any = None
    db: Any = None
    name: str = field(default_factory=lambda: f"sandbox-{uuid.uuid4().hex[:8]}")
    base_dir: Path = field(init=False)
    work_dir: Path = field(init=False)
    binds: List[Tuple[Path, Path, bool]] = field(default_factory=list)  # (src, dest, ro)
    backend: str = field(init=False)
    allowed_binds: List[Path] = field(default_factory=list)
    persistent: bool = field(init=False)

    def __post_init__(self):
        # defaults
        tmp = None
        try:
            tmp = self.cfg.get("SANDBOX_TMPDIR")
        except Exception:
            tmp = None
        base_tmp = Path(tmp) if tmp else Path(tempfile.gettempdir())

        # ensure base dir
        base_tmp.mkdir(parents=True, exist_ok=True)

        self.base_dir = base_tmp / self.name
        self.work_dir = self.base_dir / "work"
        self.backend = (self.cfg.get("SANDBOX_BACKEND") if self.cfg else None) or "bwrap"
        self.persistent = self._to_bool(self.cfg.get("SANDBOX_PERSIST") if self.cfg else False)
        self.allowed_binds = [Path(x) for x in (self.cfg.get("SANDBOX_DEFAULT_BIND") or "/dev,/proc,/sys").split(",")]

        # prepare dirs (but do not populate heavy mounts)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)

        # default binds (maps host paths to same inside sandbox)
        for p in self.allowed_binds:
            p = p if isinstance(p, Path) else Path(str(p))
            if p.exists():
                self.binds.append((p.resolve(), p.resolve(), True))

        # provide a build-friendly layout
        self._prepare_layout()

        if self.logger:
            self.logger.log_event("sandbox_create", level="INFO", message=f"Created sandbox {self.name}", metadata={"sandbox": str(self.base_dir)})

    # ----------------- helpers -----------------
    def _to_bool(self, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if v is None:
            return False
        return str(v).lower() in ("1", "true", "yes", "on")

    def _prepare_layout(self):
        # common dirs inside sandbox: sources, build, dest, tmp, home
        for d in ("sources", "build", "dest", "tmp", "home"):
            p = self.work_dir / d
            p.mkdir(parents=True, exist_ok=True)

    def sandbox_for_package(self, pkg_name: str, create_sources: bool = True) -> Path:
        """Prepare a package-structured sandbox workdir and return its path.

        Creates directories: work/sources/<pkg_name>, work/build/<pkg_name>, work/dest/<pkg_name>
        """
        src = self.work_dir / "sources" / pkg_name
        build = self.work_dir / "build" / pkg_name
        dest = self.work_dir / "dest" / pkg_name
        src.mkdir(parents=True, exist_ok=True)
        build.mkdir(parents=True, exist_ok=True)
        dest.mkdir(parents=True, exist_ok=True)
        return build

    # ----------------- bind management -----------------
    def bind(self, src: Path, dest: Optional[Path] = None, ro: bool = True) -> None:
        """Register a bind mount for the sandbox. dest is the path inside the sandbox root. If None, use same as src."""
        src = Path(src).resolve()
        if dest is None:
            dest = src
        else:
            dest = Path(dest)
        # only allow binds that are within allowed_binds or explicitly allowed by absolute path
        if not any(str(src).startswith(str(a)) for a in self.allowed_binds):
            # allow explicit bind if it is under /tmp or under base_dir
            if not (str(src).startswith('/tmp') or str(src).startswith(str(self.base_dir))):
                raise SandboxError(f"Bind source {src} is not allowed by SANDBOX_DEFAULT_BIND")
        self.binds.append((src, dest, ro))

    # ----------------- command construction -----------------
    def _bwrap_prefix(self, chdir: Optional[Path] = None) -> List[str]:
        # Basic bwrap invocation
        b = ["bwrap", "--unshare-all", "--new-session"]
        # ensure /dev and /proc are present
        for src, dest, ro in self.binds:
            flag = "--ro-bind" if ro else "--bind"
            b.extend([flag, str(src), str(dest)])
        # set working dir
        if chdir:
            b.extend(["--chdir", str(chdir)])
        # minimal environment
        b.extend(["--setenv", "HOME", str(self.work_dir / "home")])
        b.extend(["--setenv", "TMPDIR", str(self.work_dir / "tmp")])
        b.extend(["--setenv", "PATH", "/usr/bin:/bin"])
        # drop to nobody-like user if possible (rootless bwrap uses new userns)
        # note: do not set --uid/--gid to avoid requiring root
        return b

    def _ensure_bwrap_available(self) -> None:
        if shutil.which("bwrap") is None:
            raise SandboxError("bubblewrap (bwrap) is not available on PATH")

    # ----------------- run logic -----------------
    def run(self, cmd: Iterable[str], cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None, capture: bool = True) -> SandboxResult:
        """Execute a command inside the sandbox. Returns SandboxResult."""
        if self.backend != "bwrap":
            raise SandboxError("Only bwrap backend is supported currently")
        self._ensure_bwrap_available()
        chdir = cwd if cwd else (self.work_dir)
        bprefix = self._bwrap_prefix(chdir=chdir)
        full_cmd = bprefix + list(map(str, cmd))

        start = datetime.utcnow()
        started_at = start.isoformat() + "Z"
        try:
            cp = subprocess.run(full_cmd, capture_output=capture, text=True, env=env or os.environ.copy(), timeout=timeout)
            rc = cp.returncode
            stdout = cp.stdout or ""
            stderr = cp.stderr or ""
        except subprocess.TimeoutExpired as e:
            rc = -1
            stdout = e.stdout or ""
            stderr = (e.stderr or "") + f"\nTimeoutExpired after {timeout}s"
        except FileNotFoundError as e:
            raise SandboxError(f"Execution failed: {e}") from e
        end = datetime.utcnow()
        duration = (end - start).total_seconds()
        finished_at = end.isoformat() + "Z"

        # log
        if self.logger:
            self.logger.log_event("sandbox_run", level=("INFO" if rc == 0 else "ERROR"), message=f"cmd {' '.join(map(str, cmd))}", metadata={"sandbox": self.name, "cmd": list(cmd), "rc": rc, "duration": duration})

        # record in DB optionally
        if self.db:
            try:
                # store as a build_log-like record
                pkg = None
                # try to infer package from cwd path components
                try:
                    pkg = (cwd.name if cwd else None)
                except Exception:
                    pkg = None
                phase = "sandbox_run"
                status = "ok" if rc == 0 else "fail"
                self.db.add_log(pkg or self.name, phase, status, log_path=None)
            except Exception:
                pass

        return SandboxResult(returncode=rc, stdout=stdout, stderr=stderr, duration=duration, started_at=started_at, finished_at=finished_at)

    # ----------------- interactive shell -----------------
    def enter_interactive(self, shell: str = "/bin/bash") -> None:
        """Spawn an interactive shell inside the sandbox (attaches to current tty)."""
        self._ensure_bwrap_available()
        chdir = self.work_dir
        bprefix = self._bwrap_prefix(chdir=chdir)
        full_cmd = bprefix + [shell]
        if self.logger:
            self.logger.log_event("sandbox_interactive", level="INFO", message=f"Entering interactive shell: {shell}", metadata={"sandbox": self.name})
        # replace current process with bwrap shell
        os.execvp(full_cmd[0], full_cmd)

    # ----------------- cleanup -----------------
    def cleanup(self) -> None:
        if self.persistent:
            if self.logger:
                self.logger.log_event("sandbox_cleanup", level="INFO", message=f"Leaving sandbox persistent: {self.base_dir}", metadata={"sandbox": str(self.base_dir)})
            return
        try:
            shutil.rmtree(self.base_dir)
            if self.logger:
                self.logger.log_event("sandbox_cleanup", level="INFO", message=f"Removed sandbox {self.name}", metadata={"sandbox": str(self.base_dir)})
        except Exception as e:
            if self.logger:
                self.logger.log_event("sandbox_cleanup", level="ERROR", message=f"Failed to remove sandbox {self.name}: {e}", metadata={"sandbox": str(self.base_dir), "error": str(e)})

    def exists(self) -> bool:
        return self.base_dir.exists()

    # ----------------- context manager support -----------------
    def __enter__(self) -> "NewpkgSandbox":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # always cleanup unless persistent
        self.cleanup()


# ----------------- small demo if executed -----------------
if __name__ == "__main__":
    # demo: create sandbox and run echo
    s = NewpkgSandbox()
    try:
        res = s.run(["/bin/echo", "hello from sandbox"])
        print("RC:", res.returncode)
        print("OUT:", res.stdout)
    finally:
        s.cleanup()
