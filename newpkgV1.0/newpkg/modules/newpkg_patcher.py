#!/usr/bin/env python3
# newpkg_patcher.py (fixed)
"""
newpkg_patcher.py — patch application helper (fixed)

Applied improvements:
- Lazy imports of newpkg_api/newpkg_config/newpkg_logger/newpkg_db/newpkg_sandbox to avoid circular imports
- Support for .xz patches via lzma
- Fallback report/log dir to ~/.local/share/newpkg/patcher if /var/log/newpkg/patcher not writable
- Log full traceback on errors
- Add pre_patch_revert hook before rollback
- Keep API/CLI compatibility (same class/method names)
"""

from __future__ import annotations

import json
import lzma
import os
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# -------------------------
# Fallback logger
# -------------------------
import logging
_module_logger = logging.getLogger("newpkg.patcher")
if not _module_logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.patcher: %(message)s"))
    _module_logger.addHandler(_h)
_module_logger.setLevel(logging.INFO)

# -------------------------
# Data classes
# -------------------------
@dataclass
class PatchSpec:
    path: str
    cwd: Optional[str] = None
    sha256: Optional[str] = None
    strip: Optional[int] = None
    timeout: Optional[int] = 300


@dataclass
class PatchResult:
    spec: PatchSpec
    ok: bool
    applied_with: Optional[str]
    stdout: str
    stderr: str
    duration: float
    error: Optional[str] = None


# -------------------------
# Utilities
# -------------------------
def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def run_cmd(cmd: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout.decode("utf-8", errors="ignore")
        err = proc.stderr.decode("utf-8", errors="ignore")
        return proc.returncode, out, err
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout: {e}"
    except Exception as e:
        return 1, "", str(e)


def _default_report_dir() -> Path:
    """Try /var/log/newpkg/patcher, fallback to ~/.local/share/newpkg/patcher."""
    p = Path("/var/log/newpkg/patcher")
    try:
        p.mkdir(parents=True, exist_ok=True)
        test = p / ".writable_check"
        with open(test, "w") as fh:
            fh.write("ok")
        test.unlink()
        return p
    except Exception:
        fb = Path.home() / ".local/share/newpkg/patcher"
        fb.mkdir(parents=True, exist_ok=True)
        return fb


# -------------------------
# Main patcher class
# -------------------------
class NewpkgPatcher:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None):
        # Lazy imports avoid circular deps
        self._lazy_setup(cfg, logger, db, hooks, sandbox)
        self._lock = threading.RLock()
        self.checkpoints: List[str] = []
        self.report_dir = _default_report_dir()

    def _lazy_setup(self, cfg, logger, db, hooks, sandbox):
        # Logger
        self.logger = logger
        if self.logger is None:
            try:
                from newpkg_logger import get_logger  # type: ignore
                self.logger = get_logger()
            except Exception:
                self.logger = None
        # Config
        self.cfg = cfg
        try:
            from newpkg_config import get_config  # type: ignore
            if self.cfg is None:
                self.cfg = get_config()
        except Exception:
            pass
        # DB
        self.db = db
        try:
            from newpkg_db import get_db  # type: ignore
            if self.db is None:
                self.db = get_db()
        except Exception:
            pass
        # Hooks
        self.hooks = hooks
        try:
            from newpkg_hooks import get_hooks_manager  # type: ignore
            if self.hooks is None:
                self.hooks = get_hooks_manager(self.cfg)
        except Exception:
            pass
        # Sandbox
        self.sandbox = sandbox
        try:
            from newpkg_sandbox import get_sandbox  # type: ignore
            if self.sandbox is None:
                self.sandbox = get_sandbox(self.cfg)
        except Exception:
            pass

    # -------------------------------------------------
    # Core patch application
    # -------------------------------------------------
    def apply_patch(self, spec: PatchSpec, use_sandbox: bool = False) -> PatchResult:
        t0 = time.time()
        stdout, stderr = "", ""
        applied_with, error = None, None
        ok = False
        cwd = spec.cwd or os.getcwd()

        patch_path = Path(spec.path)
        tmp_written = None

        try:
            # Decompress if needed (.gz or .xz)
            if patch_path.suffix == ".gz":
                import gzip as _gzip
                tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".patch")
                with _gzip.open(str(patch_path), "rb") as fh:
                    tmpf.write(fh.read())
                tmpf.close()
                raw_patch = tmpf.name
                tmp_written = tmpf.name
            elif patch_path.suffix in (".xz", ".lzma"):
                tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".patch")
                with lzma.open(str(patch_path), "rb") as fh:
                    tmpf.write(fh.read())
                tmpf.close()
                raw_patch = tmpf.name
                tmp_written = tmpf.name
            else:
                raw_patch = str(patch_path)

            # Strip levels
            strips = [f"-p{spec.strip}"] if spec.strip is not None else ["-p1", "-p0"]

            for sflag in strips:
                cmd = ["patch", sflag, "-i", raw_patch]
                rc, out, err = run_cmd(cmd, cwd=cwd, timeout=spec.timeout)
                stdout += out
                stderr += err
                if rc == 0:
                    ok = True
                    applied_with = sflag
                    break

            if not ok:
                error = "patch failed with -p1/-p0"
        except Exception as e:
            tb = traceback.format_exc()
            error = f"{e}\n{tb}"
            if self.logger:
                self.logger.error("patch.apply.exception", error)
            else:
                _module_logger.error(error)
        finally:
            if tmp_written:
                try:
                    os.unlink(tmp_written)
                except Exception:
                    pass

        duration = time.time() - t0
        result = PatchResult(spec=spec, ok=ok, applied_with=applied_with, stdout=stdout, stderr=stderr, duration=duration, error=error)

        # Record in DB
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase("patch", "apply", "ok" if ok else "fail",
                                     meta={"path": spec.path, "cwd": cwd, "applied_with": applied_with, "error": error})
        except Exception:
            pass
        return result

    # -------------------------------------------------
    # Apply multiple patches
    # -------------------------------------------------
    def apply_patches(self, specs: List[PatchSpec], parallel: bool = False, use_sandbox: bool = False) -> List[PatchResult]:
        results: List[PatchResult] = []
        if parallel:
            cwds = [s.cwd or os.getcwd() for s in specs]
            if len(set(cwds)) != len(cwds):
                msg = "parallel=True but multiple patches target same cwd; this may conflict"
                if self.logger:
                    self.logger.warning("patch.parallel_conflict", msg)
                else:
                    _module_logger.warning(msg)

            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=min(8, max(1, len(specs)))) as ex:
                futs = {ex.submit(self.apply_patch, s, use_sandbox): s for s in specs}
                for fut in as_completed(futs):
                    try:
                        res = fut.result()
                    except Exception as e:
                        tb = traceback.format_exc()
                        res = PatchResult(spec=futs[fut], ok=False, applied_with=None, stdout="", stderr="", duration=0.0, error=f"{e}\n{tb}")
                    results.append(res)
        else:
            for s in specs:
                results.append(self.apply_patch(s, use_sandbox))

        # Write JSON report
        try:
            report = {"ts": now_iso(), "results": [asdict(r) for r in results]}
            path = Path(self.report_dir) / f"patch-report-{int(time.time())}.json"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
        except Exception as e:
            tb = traceback.format_exc()
            if self.logger:
                self.logger.warning("patch.report_fail", f"{e}\n{tb}")
            else:
                _module_logger.warning(f"{e}\n{tb}")

        return results

    # -------------------------------------------------
    # Rollback logic
    # -------------------------------------------------
    def pre_patch_revert(self, meta: Dict[str, Any]):
        """Hook before rollback."""
        try:
            if self.hooks:
                self.hooks.run("pre_patch_revert", meta)
        except Exception as e:
            msg = f"pre_patch_revert failed: {e}"
            if self.logger:
                self.logger.warning("patch.hook_pre_revert_failed", msg)
            else:
                _module_logger.warning(msg)

    def rollback(self):
        """Rollback using Git checkpoints."""
        try:
            self.pre_patch_revert({"checkpoints": list(self.checkpoints)})
            for cp in reversed(self.checkpoints):
                rc, out, err = run_cmd(["git", "reset", "--hard", cp], timeout=120)
                if rc == 0:
                    if self.logger:
                        self.logger.info("patch.rollback", f"rolled back to {cp}")
                    else:
                        _module_logger.info(f"rolled back to {cp}")
        except Exception as e:
            tb = traceback.format_exc()
            if self.logger:
                self.logger.error("patch.rollback_outer_exc", f"{e}\n{tb}")
            else:
                _module_logger.error(f"{e}\n{tb}")


# -------------------------
# Singleton accessor
# -------------------------
_default_patcher: Optional[NewpkgPatcher] = None
_patcher_lock = threading.RLock()

def get_patcher(cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None, sandbox: Any = None) -> NewpkgPatcher:
    global _default_patcher
    with _patcher_lock:
        if _default_patcher is None:
            _default_patcher = NewpkgPatcher(cfg, logger, db, hooks, sandbox)
        return _default_patcher


# -------------------------
# CLI support
# -------------------------
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-patcher")
    p.add_argument("manifest", help="patch manifest (json/patch list)")
    p.add_argument("--parallel", action="store_true")
    args = p.parse_args()

    patcher = get_patcher()
    specs: List[PatchSpec] = []

    if os.path.exists(args.manifest):
        try:
            raw = Path(args.manifest).read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, list):
                for it in data:
                    specs.append(PatchSpec(path=it.get("path"), cwd=it.get("cwd"), sha256=it.get("sha256")))
        except Exception:
            specs.append(PatchSpec(path=args.manifest))
    else:
        specs.append(PatchSpec(path=args.manifest))

    res = patcher.apply_patches(specs, parallel=args.parallel)
    pprint.pprint([asdict(r) for r in res])
