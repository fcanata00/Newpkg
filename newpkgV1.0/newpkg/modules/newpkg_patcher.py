#!/usr/bin/env python3
# newpkg_patcher.py
"""
newpkg_patcher.py — robust patch application manager for newpkg

Features:
 - Integration with newpkg_api/get_api (registers api.patcher)
 - Options: dry_run, safe_mode (sandbox), require_sha256, parallel, max_workers
 - Patch application with fallback (patch -p1 then -p0), supports .gz
 - Git checkpointing (save HEAD before applying patches) and rollback
 - Hooks: pre_patch_apply, post_patch_apply, pre_patch_revert, post_patch_revert
 - Audit & DB phase recording
 - JSON report generation in /var/log/newpkg/patcher/
 - CLI entrypoint for interactive usage
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
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

try:
    from newpkg_sandbox import get_sandbox  # type: ignore
except Exception:
    get_sandbox = None

# fallback simple logger (used if newpkg_logger not present)
import logging
_log = logging.getLogger("newpkg.patcher")
if not _log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.patcher: %(message)s"))
    _log.addHandler(h)
_log.setLevel(logging.INFO)

# defaults
REPORT_DIR = Path("/var/log/newpkg/patcher")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

@dataclass
class PatchSpec:
    path: str                  # path to patch file (can be relative to workdir)
    sha256: Optional[str] = None
    strip: Optional[int] = None   # -pN override; if None use fallback p1->p0
    description: Optional[str] = None
    cwd: Optional[str] = None     # working directory where patch should be applied

@dataclass
class PatchResult:
    spec: PatchSpec
    applied: bool
    attempt: int
    duration: float
    stdout: str
    stderr: str
    method: str
    error: Optional[str]

class Patcher:
    def __init__(self,
                 cfg: Optional[Any] = None,
                 logger: Optional[Any] = None,
                 db: Optional[Any] = None,
                 hooks: Optional[Any] = None,
                 sandbox: Optional[Any] = None,
                 report_dir: Optional[Path] = None):
        # integrate with API if present
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

        # prefer provided singletons, else get from api, else best-effort imports
        self.cfg = cfg or (self.api.cfg if self.api and getattr(self.api, "cfg", None) else (get_config() if get_config else None))
        self.logger = logger or (self.api.logger if self.api and getattr(self.api, "logger", None) else (get_logger(self.cfg) if get_logger else None))
        self.db = db or (self.api.db if self.api and getattr(self.api, "db", None) else (get_db() if get_db else None))
        self.hooks = hooks or (self.api.hooks if self.api and getattr(self.api, "hooks", None) else (get_hooks_manager(self.cfg) if get_hooks_manager else None))
        self.sandbox = sandbox or (self.api.sandbox if self.api and getattr(self.api, "sandbox", None) else (get_sandbox(self.cfg) if get_sandbox else None))

        # register with API
        try:
            if self.api:
                self.api.patcher = self
        except Exception:
            pass

        # configurable defaults (from cfg if available)
        self.require_sha256 = False
        self.safe_mode_default = False
        self.parallel_default = False
        self.max_workers = 4
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.require_sha256 = bool(self.cfg.get("patcher.require_sha256", False))
                self.safe_mode_default = bool(self.cfg.get("patcher.safe_mode", False))
                self.parallel_default = bool(self.cfg.get("patcher.parallel", False))
                self.max_workers = int(self.cfg.get("patcher.max_workers", 4) or 4)
        except Exception:
            pass

        self.report_dir = Path(report_dir or (Path(self.cfg.get("patcher.report_dir")) if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("patcher.report_dir")) else REPORT_DIR))
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # internal state for rollback: stack of checkpoints per target dir
        # { target_dir: [commit1, commit2, ...] }
        self._checkpoints: Dict[str, List[str]] = {}
        self._lock = threading.RLock()

    # ---------------- helpers ----------------
    def _log(self, level: str, key: str, msg: str, meta: Optional[Dict[str, Any]] = None):
        if self.logger:
            try:
                getattr(self.logger, level)(key, msg, meta=meta or {})
                return
            except Exception:
                pass
        # fallback
        getattr(_log, level)(f"{key}: {msg} | {meta or {}}")

    def _run_cmd(self, cmd: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None, use_sandbox: bool = False) -> Tuple[int, str, str]:
        """
        Run a command locally or in sandbox. Returns (rc, stdout, stderr).
        If sandbox is requested and available it will attempt sandbox.run_in_sandbox().
        """
        if use_sandbox and self.sandbox and hasattr(self.sandbox, "run_in_sandbox"):
            try:
                res = self.sandbox.run_in_sandbox(cmd, cwd=cwd, use_fakeroot=False)
                rc = getattr(res, "rc", None)
                out = getattr(res, "stdout", "") or ""
                err = getattr(res, "stderr", "") or ""
                return (0 if rc == 0 else (rc or 1), out, err)
            except Exception as e:
                return (1, "", f"sandbox error: {e}")
        # direct run
        try:
            proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            out = proc.stdout.decode("utf-8", errors="ignore")
            err = proc.stderr.decode("utf-8", errors="ignore")
            return proc.returncode, out, err
        except subprocess.TimeoutExpired as e:
            return (124, "", f"timeout: {e}")
        except Exception as e:
            return (1, "", str(e))

    def _sha256_of_file(self, path: str) -> Optional[str]:
        try:
            import hashlib
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _maybe_decompress(self, patch_path: str) -> Tuple[str, Optional[str]]:
        """
        If patch is compressed (.gz), decompress to temp and return path; second return is tmp file if created (to cleanup).
        """
        p = Path(patch_path)
        if p.suffix == ".gz":
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".patch")
            try:
                with gzip.open(str(p), "rb") as fi:
                    tmp.write(fi.read())
                tmp.close()
                return tmp.name, tmp.name
            except Exception:
                try:
                    tmp.close()
                except Exception:
                    pass
                return patch_path, None
        return patch_path, None

    # ---------------- git checkpoint/rollback ----------------
    def _is_git_repo(self, cwd: str) -> bool:
        return Path(cwd, ".git").exists()

    def _git_head(self, cwd: str) -> Optional[str]:
        rc, out, err = self._run_cmd(["git", "rev-parse", "HEAD"], cwd=cwd)
        if rc == 0:
            return out.strip()
        return None

    def _checkpoint_git(self, cwd: str) -> Optional[str]:
        """
        Save current HEAD in our internal checkpoint stack and return the saved commit.
        """
        try:
            head = self._git_head(cwd)
            if not head:
                return None
            with self._lock:
                arr = self._checkpoints.setdefault(os.path.abspath(cwd), [])
                arr.append(head)
            return head
        except Exception:
            return None

    def _rollback_git_to_last(self, cwd: str) -> Tuple[bool, Optional[str]]:
        """
        Rollback the repo at cwd to last checkpoint (pop). Returns (ok, message).
        """
        with self._lock:
            arr = self._checkpoints.get(os.path.abspath(cwd), [])
            if not arr:
                return False, "no checkpoint"
            last = arr.pop()
        # perform reset --hard last
        rc, out, err = self._run_cmd(["git", "reset", "--hard", last], cwd=cwd)
        if rc == 0:
            return True, f"reset to {last}"
        # if reset fails, try checkout
        rc2, out2, err2 = self._run_cmd(["git", "checkout", last], cwd=cwd)
        if rc2 == 0:
            return True, f"checkout {last}"
        return False, f"rollback failed: {err or err2}"

    # ---------------- patch application logic ----------------
    def _apply_single_patch(self,
                            spec: PatchSpec,
                            dry_run: bool = False,
                            safe_mode: bool = False,
                            require_sha: Optional[bool] = None,
                            timeout: Optional[int] = None) -> PatchResult:
        """
        Apply a single patch spec. Returns PatchResult.
        - tries strip level: spec.strip if provided, else -p1 then -p0
        - supports compressed patches
        - uses sandbox if safe_mode True
        """
        t0 = time.time()
        attempt = 0
        stdout_acc = ""
        stderr_acc = ""
        applied = False
        meth = "patch"

        cwd = spec.cwd or os.getcwd()
        patch_path = spec.path

        # verify sha if required
        require_sha = bool(self.require_sha256 if require_sha is None else require_sha)
        if require_sha and spec.sha256:
            got = self._sha256_of_file(patch_path)
            if not got or got != spec.sha256:
                err = f"sha256 mismatch or unable to compute ({got} != {spec.sha256})"
                self._log("warning", "patch.verify.fail", f"sha256 failed for {patch_path}", {"error": err, "spec": spec})
                return PatchResult(spec=spec, applied=False, attempt=0, duration=time.time() - t0, stdout="", stderr=err, method=meth, error=err)
        if require_sha and not spec.sha256:
            err = "sha256 required but not provided"
            return PatchResult(spec=spec, applied=False, attempt=0, duration=time.time() - t0, stdout="", stderr=err, method=meth, error=err)

        # decompress if needed
        real_patch, tmp_created = self._maybe_decompress(patch_path)
        try:
            strip_levels = []
            if spec.strip is not None:
                strip_levels = [f"-p{int(spec.strip)}"]
            else:
                strip_levels = ["-p1", "-p0"]

            # If cwd is a git repo, checkpoint
            checkpoint = None
            if self._is_git_repo(cwd):
                checkpoint = self._checkpoint_git(cwd)
                self._log("info", "patch.checkpoint", f"git checkpoint created for {cwd}", {"commit": checkpoint, "cwd": cwd})

            # pre-hook
            try:
                if self.hooks:
                    self.hooks.run("pre_patch_apply", {"patch": patch_path, "cwd": cwd, "dry_run": dry_run, "safe_mode": safe_mode})
            except Exception:
                pass

            for sl in strip_levels:
                attempt += 1
                if dry_run:
                    # test apply
                    cmd = ["patch", sl, "--dry-run", "-i", real_patch]
                else:
                    cmd = ["patch", sl, "-i", real_patch]

                rc, out, err = self._run_cmd(cmd, cwd=cwd, use_sandbox=safe_mode)
                stdout_acc += out or ""
                stderr_acc += err or ""
                if rc == 0:
                    applied = not dry_run
                    meth = f"patch {sl}"
                    # record DB phase
                    try:
                        if self.db:
                            self.db.record_phase(spec.cwd or None, "patch.apply", "ok", meta={"patch": patch_path, "strip": sl, "dry_run": dry_run})
                    except Exception:
                        pass
                    # post-hook
                    try:
                        if self.hooks:
                            self.hooks.run("post_patch_apply", {"patch": patch_path, "cwd": cwd, "strip": sl, "dry_run": dry_run})
                    except Exception:
                        pass
                    break
                else:
                    # continue trying next strip level
                    continue

            # if not applied and not dry_run, register failure
            if not applied and not dry_run:
                err_msg = stderr_acc or "patch failed"
                try:
                    if self.db:
                        self.db.record_phase(spec.cwd or None, "patch.apply.fail", "fail", meta={"patch": patch_path, "error": err_msg})
                except Exception:
                    pass
                # if git checkpoint exists, record for potential rollback
                if checkpoint:
                    # keep checkpoint for later rollback; caller may call revert_last_failed
                    self._log("warning", "patch.apply.failed", f"patch {patch_path} failed in {cwd}", {"error": err_msg})
                return PatchResult(spec=spec, applied=False, attempt=attempt, duration=time.time() - t0, stdout=stdout_acc, stderr=stderr_acc, method=meth, error=err_msg)
            # success or dry-run success
            return PatchResult(spec=spec, applied=applied, attempt=attempt, duration=time.time() - t0, stdout=stdout_acc, stderr=stderr_acc, method=meth, error=None)
        finally:
            # cleanup tmp if was created
            if tmp_created:
                try:
                    os.unlink(tmp_created)
                except Exception:
                    pass

    # ---------------- public batch apply ----------------
    def apply_patches(self,
                      specs: List[PatchSpec],
                      dry_run: bool = False,
                      safe_mode: Optional[bool] = None,
                      parallel: Optional[bool] = None,
                      max_workers: Optional[int] = None,
                      report_name: Optional[str] = None,
                      timeout_per_patch: Optional[int] = None) -> Dict[str, Any]:
        """
        Apply multiple patches in order. Returns dict with results and report path.
        - parallel: if True attempt to apply patches concurrently (only for independent patches)
        - safe_mode: if True run inside sandbox (overrides config)
        """
        t0 = time.time()
        safe_mode = bool(self.safe_mode_default if safe_mode is None else safe_mode)
        parallel = bool(self.parallel_default if parallel is None else parallel)
        max_workers = int(self.max_workers if max_workers is None else max_workers)

        # pre-run hook
        try:
            if self.hooks:
                self.hooks.run("pre_patch_run", {"count": len(specs), "dry_run": dry_run, "safe_mode": safe_mode})
        except Exception:
            pass

        results: List[PatchResult] = []
        errors: List[str] = []

        # choose execution strategy
        if parallel:
            # run concurrently with ThreadPoolExecutor — caller must ensure patches independent
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futs = {ex.submit(self._apply_single_patch, s, dry_run, safe_mode, None, timeout_per_patch): s for s in specs}
                for fut in as_completed(futs):
                    s = futs[fut]
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = PatchResult(spec=s, applied=False, attempt=0, duration=0.0, stdout="", stderr=str(e), method="exception", error=str(e))
                    results.append(res)
                    if not res.applied and not dry_run:
                        errors.append(f"{s.path}: {res.error}")
        else:
            # sequential
            for s in specs:
                try:
                    res = self._apply_single_patch(s, dry_run=dry_run, safe_mode=safe_mode, require_sha=None, timeout=timeout_per_patch)
                except Exception as e:
                    res = PatchResult(spec=s, applied=False, attempt=0, duration=0.0, stdout="", stderr=traceback.format_exc(), method="exception", error=str(e))
                results.append(res)
                if not res.applied and not dry_run:
                    errors.append(f"{s.path}: {res.error}")
                    # stop on first failure (conservative) — keep checkpoints for rollback
                    break

        # post-run hook
        try:
            if self.hooks:
                self.hooks.run("post_patch_run", {"results": [asdict(r) for r in results], "dry_run": dry_run})
        except Exception:
            pass

        # build report
        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_s": round(time.time() - t0, 3),
            "dry_run": bool(dry_run),
            "safe_mode": bool(safe_mode),
            "results": [asdict(r) for r in results],
        }
        # write report
        try:
            name = report_name or f"patch-report-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
            out = self.report_dir / name
            out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            report_path = str(out)
        except Exception:
            report_path = None

        # record top-level DB phase
        try:
            if self.db:
                status = "ok" if not errors else "partial" if dry_run else "fail"
                self.db.record_phase(None, "patch.run", status, meta={"count": len(results), "errors": len(errors), "report": report_path})
        except Exception:
            pass

        return {"ok": (len(errors) == 0 or dry_run), "errors": errors, "results": results, "report": report_path}

    # ---------------- rollback helpers ----------------
    def revert_last_failed(self, target_cwd: Optional[str] = None) -> Dict[str, Any]:
        """
        Revert last checkpoint for target_cwd (if git). If target_cwd is None revert all tracked checkpoints.
        Returns dict with per-target results.
        """
        outcomes = {}
        if target_cwd:
            targets = [os.path.abspath(target_cwd)]
        else:
            with self._lock:
                targets = list(self._checkpoints.keys())
        for t in targets:
            try:
                ok, msg = self._rollback_git_to_last(t)
                outcomes[t] = {"ok": ok, "message": msg}
                # db record
                if self.db:
                    self.db.record_phase(t, "patch.rollback", "ok" if ok else "fail", meta={"message": msg})
                # hooks
                if self.hooks:
                    try:
                        self.hooks.run("post_patch_revert", {"cwd": t, "ok": ok, "message": msg})
                    except Exception:
                        pass
            except Exception as e:
                outcomes[t] = {"ok": False, "message": str(e)}
        return outcomes

# ---------------- CLI ----------------
def _parse_patch_spec(dot: Dict[str, Any]) -> PatchSpec:
    return PatchSpec(
        path=dot.get("path") or dot.get("file"),
        sha256=dot.get("sha256"),
        strip=dot.get("strip"),
        description=dot.get("description"),
        cwd=dot.get("cwd")
    )

def _main():
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-patcher", description="apply patches safely with sandbox/checkpoints")
    p.add_argument("manifest", nargs="?", help="JSON manifest with array of patch objects or single patch path")
    p.add_argument("--cwd", help="working directory where patch(s) will be applied (overrides manifest cwd)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--safe", action="store_true", help="force sandbox/safe mode")
    p.add_argument("--no-checksum", action="store_true", help="do not require checksum even if config requests it")
    p.add_argument("--parallel", action="store_true")
    p.add_argument("--max-workers", type=int, default=None)
    p.add_argument("--report", help="report filename")
    p.add_argument("--revert", action="store_true", help="revert last failed checkpoint(s)")
    args = p.parse_args()

    patcher = Patcher()

    if args.revert:
        res = patcher.revert_last_failed(args.cwd)
        pprint.pprint(res)
        return

    specs: List[PatchSpec] = []
    if args.manifest:
        # if manifest is a file path to JSON array
        if os.path.exists(args.manifest):
            txt = Path(args.manifest).read_text(encoding="utf-8")
            try:
                data = json.loads(txt)
                if isinstance(data, list):
                    specs = [_parse_patch_spec(x) for x in data]
                elif isinstance(data, dict):
                    specs = [_parse_patch_spec(data)]
            except Exception:
                # treat manifest as single patch file path
                specs = [PatchSpec(path=args.manifest, cwd=args.cwd)]
        else:
            # manifest might be dash or invalid — treat as path
            specs = [PatchSpec(path=args.manifest, cwd=args.cwd)]
    else:
        # read from stdin?
        p0 = os.readlink("/proc/self/fd/0") if os.path.exists("/proc/self/fd/0") else None
        # if nothing, exit
        print("No manifest provided. Provide JSON manifest or patch path.")
        return

    # override cwd
    if args.cwd:
        for s in specs:
            s.cwd = args.cwd

    safe_mode = args.safe
    dry_run = args.dry_run
    parallel = args.parallel
    if args.no_checksum:
        patcher.require_sha256 = False

    res = patcher.apply_patches(specs, dry_run=dry_run, safe_mode=safe_mode, parallel=parallel, max_workers=args.max_workers, report_name=args.report)
    # pretty print summary
    ok = res.get("ok")
    report = res.get("report")
    print("OK" if ok else "FAILED")
    if report:
        print("report:", report)
    for r in res.get("results", []):
        pr: PatchResult = r
        print(f"{Path(pr.spec.path).name}: applied={pr.applied} attempt={pr.attempt} dur={pr.duration:.2f}s err={pr.error}")

if __name__ == "__main__":
    _main()
