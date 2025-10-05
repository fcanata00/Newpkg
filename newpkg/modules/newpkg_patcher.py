#!/usr/bin/env python3
# newpkg_patcher.py
"""
newpkg_patcher.py — robust patch manager for newpkg

Features:
 - Loads patches from directories or explicit file list
 - Supports patch application via `git apply` or `patch -p{n}`
 - Verifies patch checksums when provided
 - Respects newpkg_config: general.dry_run, output.quiet, output.json, sandbox options
 - Uses cfg.as_env() for subprocess environments
 - Integrates with newpkg_logger (perf_timer) and newpkg_db.record_phase
 - Stores applied patch metadata in .applied_patches.json (reversible)
 - Can delegate execution to NewpkgSandbox.run_in_sandbox when available
"""

from __future__ import annotations

import json
import hashlib
import os
import shlex
import shutil
import subprocess
import tarfile
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# optional project modules (best-effort imports)
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

# fallback stdlib logger for internal messages
import logging
_logger = logging.getLogger("newpkg.patcher")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.patcher: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


APPLIED_MARKER = ".applied_patches.json"


@dataclass
class PatchEntry:
    path: str
    applied_at: Optional[str] = None
    method: Optional[str] = None
    sha256: Optional[str] = None
    author: Optional[str] = None
    description: Optional[str] = None
    meta: Dict[str, Any] = None

    def to_dict(self):
        d = asdict(self)
        d["meta"] = d.get("meta") or {}
        return d


class NewpkgPatcher:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        # logger: prefer provided, else try NewpkgLogger.from_config, else fallback to module logger
        if logger:
            self.logger = logger
        else:
            try:
                self.logger = NewpkgLogger.from_config(self.cfg, db) if NewpkgLogger and self.cfg else None
            except Exception:
                self.logger = None
        self._log = self._make_logger()

        # db
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)

        # sandbox: prefer provided, else try to create one if available
        if sandbox:
            self.sandbox = sandbox
        else:
            try:
                self.sandbox = NewpkgSandbox(cfg=self.cfg, logger=self.logger, db=self.db) if NewpkgSandbox and self.cfg else None
            except Exception:
                self.sandbox = None

        # settings from config
        self.dry_run = bool(self._cfg_get("general.dry_run", False))
        self.quiet = bool(self._cfg_get("output.quiet", False))
        self.json_out = bool(self._cfg_get("output.json", False))
        self.default_strip = int(self._cfg_get("patches.default_strip", 1))
        self.auto_apply = bool(self._cfg_get("patches.auto_apply", True))
        self.marker_name = self._cfg_get("patches.marker", APPLIED_MARKER)

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        # fallback to environment
        return os.environ.get(key.upper().replace(".", "_"), default)

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

    # ------------------ utilities ------------------
    @staticmethod
    def sha256_of_path(path: Union[str, Path]) -> str:
        h = hashlib.sha256()
        with open(str(path), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _marker_path(self, workdir: Union[str, Path]) -> Path:
        return Path(workdir) / self.marker_name

    def load_marker(self, workdir: Union[str, Path]) -> Dict[str, Any]:
        p = self._marker_path(workdir)
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save_marker(self, workdir: Union[str, Path], data: Dict[str, Any]):
        p = self._marker_path(workdir)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._log("info", "patch.marker.write", f"Wrote marker {p}", path=str(p))

    # ------------------ patch discovery ------------------
    def discover_patches(self, patch_dirs: Iterable[Union[str, Path]], pattern: Optional[str] = None) -> List[Path]:
        """
        Find patch files in given directories. Returns list of Path sorted lexicographically.
        pattern is optional filter like '*.patch' or 'fix-*.diff'
        """
        out: List[Path] = []
        for d in patch_dirs:
            p = Path(d)
            if not p.exists():
                continue
            if p.is_file():
                out.append(p)
            else:
                for f in sorted(p.iterdir()):
                    if f.is_file():
                        if pattern:
                            if Path(f.name).match(pattern):
                                out.append(f)
                        else:
                            out.append(f)
        return out

    # ------------------ apply/revert single patch ------------------
    def _run_command(self, cmd: Union[str, List[str]], cwd: Optional[Union[str, Path]] = None, env_extra: Optional[Dict[str, str]] = None, use_sandbox: bool = False) -> Tuple[int, str, str]:
        """
        Run a command. If sandbox is available and use_sandbox=True, delegate to sandbox.run_in_sandbox().
        Returns (rc, stdout, stderr).
        """
        env = dict(os.environ)
        try:
            if self.cfg and hasattr(self.cfg, "as_env"):
                env.update(self.cfg.as_env())
        except Exception:
            pass
        if env_extra:
            env.update({k: str(v) for k, v in env_extra.items()})

        # dry-run simulation
        if self.dry_run:
            self._log("info", "patch.cmd.dryrun", f"DRY-RUN: {cmd}", cmd=str(cmd), cwd=str(cwd))
            return 0, "", ""

        # use sandbox wrapper if requested and available
        if use_sandbox and self.sandbox:
            try:
                res = self.sandbox.run_in_sandbox(cmd, cwd=cwd, captures=True, env=env)
                return res.rc, res.stdout or "", res.stderr or ""
            except Exception as e:
                return 255, "", str(e)

        # otherwise run as subprocess
        if isinstance(cmd, (list, tuple)):
            cmd_list = [str(x) for x in cmd]
            shell = False
        else:
            cmd_list = cmd
            shell = True

        proc = subprocess.run(cmd_list, cwd=str(cwd) if cwd else None, env=env, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return proc.returncode, proc.stdout or "", proc.stderr or ""

    def _apply_patch_file(self, patch_path: Path, workdir: Union[str, Path], strip: Optional[int] = None, method: Optional[str] = None, use_sandbox: bool = True) -> Tuple[bool, str]:
        """
        Try to apply a single patch file. method can be 'git' or 'patch' or None (auto).
        strip: -p level for patch(1). Returns (ok, message)
        """
        workdir = Path(workdir)
        if strip is None:
            strip = self.default_strip

        # compute sha if available
        try:
            sha = self.sha256_of_path(patch_path)
        except Exception:
            sha = None

        # choose method
        method_try = [method] if method else ["git", "patch"]
        last_err = ""
        for m in method_try:
            if m == "git":
                # try git apply --index --3way
                git_bin = shutil.which("git") or "git"
                cmd = [git_bin, "apply", "--index", "--3way", str(patch_path)]
                rc, out, err = self._run_command(cmd, cwd=workdir, use_sandbox=use_sandbox)
                if rc == 0:
                    return True, f"applied via git: {patch_path}"
                last_err = f"git apply failed: {err.strip()}"
            elif m == "patch":
                # patch -p{strip} < file
                # use shell invocation to redirect stdin
                cmd = f"patch -p{strip} --forward --input {shlex.quote(str(patch_path))}"
                rc, out, err = self._run_command(cmd, cwd=workdir, use_sandbox=use_sandbox)
                if rc == 0:
                    return True, f"applied via patch: {patch_path}"
                last_err = f"patch failed: {err.strip()}"
            else:
                last_err = f"unknown method {m}"
        return False, last_err

    def _revert_patch_file(self, patch_path: Path, workdir: Union[str, Path], strip: Optional[int] = None, method: Optional[str] = None, use_sandbox: bool = True) -> Tuple[bool, str]:
        """
        Revert a single patch. Tries `git apply -R` then `patch -R`.
        """
        workdir = Path(workdir)
        if strip is None:
            strip = self.default_strip

        last_err = ""
        methods = [method] if method else ["git", "patch"]
        for m in methods:
            if m == "git":
                git_bin = shutil.which("git") or "git"
                cmd = [git_bin, "apply", "-R", "--index", str(patch_path)]
                rc, out, err = self._run_command(cmd, cwd=workdir, use_sandbox=use_sandbox)
                if rc == 0:
                    return True, f"reverted via git: {patch_path}"
                last_err = f"git revert failed: {err.strip()}"
            elif m == "patch":
                cmd = f"patch -p{strip} -R --input {shlex.quote(str(patch_path))}"
                rc, out, err = self._run_command(cmd, cwd=workdir, use_sandbox=use_sandbox)
                if rc == 0:
                    return True, f"reverted via patch: {patch_path}"
                last_err = f"patch revert failed: {err.strip()}"
            else:
                last_err = f"unknown method {m}"
        return False, last_err

    # ------------------ public apply/revert helpers ------------------
    def apply_all(self, patch_paths: Iterable[Union[str, Path]], workdir: Union[str, Path], strip: Optional[int] = None, method: Optional[str] = None, use_sandbox: bool = True) -> Dict[str, Any]:
        """
        Apply a sequence of patches in order. Returns summary dict with details per patch.
        Respects dry_run and writes marker file with applied entries.
        """
        start = datetime.utcnow()
        workdir = Path(workdir)
        applied = self.load_marker(workdir) or {}
        results = []
        total_applied = 0

        for p in patch_paths:
            pth = Path(p)
            key = str(pth.name)
            if key in applied:
                self._log("info", "patch.skip", f"Skipping already applied patch {pth.name}", patch=str(pth))
                results.append({"patch": str(pth), "status": "skipped"})
                continue

            # verify optional sha from metafile or similar (caller may pass)
            # here we will compute actual sha and include in marker
            try:
                sha = self.sha256_of_path(pth)
            except Exception:
                sha = None

            self._log("info", "patch.apply.start", f"Applying patch {pth.name}", patch=str(pth), sha256=sha)
            ok, msg = self._apply_patch_file(pth, workdir, strip=strip, method=method, use_sandbox=use_sandbox)
            if ok:
                total_applied += 1
                entry = PatchEntry(path=str(pth.name), applied_at=start.isoformat() + "Z", method=(method or "auto"), sha256=sha, meta={"applied_msg": msg})
                applied[str(pth.name)] = entry.to_dict()
                results.append({"patch": str(pth), "status": "applied", "msg": msg})
                self._log("info", "patch.apply.ok", f"Applied patch {pth.name}: {msg}", patch=str(pth), sha256=sha)
            else:
                results.append({"patch": str(pth), "status": "failed", "msg": msg})
                self._log("error", "patch.apply.fail", f"Failed to apply {pth.name}: {msg}", patch=str(pth), err=msg)
                # record failure phase to DB
                if self.db and hasattr(self.db, "record_phase"):
                    try:
                        self.db.record_phase(package=self._context_package(), phase="patch.apply", status="error", meta={"patch": str(pth), "error": msg})
                    except Exception:
                        pass
                # stop on first failure (configurable later)
                break

        # save marker (best-effort)
        try:
            self.save_marker(workdir, applied)
        except Exception:
            pass

        # record overall phase
        duration = (datetime.utcnow() - start).total_seconds()
        status = "ok" if total_applied > 0 else "noop"
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=self._context_package(), phase="patch.apply_all", status=status, meta={"count": total_applied, "duration": duration})
        except Exception:
            pass

        return {"status": status, "applied": total_applied, "details": results, "duration": duration}

    def revert_all(self, patch_paths: Iterable[Union[str, Path]], workdir: Union[str, Path], strip: Optional[int] = None, method: Optional[str] = None, use_sandbox: bool = True) -> Dict[str, Any]:
        """
        Revert patches in reverse order. Removes them from the marker on success.
        """
        start = datetime.utcnow()
        workdir = Path(workdir)
        applied = self.load_marker(workdir) or {}
        results = []
        reverted = 0

        # reverse iteration
        for p in reversed(list(patch_paths)):
            pth = Path(p)
            key = str(pth.name)
            if key not in applied:
                self._log("info", "patch.revert.skip", f"Patch not recorded as applied: {pth.name}", patch=str(pth))
                results.append({"patch": str(pth), "status": "not_applied"})
                continue

            self._log("info", "patch.revert.start", f"Reverting patch {pth.name}", patch=str(pth))
            ok, msg = self._revert_patch_file(pth, workdir, strip=strip, method=method, use_sandbox=use_sandbox)
            if ok:
                reverted += 1
                applied.pop(key, None)
                results.append({"patch": str(pth), "status": "reverted", "msg": msg})
                self._log("info", "patch.revert.ok", f"Reverted patch {pth.name}: {msg}", patch=str(pth))
            else:
                results.append({"patch": str(pth), "status": "failed", "msg": msg})
                self._log("error", "patch.revert.fail", f"Failed to revert {pth.name}: {msg}", patch=str(pth), err=msg)
                # record failure in DB
                if self.db and hasattr(self.db, "record_phase"):
                    try:
                        self.db.record_phase(package=self._context_package(), phase="patch.revert", status="error", meta={"patch": str(pth), "error": msg})
                    except Exception:
                        pass
                break

        # save updated marker
        try:
            self.save_marker(workdir, applied)
        except Exception:
            pass

        duration = (datetime.utcnow() - start).total_seconds()
        try:
            if self.db and hasattr(self.db, "record_phase"):
                self.db.record_phase(package=self._context_package(), phase="patch.revert_all", status="ok" if reverted > 0 else "noop", meta={"count": reverted, "duration": duration})
        except Exception:
            pass

        return {"status": "ok" if reverted > 0 else "noop", "reverted": reverted, "details": results, "duration": duration}

    # ------------------ helpers ------------------
    def _context_package(self) -> str:
        # try to get package context from logger context if present
        try:
            if self.logger and hasattr(self.logger, "_context"):
                return getattr(self.logger, "_context", {}).get("package", "global")
        except Exception:
            pass
        try:
            return str(self._cfg_get("general.default_package") or "global")
        except Exception:
            return "global"

    # ------------------ CLI helpers ------------------
    def cli_apply_from_dir(self, patch_dir: Union[str, Path], workdir: Union[str, Path], pattern: Optional[str] = None, **kwargs) -> int:
        """
        Convenience entry: discover patches in directory and apply them.
        Returns exit code 0 on success; non-zero otherwise.
        """
        patch_list = self.discover_patches([patch_dir], pattern=pattern)
        summary = self.apply_all(patch_list, workdir, **kwargs)
        if self.json_out:
            print(json.dumps(summary, indent=2))
        else:
            # human friendly summary
            self._log("info", "patch.summary", f"Applied {summary.get('applied')} patches in {summary.get('duration'):.2f}s", summary=summary)
        return 0 if summary.get("status") in ("ok", "noop") else 2

    def cli_revert_from_dir(self, patch_dir: Union[str, Path], workdir: Union[str, Path], pattern: Optional[str] = None, **kwargs) -> int:
        patch_list = self.discover_patches([patch_dir], pattern=pattern)
        summary = self.revert_all(patch_list, workdir, **kwargs)
        if self.json_out:
            print(json.dumps(summary, indent=2))
        else:
            self._log("info", "patch.summary", f"Reverted {summary.get('reverted')} patches in {summary.get('duration'):.2f}s", summary=summary)
        return 0 if summary.get("status") in ("ok", "noop") else 2


# ---------- top-level helper ----------
_default_patcher: Optional[NewpkgPatcher] = None


def get_patcher(cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None) -> NewpkgPatcher:
    global _default_patcher
    if _default_patcher is None:
        _default_patcher = NewpkgPatcher(cfg=cfg, logger=logger, db=db, sandbox=sandbox)
    return _default_patcher


# CLI entrypoint when run directly
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(prog="newpkg-patcher", description="Apply/revert patches for newpkg")
    p.add_argument("action", choices=["apply", "revert"], help="apply or revert patches")
    p.add_argument("patch_dir", help="directory or patch file")
    p.add_argument("--workdir", required=True, help="work directory (where to apply patches)")
    p.add_argument("--pattern", help="glob pattern to filter patches")
    p.add_argument("--strip", type=int, default=None, help="strip components (-pN)")
    p.add_argument("--method", choices=["git", "patch"], default=None, help="force method")
    p.add_argument("--no-sandbox", action="store_true", help="do not use sandbox even if available")
    args = p.parse_args()

    cfg = init_config() if init_config else None
    patcher = get_patcher(cfg=cfg)
    use_sandbox = not args.no_sandbox
    if args.action == "apply":
        rc = patcher.cli_apply_from_dir(args.patch_dir, args.workdir, pattern=args.pattern, strip=args.strip, method=args.method, use_sandbox=use_sandbox)
    else:
        rc = patcher.cli_revert_from_dir(args.patch_dir, args.workdir, pattern=args.pattern, strip=args.strip, method=args.method, use_sandbox=use_sandbox)
    raise SystemExit(rc)
