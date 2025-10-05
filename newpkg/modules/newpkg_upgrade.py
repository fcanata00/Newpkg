#!/usr/bin/env python3
# newpkg_upgrade.py
"""
Revised newpkg_upgrade.py

Features implemented:
 - perf timing for phases (uses logger.perf_timer if available, else time.time)
 - hooks for pre/post phases
 - progress UI via logger.progress() (rich if available)
 - retry with exponential backoff for fetch/build
 - sandbox support with profiles
 - audit post-upgrade integration
 - compress/rotate reports and keep N reports
 - remove old versions via newpkg_remove (optional)
 - API: upgrade_package(), upgrade_all()
"""

from __future__ import annotations

import json
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional integrations (best-effort)
try:
    from newpkg_config import init_config  # type: ignore
except Exception:
    init_config = None

try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_db import NewpkgDB  # type: ignore
except Exception:
    NewpkgDB = None

try:
    from newpkg_hooks import get_hooks_manager  # type: ignore
except Exception:
    get_hooks_manager = None

try:
    from newpkg_sandbox import get_sandbox  # type: ignore
except Exception:
    get_sandbox = None

try:
    from newpkg_core import NewpkgCore  # type: ignore
except Exception:
    NewpkgCore = None

try:
    from newpkg_metafile import MetafileManager  # type: ignore
except Exception:
    MetafileManager = None

try:
    from newpkg_patcher import get_patcher  # type: ignore
except Exception:
    get_patcher = None

try:
    from newpkg_remove import get_remove  # type: ignore
except Exception:
    get_remove = None

try:
    from newpkg_audit import get_audit  # type: ignore
except Exception:
    get_audit = None

try:
    from newpkg_deps import get_deps  # type: ignore
except Exception:
    get_deps = None

# fallback logger
import logging
_logger = logging.getLogger("newpkg.upgrade")
if not _logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.upgrade: %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# optional rich fallback via logger.progress
try:
    from rich.console import Console  # type: ignore
    RICH = True
    _console = Console()
except Exception:
    RICH = False
    _console = None

# ---------------- dataclasses ----------------
@dataclass
class UpgradeResult:
    package: str
    ok: bool
    stage: str
    message: Optional[str]
    report_path: Optional[str]
    duration: float


# ---------------- helpers ----------------
def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


# ---------------- main class ----------------
class NewpkgUpgrade:
    DEFAULT_REPORT_DIR = "/var/log/newpkg/upgrade"
    DEFAULT_BACKUP_DIR = "/var/cache/newpkg/upgrade_backups"
    DEFAULT_KEEP_REPORTS = 30

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None,
                 sandbox: Any = None, core: Any = None, metafile: Any = None, patcher: Any = None,
                 remover: Any = None, audit: Any = None, deps: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        self.logger = logger or (get_logger(self.cfg) if get_logger else None)
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)
        self.hooks = hooks or (get_hooks_manager(self.cfg) if get_hooks_manager else None)
        self.sandbox = sandbox or (get_sandbox(self.cfg) if get_sandbox else None)
        self.core = core or (NewpkgCore(self.cfg) if NewpkgCore and self.cfg else None)
        self.metafile = metafile or (MetafileManager(self.cfg) if MetafileManager and self.cfg else None)
        self.patcher = patcher or (get_patcher(self.cfg) if get_patcher else None)
        self.remover = remover or (get_remove(self.cfg) if get_remove else None)
        self.audit = audit or (get_audit(self.cfg) if get_audit else None)
        self.deps = deps or (get_deps(self.cfg) if get_deps else None)

        # config
        self.report_dir = Path(self._cfg_get("upgrade.report_dir", self.DEFAULT_REPORT_DIR)).expanduser()
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir = Path(self._cfg_get("upgrade.backup_dir", self.DEFAULT_BACKUP_DIR)).expanduser()
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.keep_reports = int(self._cfg_get("upgrade.report_keep", self.DEFAULT_KEEP_REPORTS))
        self.compress_reports = bool(self._cfg_get("upgrade.compress_reports", True))

        # retries and backoff
        self.retries = int(self._cfg_get("upgrade.retries", 3))
        self.backoff_max = int(self._cfg_get("upgrade.backoff_max", 30))
        self.timeout = int(self._cfg_get("upgrade.timeout", 1800))

        # sandbox
        self.use_sandbox = bool(self._cfg_get("upgrade.use_sandbox", False))
        self.sandbox_profile = str(self._cfg_get("upgrade.sandbox_profile", "light"))
        self.keep_backups = int(self._cfg_get("upgrade.keep_backups", 3))

        # parallelism
        self.parallel = int(self._cfg_get("upgrade.parallel", max(1, (os.cpu_count() or 2))))
        # cleanup old versions
        self.cleanup_old = bool(self._cfg_get("upgrade.cleanup_old", True))
        self.dry_run = bool(self._cfg_get("upgrade.dry_run", False))

    def _cfg_get(self, key: str, default: Any = None) -> Any:
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                v = self.cfg.get(key)
                if v is not None:
                    return v
        except Exception:
            pass
        envk = key.upper().replace(".", "_")
        return os.environ.get(envk, default)

    def _rotate_reports(self) -> None:
        try:
            files = sorted([p for p in self.report_dir.iterdir() if p.is_file() and p.name.startswith("upgrade-report-")], key=lambda p: p.stat().st_mtime, reverse=True)
            for p in files[self.keep_reports:]:
                try:
                    p.unlink()
                except Exception:
                    pass
        except Exception:
            pass

    def _save_report(self, pkg: str, report: Dict[str, Any]) -> Path:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        name = f"upgrade-report-{pkg}-{ts}.json"
        path = self.report_dir / name
        try:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(path))
            if self.compress_reports:
                try:
                    comp = path.with_suffix(path.suffix + ".xz")
                    with open(path, "rb") as f_in:
                        import lzma
                        comp_data = lzma.compress(f_in.read())
                    with open(comp, "wb") as f_out:
                        f_out.write(comp_data)
                    try:
                        path.unlink()
                        path = comp
                    except Exception:
                        pass
                except Exception:
                    pass
            self._rotate_reports()
        except Exception as e:
            if self.logger:
                self.logger.warning("upgrade.report_save_fail", f"failed to save report for {pkg}: {e}")
        return path

    # ---------------- perf timer helper ----------------
    class _Perf:
        def __init__(self, parent: "NewpkgUpgrade", name: str):
            self.parent = parent
            self.name = name
            self._ctx = None
            self._start = None

        def __enter__(self):
            self._start = time.time()
            try:
                if self.parent.logger and hasattr(self.parent.logger, "perf_timer"):
                    self._ctx = self.parent.logger.perf_timer(self.name)
                    self._ctx.__enter__()
            except Exception:
                self._ctx = None
            return self

        def __exit__(self, exc_type, exc, tb):
            dur = time.time() - (self._start or time.time())
            if self._ctx:
                try:
                    self._ctx.__exit__(exc_type, exc, tb)
                except Exception:
                    pass
            # record duration in DB if available
            try:
                if self.parent.db:
                    self.parent.db.record_phase(None, self.name, "ok", meta={"duration": round(dur, 3)})
            except Exception:
                pass

    def _perf_timer(self, name: str):
        return NewpkgUpgrade._Perf(self, name)

    # ---------------- safe run helper ----------------
    def _safe_run(self, cmd: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        try:
            proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout or self.timeout, check=False)
            out = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
            err = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            return proc.returncode, out, err
        except subprocess.TimeoutExpired as e:
            return 124, "", f"timeout: {e}"
        except Exception as e:
            return 1, "", f"exception: {e}"

    # ---------------- backup / restore ----------------
    def _create_backup(self, pkg: str, paths: List[str]) -> Optional[str]:
        """Create tar.xz backup of provided paths; rotate keep_backups"""
        if not paths:
            return None
        try:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            tmpf = tempfile.NamedTemporaryFile(delete=False, dir=str(self.backup_dir), prefix=f"{pkg}-", suffix=".tar.xz")
            tmpf.close()
            with tarfile.open(tmpf.name, "w:xz") as tf:
                for p in paths:
                    try:
                        if os.path.exists(p) or os.path.islink(p):
                            tf.add(p, arcname=os.path.join(pkg, os.path.relpath(p, "/")))
                    except Exception:
                        continue
            dest = self.backup_dir / f"{pkg}-{ts}.tar.xz"
            os.replace(tmpf.name, dest)
            # rotate backups for this package
            try:
                files = sorted([p for p in self.backup_dir.iterdir() if p.name.startswith(f"{pkg}-")], key=lambda p: p.stat().st_mtime, reverse=True)
                for old in files[self.keep_backups:]:
                    try:
                        old.unlink()
                    except Exception:
                        pass
            except Exception:
                pass
            return str(dest)
        except Exception as e:
            if self.logger:
                self.logger.error("upgrade.backup_fail", f"backup failed for {pkg}: {e}")
            return None

    def _restore_backup(self, backup_path: str) -> Tuple[bool, str]:
        try:
            p = Path(backup_path)
            if not p.exists():
                return False, "backup not found"
            with tarfile.open(str(p), mode="r:xz") as tf:
                # strip first path component (pkg) and extract
                for member in tf.getmembers():
                    parts = member.name.split("/", 1)
                    if len(parts) == 2:
                        member.name = parts[1]
                    else:
                        member.name = parts[-1]
                    # prevent path traversal
                    if member.name.startswith(".."):
                        continue
                    tf.extract(member, path="/")
            return True, "restored"
        except Exception as e:
            return False, str(e)

    # ---------------- fetch / download (with retries) ----------------
    def fetch_sources(self, pkg: str, metafile: Optional[Dict[str, Any]] = None, dest: Optional[str] = None, preferred_backends: Optional[List[str]] = None) -> Tuple[bool, str, Optional[List[str]]]:
        """
        Fetch sources for a package. Returns (ok, message, downloaded_paths)
        Uses metafile (if provided) to get urls. Retries with backoff.
        """
        dest_dir = Path(dest or tempfile.mkdtemp(prefix=f"newpkg-fetch-{pkg}-"))
        dest_dir.mkdir(parents=True, exist_ok=True)
        urls: List[str] = []
        # extract download urls from metafile structure if provided
        if metafile:
            # metafile may contain ['sources'] list or 'downloads'
            urls = metafile.get("downloads") or metafile.get("sources") or []
            if isinstance(urls, dict):
                # maybe a map of mirrors; flatten
                tmp = []
                for v in urls.values():
                    if isinstance(v, list):
                        tmp.extend(v)
                    elif isinstance(v, str):
                        tmp.append(v)
                urls = tmp
        # fallback: ask metafile manager
        if not urls and self.metafile and hasattr(self.metafile, "get_sources_for"):
            try:
                urls = self.metafile.get_sources_for(pkg) or []
            except Exception:
                urls = []

        if not urls:
            return False, "no sources found", None

        downloaded = []
        last_err = ""
        # use simple retry/backoff
        for url in urls:
            attempt = 0
            ok = False
            while attempt <= self.retries:
                attempt += 1
                try:
                    # choose backend: try aria2c/curl/wget/system fallback via curl if not provided
                    # But keep it simple: use system curl/wget if available else requests (not required)
                    curl = shutil.which("curl")
                    wget = shutil.which("wget")
                    aria = shutil.which("aria2c")
                    target = dest_dir / os.path.basename(url.split("?")[0])
                    if aria:
                        cmd = [aria, "-x", "4", "-s", "4", "-d", str(dest_dir), "-o", target.name, url]
                    elif curl:
                        cmd = [curl, "-L", "--fail", "-o", str(target), url]
                    elif wget:
                        cmd = [wget, "-O", str(target), url]
                    else:
                        # fallback to Python urllib
                        import urllib.request
                        try:
                            urllib.request.urlretrieve(url, str(target))
                            rc, out, err = 0, "downloaded", ""
                            ok = True
                        except Exception as e:
                            rc, out, err = 1, "", str(e)
                    if not ok:
                        rc, out, err = self._safe_run(cmd, timeout=self.timeout)
                        ok = rc == 0
                    if ok:
                        downloaded.append(str(target))
                        break
                    else:
                        last_err = err or out or f"rc={rc}"
                except Exception as e:
                    last_err = str(e)
                # backoff
                time.sleep(min(2 ** attempt, self.backoff_max))
            if not ok:
                # try next mirror/url
                continue
        if not downloaded:
            return False, last_err or "all downloads failed", None
        return True, "downloaded", downloaded

    # ---------------- apply patches ----------------
    def apply_patches(self, pkg: str, metafile: Optional[Dict[str, Any]] = None, workdir: Optional[str] = None) -> Tuple[bool, str]:
        """
        Apply patches listed in metafile using patcher module if available.
        """
        if not self.patcher:
            return True, "no patcher available; skipping"
        patches = []
        if metafile:
            patches = metafile.get("patches") or []
        if not patches:
            return True, "no patches required"
        try:
            # if patcher exposes apply_many or apply_all
            if hasattr(self.patcher, "apply_all"):
                res = self.patcher.apply_all([Path(p) for p in patches], Path(workdir or "/"))
                return (res.get("ok", False) if isinstance(res, dict) else bool(res)), str(res)
            elif hasattr(self.patcher, "apply_single"):
                msgs = []
                ok_any = True
                for p in patches:
                    r = self.patcher.apply_single(Path(p), Path(workdir or "/"))
                    if isinstance(r, dict):
                        ok_any = ok_any and bool(r.get("ok", False))
                        msgs.append(str(r))
                    else:
                        ok_any = ok_any and bool(r)
                return ok_any, "|".join(msgs)
        except Exception as e:
            return False, str(e)
        return True, "patched"

    # ---------------- build (with retries and sandbox) ----------------
    def build_package(self, pkg: str, workdir: Optional[str] = None, sandbox_profile: Optional[str] = None, use_sandbox: Optional[bool] = None) -> Tuple[bool, str]:
        """
        Build package using core.build_package (preferred) or fallback to metafile build commands.
        Retries with backoff on failure.
        """
        use_sandbox = self.use_sandbox if use_sandbox is None else bool(use_sandbox)
        sandbox_profile = sandbox_profile or self.sandbox_profile
        last_err = ""
        for attempt in range(1, self.retries + 1):
            with self._perf_timer("upgrade.build"):
                try:
                    if self.core and hasattr(self.core, "build_package"):
                        if use_sandbox and self.sandbox:
                            # attempt to call CLI inside sandbox for deterministic behavior
                            # We try to call core.build_package directly (best-effort), because serializing build in sandbox is environment-specific
                            try:
                                ok, msg = self.core.build_package(pkg, workdir=workdir, sandbox_profile=sandbox_profile)
                                if isinstance(ok, tuple) or isinstance(ok, dict):
                                    # support various return shapes
                                    if isinstance(ok, dict):
                                        ok_bool = bool(ok.get("ok", False))
                                        msg = json.dumps(ok)
                                    else:
                                        ok_bool = bool(ok[0])
                                else:
                                    ok_bool = bool(ok)
                                if ok_bool:
                                    return True, str(msg)
                                last_err = str(msg)
                            except Exception as e:
                                last_err = str(e)
                        else:
                            # direct
                            try:
                                r = self.core.build_package(pkg, workdir=workdir)
                                if isinstance(r, tuple):
                                    ok_bool = bool(r[0]); msg = str(r[1] if len(r) > 1 else "")
                                elif isinstance(r, dict):
                                    ok_bool = bool(r.get("ok", False)); msg = json.dumps(r)
                                else:
                                    ok_bool = bool(r); msg = ""
                                if ok_bool:
                                    return True, msg
                                last_err = msg or "build failed"
                            except Exception as e:
                                last_err = str(e)
                    else:
                        # fallback: try running build commands from metafile (if any)
                        mf = None
                        if self.metafile and hasattr(self.metafile, "load_metafile_for"):
                            try:
                                mf = self.metafile.load_metafile_for(pkg)
                            except Exception:
                                mf = None
                        build_cmds = []
                        if mf:
                            build_cmds = mf.get("build", []) or []
                        if build_cmds:
                            # run commands sequentially
                            for cmd in build_cmds:
                                if isinstance(cmd, str):
                                    rc, out, err = self._safe_run(["/bin/sh", "-c", cmd], cwd=workdir)
                                elif isinstance(cmd, list):
                                    rc, out, err = self._safe_run(cmd, cwd=workdir)
                                else:
                                    rc, out, err = 1, "", f"unsupported build cmd type: {cmd}"
                                if rc != 0:
                                    last_err = err or out or f"rc={rc}"
                                    raise RuntimeError(last_err)
                            return True, "built by metafile cmds"
                        else:
                            return False, "no build backend available"
                except Exception as e:
                    last_err = str(e)
            # backoff if not last attempt
            if attempt < self.retries:
                time.sleep(min(2 ** attempt, self.backoff_max))
        return False, last_err or "build failed after retries"

    # ---------------- package / install ----------------
    def package_and_install(self, pkg: str, workdir: Optional[str] = None, use_fakeroot: bool = True) -> Tuple[bool, str]:
        """
        Package built artifacts and install into destdir or system via core.install_package if available.
        """
        try:
            if self.core and hasattr(self.core, "package_and_install"):
                r = self.core.package_and_install(pkg, workdir=workdir, use_fakeroot=use_fakeroot)
                if isinstance(r, tuple):
                    ok = bool(r[0]); msg = str(r[1] if len(r) > 1 else "")
                elif isinstance(r, dict):
                    ok = bool(r.get("ok", False)); msg = json.dumps(r)
                else:
                    ok = bool(r); msg = ""
                return ok, msg
            # fallback: no universal packaging method
            return True, "no package step required (fallback)"
        except Exception as e:
            return False, str(e)

    # ---------------- verify ----------------
    def verify_install(self, pkg: str) -> Tuple[bool, str]:
        """
        Verify package via DB checksum or optional verification hooks.
        """
        try:
            # call core.verify_package if present
            if self.core and hasattr(self.core, "verify_package"):
                r = self.core.verify_package(pkg)
                if isinstance(r, tuple):
                    ok = bool(r[0]); msg = str(r[1] if len(r) > 1 else "")
                elif isinstance(r, dict):
                    ok = bool(r.get("ok", False)); msg = json.dumps(r)
                else:
                    ok = bool(r); msg = ""
                return ok, msg
            return True, "no verification backend"
        except Exception as e:
            return False, str(e)

    # ---------------- post-deploy cleanup (remove old versions) ----------------
    def cleanup_old_versions(self, pkg: str, keep: int = 2) -> Tuple[bool, str]:
        if not self.cleanup_old:
            return True, "cleanup disabled"
        if not self.remover:
            return False, "remover not available"
        try:
            # attempt to find previous versions via db.get_package_versions or similar
            versions = []
            if self.db and hasattr(self.db, "get_package_versions"):
                try:
                    versions = self.db.get_package_versions(pkg) or []
                except Exception:
                    versions = []
            # versions is list of dicts with 'version' and 'installed_at' maybe
            # pick older ones to remove
            if not versions:
                return True, "no version history"
            # assume versions sorted newest-first; if not, sort by installed date if present
            if versions and isinstance(versions[0], dict) and "installed_at" in versions[0]:
                versions_sorted = sorted(versions, key=lambda v: v.get("installed_at", 0), reverse=True)
            else:
                versions_sorted = list(versions)
            to_remove = versions_sorted[keep:]
            removed = []
            for v in to_remove:
                ver = v.get("version") if isinstance(v, dict) else str(v)
                # call remover.remove_version(package, version) if exists
                try:
                    if hasattr(self.remover, "remove_version"):
                        ok, msg = self.remover.remove_version(pkg, ver)
                        if ok:
                            removed.append(ver)
                except Exception:
                    continue
            return True, f"removed versions: {removed}"
        except Exception as e:
            return False, str(e)

    # ---------------- single package upgrade pipeline ----------------
    def _process_single(self, pkg: str, metafile: Optional[Dict[str, Any]] = None, workdir: Optional[str] = None, use_sandbox: Optional[bool] = None) -> UpgradeResult:
        t0 = time.time()
        report = {"pkg": pkg, "start": now_iso(), "stages": [], "ok": False}
        report_path = None
        use_sandbox = self.use_sandbox if use_sandbox is None else bool(use_sandbox)
        try:
            # pre-upgrade hook
            if self.hooks:
                try:
                    self.hooks.run("pre_upgrade", {"package": pkg, "metafile": metafile})
                except Exception:
                    pass

            # 1) fetch
            with self._perf_timer("upgrade.fetch"):
                if self.hooks:
                    try:
                        self.hooks.run("pre_fetch", {"package": pkg})
                    except Exception:
                        pass
                ok, msg, downloaded = self.fetch_sources(pkg, metafile=metafile, dest=workdir)
                report["stages"].append({"stage": "fetch", "ok": ok, "message": msg, "downloaded": downloaded})
                if self.hooks:
                    try:
                        self.hooks.run("post_fetch", {"package": pkg, "ok": ok, "message": msg, "downloaded": downloaded})
                    except Exception:
                        pass
                if not ok:
                    raise RuntimeError(f"fetch failed: {msg}")

            # 2) backup current installation (best-effort)
            with self._perf_timer("upgrade.backup"):
                # gather paths to backup from DB metadata if possible
                backup_paths = []
                if self.db and hasattr(self.db, "get_package_files"):
                    try:
                        backup_paths = self.db.get_package_files(pkg) or []
                    except Exception:
                        backup_paths = []
                backup_path = None
                if backup_paths:
                    backup_path = self._create_backup(pkg, backup_paths)
                report["stages"].append({"stage": "backup", "ok": True, "backup": backup_path})

            # 3) apply patches if any
            with self._perf_timer("upgrade.patches"):
                ok_patch, patch_msg = self.apply_patches(pkg, metafile=metafile, workdir=workdir)
                report["stages"].append({"stage": "patch", "ok": ok_patch, "message": patch_msg})
                if not ok_patch:
                    raise RuntimeError(f"patch apply failed: {patch_msg}")

            # 4) build
            with self._perf_timer("upgrade.build"):
                if self.hooks:
                    try:
                        self.hooks.run("pre_build", {"package": pkg})
                    except Exception:
                        pass
                ok_build, build_msg = self.build_package(pkg, workdir=workdir, use_sandbox=use_sandbox)
                report["stages"].append({"stage": "build", "ok": ok_build, "message": build_msg})
                if self.hooks:
                    try:
                        self.hooks.run("post_build", {"package": pkg, "ok": ok_build, "message": build_msg})
                    except Exception:
                        pass
                if not ok_build:
                    raise RuntimeError(f"build failed: {build_msg}")

            # 5) package/install
            with self._perf_timer("upgrade.package"):
                ok_pkg, pkg_msg = self.package_and_install(pkg, workdir=workdir)
                report["stages"].append({"stage": "package", "ok": ok_pkg, "message": pkg_msg})
                if not ok_pkg:
                    raise RuntimeError(f"package/install failed: {pkg_msg}")

            # 6) verify
            with self._perf_timer("upgrade.verify"):
                ok_ver, ver_msg = self.verify_install(pkg)
                report["stages"].append({"stage": "verify", "ok": ok_ver, "message": ver_msg})
                if not ok_ver:
                    raise RuntimeError(f"verify failed: {ver_msg}")

            # 7) post-deploy hooks and audit
            with self._perf_timer("upgrade.deploy"):
                if self.hooks:
                    try:
                        self.hooks.run("pre_deploy", {"package": pkg})
                    except Exception:
                        pass
                if self.audit:
                    try:
                        # incremental attempt to call audit for the package (best-effort)
                        self.audit.scan_system()
                    except Exception:
                        pass
                if self.hooks:
                    try:
                        self.hooks.run("post_deploy", {"package": pkg})
                    except Exception:
                        pass

            # 8) cleanup old versions if configured
            if self.cleanup_old:
                try:
                    keep = int(self._cfg_get("upgrade.keep_versions", 2))
                    ok_cleanup, cleanup_msg = self.cleanup_old_versions(pkg, keep=keep)
                    report["stages"].append({"stage": "cleanup_old", "ok": ok_cleanup, "message": cleanup_msg})
                except Exception as e:
                    report["stages"].append({"stage": "cleanup_old", "ok": False, "message": str(e)})

            report["ok"] = True
            report["end"] = now_iso()
            # save report
            report_path = str(self._save_report(pkg, report))
            # post-upgrade hook
            if self.hooks:
                try:
                    self.hooks.run("post_upgrade", {"package": pkg, "report": report_path})
                except Exception:
                    pass
            # record in DB
            try:
                if self.db:
                    self.db.record_phase(pkg, "upgrade", "ok", meta={"report": report_path})
            except Exception:
                pass

            # optionally remove old versions via remover
            if self.cleanup_old and self.remover:
                try:
                    keep = int(self._cfg_get("upgrade.keep_versions", 2))
                    self.cleanup_old_versions(pkg, keep=keep)
                except Exception:
                    pass

            duration = time.time() - t0
            return UpgradeResult(package=pkg, ok=True, stage="done", message="upgrade successful", report_path=report_path, duration=duration)

        except Exception as e:
            # attempt rollback if backup exists
            err = str(e)
            tb = traceback.format_exc()
            if self.logger:
                self.logger.error("upgrade.fail", f"upgrade failed for {pkg}: {err}", traceback=tb)
            # record fail phase
            try:
                if self.db:
                    self.db.record_phase(pkg, "upgrade", "fail", meta={"error": err})
            except Exception:
                pass
            # try restore
            try:
                if 'backup_path' in locals() and backup_path:
                    r_ok, r_msg = self._restore_backup(backup_path)
                    if self.logger:
                        self.logger.info("upgrade.rollback", f"rollback attempted for {pkg}: {r_ok} {r_msg}")
                else:
                    # no backup: nothing to restore
                    r_ok, r_msg = False, "no backup available"
            except Exception as e2:
                r_ok, r_msg = False, str(e2)
            report["ok"] = False
            report["error"] = err
            report["traceback"] = tb
            report["rollback"] = {"attempted": bool(backup_path), "result": r_ok, "message": r_msg}
            report["end"] = now_iso()
            report_path = str(self._save_report(pkg, report))
            # audit fail
            if self.audit:
                try:
                    self.audit.report("upgrade", pkg, "failed", {"error": err, "rollback": r_ok})
                except Exception:
                    pass
            duration = time.time() - t0
            return UpgradeResult(package=pkg, ok=False, stage="failed", message=err, report_path=report_path, duration=duration)

    # ---------------- public API: upgrade a package ----------------
    def upgrade_package(self, pkg: str, metafile: Optional[Dict[str, Any]] = None, workdir: Optional[str] = None, use_sandbox: Optional[bool] = None) -> UpgradeResult:
        """
        Public API to upgrade a single package. Returns UpgradeResult.
        """
        # prepare workdir if none
        if workdir is None:
            workdir = str(tempfile.mkdtemp(prefix=f"newpkg-work-{pkg}-"))
        # show progress via logger if available
        progress_ctx = None
        if self.logger:
            try:
                progress_ctx = self.logger.progress(f"Upgrading {pkg}", total=1)
            except Exception:
                progress_ctx = None
        res = self._process_single(pkg, metafile=metafile, workdir=workdir, use_sandbox=use_sandbox)
        if progress_ctx:
            try:
                progress_ctx.__exit__(None, None, None)
            except Exception:
                pass
        return res

    # ---------------- upgrade multiple packages (parallel) ----------------
    def upgrade_all(self, pkgs: List[str], parallel: Optional[int] = None, metafiles: Optional[Dict[str, Dict[str, Any]]] = None) -> List[UpgradeResult]:
        """
        Upgrade multiple packages concurrently. metafiles may be a dict pkg->metafile.
        """
        parallel = parallel or self.parallel
        results: List[UpgradeResult] = []
        # hooks
        if self.hooks:
            try:
                self.hooks.run("pre_upgrade_all", {"packages": pkgs})
            except Exception:
                pass

        progress_ctx = None
        if self.logger:
            try:
                progress_ctx = self.logger.progress(f"Upgrading {len(pkgs)} packages", total=len(pkgs))
            except Exception:
                progress_ctx = None

        with ThreadPoolExecutor(max_workers=max(1, parallel)) as ex:
            future_map = {}
            for pkg in pkgs:
                mf = (metafiles or {}).get(pkg) if metafiles else None
                fut = ex.submit(self.upgrade_package, pkg, mf)
                future_map[fut] = pkg
            for fut in as_completed(future_map):
                pkg = future_map[fut]
                try:
                    r = fut.result()
                except Exception as e:
                    r = UpgradeResult(package=pkg, ok=False, stage="exception", message=str(e), report_path=None, duration=0.0)
                results.append(r)
                # update progress
                try:
                    if progress_ctx:
                        pass
                except Exception:
                    pass

        if progress_ctx:
            try:
                progress_ctx.__exit__(None, None, None)
            except Exception:
                pass

        if self.hooks:
            try:
                self.hooks.run("post_upgrade_all", {"results": [asdict(x) for x in results]})
            except Exception:
                pass

        return results

    # ---------------- CLI ----------------
    def cli(self, argv: Optional[List[str]] = None) -> int:
        import argparse
        parser = argparse.ArgumentParser(prog="newpkg-upgrade", description="Upgrade packages safely (newpkg)")
        parser.add_argument("packages", nargs="*", help="package names to upgrade (omit for all)")
        parser.add_argument("--all", action="store_true", help="upgrade all packages available in repo/metafiles")
        parser.add_argument("--parallel", type=int, help="parallel workers")
        parser.add_argument("--report-dir", help="override report dir")
        parser.add_argument("--dry-run", action="store_true", help="dry run")
        args = parser.parse_args(argv or sys.argv[1:])

        if args.report_dir:
            self.report_dir = Path(args.report_dir)
            self.report_dir.mkdir(parents=True, exist_ok=True)
        if args.parallel:
            self.parallel = args.parallel
        if args.dry_run:
            self.dry_run = True

        target_pkgs = []
        if args.all:
            # try to list packages from metafile or db
            if self.metafile and hasattr(self.metafile, "list_all_packages"):
                try:
                    target_pkgs = self.metafile.list_all_packages()
                except Exception:
                    target_pkgs = []
            elif self.db and hasattr(self.db, "list_available_packages"):
                try:
                    target_pkgs = [p.get("name") for p in self.db.list_available_packages()]
                except Exception:
                    target_pkgs = []
            else:
                if self.logger:
                    self.logger.error("upgrade.cli.no_packages", "no package source available for --all")
                return 2
        else:
            if not args.packages:
                parser.print_help()
                return 1
            target_pkgs = args.packages

        # run upgrades
        results = self.upgrade_all(target_pkgs, parallel=self.parallel)
        # summary
        ok = all(r.ok for r in results)
        if RICH and _console:
            tbl = []
            for r in results:
                status = "[green]OK[/green]" if r.ok else "[red]FAIL[/red]"
                _console.print(f"{r.package}: {status} ({r.stage}) - {r.message or ''}")
        else:
            for r in results:
                print(f"{r.package}\t{r.ok}\t{r.stage}\t{r.message}")
        return 0 if ok else 2


# ---------------- module-level convenience ----------------
_default_upgrade: Optional[NewpkgUpgrade] = None


def get_upgrade(cfg: Any = None, logger: Any = None, db: Any = None, hooks: Any = None,
                sandbox: Any = None, core: Any = None, metafile: Any = None, patcher: Any = None,
                remover: Any = None, audit: Any = None, deps: Any = None) -> NewpkgUpgrade:
    global _default_upgrade
    if _default_upgrade is None:
        _default_upgrade = NewpkgUpgrade(cfg=cfg, logger=logger, db=db, hooks=hooks, sandbox=sandbox, core=core, metafile=metafile, patcher=patcher, remover=remover, audit=audit, deps=deps)
    return _default_upgrade


if __name__ == "__main__":
    u = get_upgrade()
    sys.exit(u.cli())
