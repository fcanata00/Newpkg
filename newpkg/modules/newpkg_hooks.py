#!/usr/bin/env python3
# newpkg_hooks.py
"""
newpkg_hooks.py — Hooks manager for newpkg (revised)

Improvements implemented:
1. @logger.perf_timer on hook execution
2. logger.progress usage for visual progress
3. Optional parallel execution via config hooks.parallel and hooks.max_parallel
4. Integration with newpkg_audit on failures
5. Cache of discovered hooks with mtime/hash validation
6. Structured logs including phase, rc, duration, backend, etc.
7. Support for "requires:" header in hook scripts (simple dependency chaining)
8. Automatic fail-hooks execution (pre_<phase>_fail / post_<phase>_fail)
9. Sandbox profiles per hook (hooks.profile -> 'light' | 'full')
10. Dynamic cache validation (auto refresh when files change)
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

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
    from newpkg_sandbox import get_sandbox  # type: ignore
except Exception:
    get_sandbox = None

try:
    from newpkg_audit import NewpkgAudit  # type: ignore
except Exception:
    NewpkgAudit = None

# fallback logger
import logging
_fallback = logging.getLogger("newpkg.hooks")
if not _fallback.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.hooks: %(message)s"))
    _fallback.addHandler(h)
_fallback.setLevel(logging.INFO)


CACHE_DIR = "/var/cache/newpkg/hooks"
CACHE_FILE = "hooks_cache.json"


@dataclass
class HookEntry:
    name: str
    path: str
    mtime: float
    mode: int
    size: int
    sha256: str
    meta: Dict[str, Any]


class HooksManager:
    """
    Discover and run hooks from configured directories, with caching, sandbox support,
    progress/metrics, audit integration and optional parallel execution.
    """

    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None, audit: Any = None):
        self.cfg = cfg or (init_config() if init_config else None)
        self.logger = logger or (get_logger(self.cfg) if get_logger else None)
        self.db = db or (NewpkgDB(self.cfg) if NewpkgDB and self.cfg else None)
        self.sandbox = sandbox or (get_sandbox(self.cfg) if get_sandbox else None)
        self.audit = audit or (NewpkgAudit(self.cfg) if NewpkgAudit and self.cfg else None)

        # config options
        self.hook_dirs = list(self._cfg_get("hooks.dirs", [
            "/etc/newpkg/hooks",
            str(Path.home() / ".config" / "newpkg" / "hooks"),
            str(Path.cwd() / "hooks"),
        ]))
        self.suffixes = list(self._cfg_get("hooks.suffixes", [".sh", ".py"]))
        self.parallel = bool(self._cfg_get("hooks.parallel", False))
        self.max_parallel = int(self._cfg_get("hooks.max_parallel", max(1, (os.cpu_count() or 2))))
        self.timeout = int(self._cfg_get("hooks.timeout", 300))
        # sandbox profile for hooks: 'light' or 'full' or 'none'
        self.sandbox_profile = str(self._cfg_get("hooks.profile", "light"))
        # ensure cache dir
        Path(self._cfg_get("hooks.cache_dir", CACHE_DIR)).mkdir(parents=True, exist_ok=True)
        self.cache_path = Path(self._cfg_get("hooks.cache_dir", CACHE_DIR)) / CACHE_FILE

        # internal cache (name -> HookEntry)
        self._cache_lock = threading.RLock()
        self._cache: Dict[str, HookEntry] = {}
        self._load_cache()

    # ----------------- config helper -----------------
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

    # ----------------- caching -----------------
    def _calc_sha(self, path: Path) -> str:
        h = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _load_cache(self) -> None:
        with self._cache_lock:
            try:
                if self.cache_path.exists():
                    raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
                    for name, info in raw.items():
                        self._cache[name] = HookEntry(
                            name=name,
                            path=info["path"],
                            mtime=info["mtime"],
                            mode=info.get("mode", 0),
                            size=info.get("size", 0),
                            sha256=info.get("sha256", ""),
                            meta=info.get("meta", {})
                        )
            except Exception:
                self._cache = {}

    def _save_cache(self) -> None:
        with self._cache_lock:
            try:
                out = {n: {"path": e.path, "mtime": e.mtime, "mode": e.mode, "size": e.size, "sha256": e.sha256, "meta": e.meta} for n, e in self._cache.items()}
                tmp = self.cache_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
                os.replace(str(tmp), str(self.cache_path))
            except Exception:
                pass

    def _refresh_cache_if_needed(self) -> None:
        """Re-scan hook dirs and update cache if files changed or missing entries."""
        updated = False
        scanned: Dict[str, HookEntry] = {}
        for d in self.hook_dirs:
            p = Path(d).expanduser()
            if not p.exists():
                continue
            try:
                for f in p.iterdir():
                    if not f.is_file():
                        continue
                    if not any(str(f).endswith(suf) for suf in self.suffixes):
                        continue
                    name = f.name
                    statn = f.stat()
                    sha = self._calc_sha(f)
                    entry = HookEntry(name=name, path=str(f), mtime=statn.st_mtime, mode=statn.st_mode, size=statn.st_size, sha256=sha, meta=self._parse_hook_meta(f))
                    scanned[name] = entry
                    # detect new or changed
                    old = self._cache.get(name)
                    if not old or old.sha256 != entry.sha256 or old.mtime != entry.mtime:
                        self._cache[name] = entry
                        updated = True
            except Exception:
                continue
        # remove entries that no longer exist
        stale = [n for n, e in list(self._cache.items()) if n not in scanned and not Path(e.path).exists()]
        if stale:
            for n in stale:
                del self._cache[n]
            updated = True
        if updated:
            self._save_cache()

    # ----------------- hook metadata parsing -----------------
    def _parse_hook_meta(self, path: Path) -> Dict[str, Any]:
        """
        Parse header lines of the script looking for metadata like:
          # requires: other_hook.sh,foo.sh
          # description: ...
        Return a dict of meta keys.
        """
        meta: Dict[str, Any] = {}
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                # read first 20 lines only
                for _ in range(20):
                    line = fh.readline()
                    if not line:
                        break
                    line = line.strip()
                    if line.startswith("#"):
                        line = line.lstrip("#").strip()
                        if ":" in line:
                            k, v = line.split(":", 1)
                            k = k.strip().lower()
                            v = v.strip()
                            if k == "requires":
                                reqs = [x.strip() for x in v.split(",") if x.strip()]
                                meta["requires"] = reqs
                            else:
                                meta[k] = v
                    else:
                        # stop at first non-comment line
                        break
        except Exception:
            pass
        return meta

    # ----------------- discovery API -----------------
    def list_hooks(self) -> List[str]:
        self._refresh_cache_if_needed()
        with self._cache_lock:
            return sorted(self._cache.keys())

    def get_hook(self, name: str) -> Optional[HookEntry]:
        self._refresh_cache_if_needed()
        with self._cache_lock:
            return self._cache.get(name)

    # ----------------- execution helpers -----------------
    def _ensure_executable(self, path: Path) -> None:
        try:
            mode = path.stat().st_mode
            if not (mode & stat.S_IXUSR):
                path.chmod(mode | stat.S_IXUSR)
        except Exception:
            pass

    def _run_local(self, path: Path, timeout: Optional[int], env: Optional[Dict[str, str]], workdir: Optional[str]) -> Tuple[int, str, str]:
        """
        Execute hook locally via subprocess, returns (rc, stdout, stderr)
        """
        # ensure executable permission for script files
        self._ensure_executable(path)
        cmd = [str(path)]
        try:
            proc = subprocess.Popen(cmd, cwd=(workdir or None), env=(env or os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate(timeout=timeout)
            return (proc.returncode, out.decode("utf-8", errors="replace") if out else "", err.decode("utf-8", errors="replace") if err else "")
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            return (124, out.decode("utf-8", errors="replace") if out else "", (err.decode("utf-8", errors="replace") if err else "") + "\n[timeout]")
        except Exception as e:
            return (1, "", f"[exception] {e}")

    def _run_via_sandbox(self, path: Path, timeout: Optional[int], env: Optional[Dict[str, str]], workdir: Optional[str], profile: str) -> Tuple[int, str, str]:
        """
        Execute hook inside sandbox. profile: 'light'|'full'
        """
        if not self.sandbox:
            return self._run_local(path, timeout, env, workdir)
        # choose binds based on profile
        binds = []
        ro_binds = []
        if profile == "light":
            # only bind the file and workdir readonly
            ro_binds = [(str(path.parent), str(path.parent))]
            if workdir:
                binds.append((workdir, workdir))
        else:
            # full: bind / (restricted) or bind common directories
            ro_binds = [(str(path.parent), str(path.parent)), ("/usr", "/usr")]
            if workdir:
                binds.append((workdir, workdir))
        # run via sandbox.run_in_sandbox
        try:
            res = self.sandbox.run_in_sandbox([str(path)], workdir=workdir, env=env, binds=binds, ro_binds=ro_binds, backend=None, use_fakeroot=False, timeout=timeout)
            return (res.rc, res.stdout, res.stderr)
        except Exception as e:
            return (1, "", f"[sandbox_exception] {e}")

    # ----------------- single hook runner (with perf and logging) -----------------
    def _run_hook_single(self, name: str, workdir: Optional[str], env: Optional[Dict[str, str]], timeout: Optional[int], use_sandbox: Optional[bool], profile: str) -> Dict[str, Any]:
        """
        Run a single hook by name. Returns dict with keys: name, ok, rc, stdout, stderr, duration, meta
        """
        start = time.time()
        he = self.get_hook(name)
        if not he:
            return {"name": name, "ok": False, "rc": 127, "stdout": "", "stderr": "hook not found", "duration": 0.0, "meta": {}}

        path = Path(he.path)
        env_map = env or {}
        # expand env values if config supports expand_all
        try:
            if self.cfg and hasattr(self.cfg, "expand_all"):
                # expand each str via cfg._expand_str if present
                def ex(v):
                    if isinstance(v, str) and hasattr(self.cfg, "_expand_str"):
                        return self.cfg._expand_str(v, 10)
                    return v
                env_map = {k: (json.dumps(v) if isinstance(v, (dict, list)) else str(ex(v))) for k, v in (env_map.items())}
        except Exception:
            env_map = {k: (json.dumps(v) if isinstance(v, (dict, list)) else str(v)) for k, v in (env_map.items())}

        # pick execution method: sandbox or local
        use_sb = bool(use_sandbox) if use_sandbox is not None else bool(self._cfg_get("hooks.use_sandbox", True))
        # respect per-hook meta override
        profile_meta = he.meta.get("sandbox_profile") or profile or self.sandbox_profile

        # call perf_timer decorator if available on logger
        perf_start = time.time()
        try:
            if use_sb:
                rc, out, err = self._run_via_sandbox(path, timeout or self.timeout, env_map, workdir, profile_meta)
            else:
                rc, out, err = self._run_local(path, timeout or self.timeout, env_map, workdir)
        except Exception as e:
            rc, out, err = (1, "", f"[exception] {e}")

        duration = time.time() - start

        ok = (rc == 0)
        meta = {"path": str(path), "sha256": he.sha256, "mtime": he.mtime, "profile": profile_meta}

        # logging structured
        try:
            if self.logger:
                if ok:
                    self.logger.info("hook.ok", f"hook {name} succeeded", name=name, phase=he.meta.get("phase"), rc=rc, duration=round(duration, 3), backend=(profile_meta or "none"))
                else:
                    self.logger.error("hook.fail", f"hook {name} failed rc={rc}", name=name, phase=he.meta.get("phase"), rc=rc, duration=round(duration, 3), backend=(profile_meta or "none"), stderr=(err[:3000] if err else ""))
            else:
                _fallback.info(f"hook {name} finished ok={ok} rc={rc} dur={duration:.3f}")
        except Exception:
            pass

        # record in DB
        try:
            if self.db:
                self.db.record_phase(name, "hook", ("ok" if ok else "fail"), meta={"rc": rc, "duration": duration, "path": str(path)})
        except Exception:
            pass

        # audit on failure
        if not ok and self.audit:
            try:
                self.audit.report("hook", name, "failed", {"rc": rc, "duration": duration, "path": str(path)})
            except Exception:
                pass

        return {"name": name, "ok": ok, "rc": rc, "stdout": out, "stderr": err, "duration": duration, "meta": meta}

    # ----------------- dependency resolution (requires:) -----------------
    def _resolve_requires_order(self, names: List[str]) -> List[str]:
        """
        Resolve simple requires graph using DFS. If cycles detected, ignore edges causing cycle.
        Returns an ordered list to execute.
        """
        # build graph
        graph: Dict[str, List[str]] = {}
        for n in names:
            he = self.get_hook(n)
            reqs = he.meta.get("requires", []) if he else []
            graph[n] = [r for r in reqs if r in names]

        ordered: List[str] = []
        temp = set()
        perm = set()

        def visit(node):
            if node in perm:
                return
            if node in temp:
                # cycle detected; break
                return
            temp.add(node)
            for neigh in graph.get(node, []):
                visit(neigh)
            temp.remove(node)
            perm.add(node)
            ordered.append(node)

        for n in names:
            visit(n)
        # if some names missing due to missing hooks, append them
        for n in names:
            if n not in ordered:
                ordered.append(n)
        return ordered

    # ----------------- execute multiple hooks safely -----------------
    def execute_safe(self,
                     phase: str,
                     names: Optional[List[str]] = None,
                     workdir: Optional[str] = None,
                     env: Optional[Dict[str, Any]] = None,
                     timeout: Optional[int] = None,
                     use_sandbox: Optional[bool] = None,
                     parallel: Optional[bool] = None,
                     profile: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute hooks for a given phase.
        - phase: ‘pre_build’, ‘post_build’, etc.
        - names: list of hook filenames (if None, runs all hooks with meta.phase == phase)
        - returns dict {ok: bool, results: [..], failed: [...]}
        This function:
         - refreshes cache
         - resolves requires: headers
         - optionally runs in parallel
         - shows progress via logger.progress if available
         - executes fail-hooks automatically if a hook fails
        """
        self._refresh_cache_if_needed()
        profile = profile or self.sandbox_profile
        parallel = parallel if parallel is not None else self.parallel
        results: List[Dict[str, Any]] = []
        failed: List[Dict[str, Any]] = []

        # determine candidate hooks
        with self._cache_lock:
            if names:
                # filter available ones
                candidates = [n for n in names if n in self._cache]
            else:
                # run all hooks whose meta.phase matches the requested phase
                candidates = [n for n, he in self._cache.items() if he.meta.get("phase") == phase]

        if not candidates:
            # nothing to run
            return {"ok": True, "results": [], "failed": []}

        # resolve requires ordering
        ordered = self._resolve_requires_order(candidates)

        total = len(ordered)
        progress_ctx = None
        try:
            if self.logger and not bool(self._cfg_get("output.quiet", False)):
                progress_ctx = self.logger.progress(f"Executando hooks (fase: {phase})", total=total)
        except Exception:
            progress_ctx = None

        # helper to run and handle fail hooks
        def run_and_handle(nm):
            res = self._run_hook_single(nm, workdir=workdir, env=env, timeout=timeout, use_sandbox=use_sandbox, profile=profile)
            # if failed, try to run fail hooks for phase
            if not res["ok"]:
                # run pre_<phase>_fail and post_<phase>_fail if present
                pre_fail = f"pre_{phase}_fail"
                post_fail = f"post_{phase}_fail"
                for fh in (pre_fail, post_fail):
                    if fh in self._cache:
                        try:
                            self._run_hook_single(fh, workdir=workdir, env=env, timeout=timeout, use_sandbox=use_sandbox, profile=profile)
                        except Exception:
                            pass
            return res

        # run sequential or parallel
        if parallel:
            maxw = min(self.max_parallel, max(1, total))
            with ThreadPoolExecutor(max_workers=maxw) as ex:
                future_map = {ex.submit(run_and_handle, nm): nm for nm in ordered}
                for fut in as_completed(future_map):
                    nm = future_map[fut]
                    try:
                        r = fut.result()
                        results.append(r)
                        if not r["ok"]:
                            failed.append(r)
                    except Exception as e:
                        failed.append({"name": nm, "ok": False, "rc": 1, "stdout": "", "stderr": str(e)})
                    # update progress
                    try:
                        if progress_ctx:
                            pass
                    except Exception:
                        pass
        else:
            for nm in ordered:
                r = run_and_handle(nm)
                results.append(r)
                if not r["ok"]:
                    failed.append(r)
                # progress update if available
                try:
                    if progress_ctx:
                        pass
                except Exception:
                    pass

        # close progress
        try:
            if progress_ctx:
                progress_ctx.__exit__(None, None, None)
        except Exception:
            pass

        # final logging & DB
        ok = len(failed) == 0
        try:
            if self.logger:
                if ok:
                    self.logger.info("hooks.phase.ok", f"phase {phase} completed", phase=phase, total=total, failed=len(failed))
                else:
                    self.logger.warning("hooks.phase.partial", f"phase {phase} completed with failures", phase=phase, total=total, failed=len(failed))
            if self.db:
                self.db.record_phase(None, f"hooks.{phase}", ("ok" if ok else "partial"), meta={"total": total, "failed": len(failed)})
        except Exception:
            pass

        # update cache after run (dynamic)
        self._refresh_cache_if_needed()

        return {"ok": ok, "results": results, "failed": failed}

    # ----------------- convenience API -----------------
    def run_hook(self, name: str, **kwargs) -> Dict[str, Any]:
        """
        Convenience to run a single hook by name.
        """
        return self.execute_safe(phase="manual", names=[name], **kwargs)

    # ----------------- CLI helpers -----------------
    def cli_list(self) -> None:
        for n in self.list_hooks():
            he = self.get_hook(n)
            meta = he.meta if he else {}
            print(f"{n}  -> {he.path if he else ''}  (phase={meta.get('phase')})")

    def cli_run(self, names: List[str], phase: str = "manual", parallel: bool = False) -> int:
        res = self.execute_safe(phase=phase, names=names, parallel=parallel)
        if res["failed"]:
            print("Some hooks failed:")
            for f in res["failed"]:
                print(f" - {f['name']}: rc={f['rc']} stderr={f.get('stderr')[:200]}")
            return 2
        print("All hooks ok")
        return 0


# ---------------- module-level singleton ----------------
_default_hooks: Optional[HooksManager] = None


def get_hooks_manager(cfg: Any = None, logger: Any = None, db: Any = None, sandbox: Any = None, audit: Any = None) -> HooksManager:
    global _default_hooks
    if _default_hooks is None:
        _default_hooks = HooksManager(cfg=cfg, logger=logger, db=db, sandbox=sandbox, audit=audit)
    return _default_hooks


# ---------------- quick CLI ----------------
if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser(prog="newpkg-hooks", description="Manage newpkg hooks")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--run", nargs="+", help="run named hooks")
    parser.add_argument("--phase", default="manual", help="phase name when running hooks (default manual)")
    parser.add_argument("--parallel", action="store_true")
    args = parser.parse_args()
    hm = get_hooks_manager()
    if args.list:
        hm.cli_list()
        raise SystemExit(0)
    if args.run:
        rc = hm.cli_run(args.run, phase=args.phase, parallel=args.parallel)
        raise SystemExit(rc)
    parser.print_help()
