#!/usr/bin/env python3
# newpkg_hooks.py
"""
newpkg_hooks.py — hooks manager for newpkg (revised)

Features:
 - auto integration with newpkg_api (api.hooks)
 - discover hooks under hooks_dir (configurable)
 - TTL cache for discovery to speed startup
 - per-hook metadata: requires, async, sandbox_profile, timeout, backend
 - sandbox per-hook (none|light|full) using api.sandbox when available
 - async hooks executed in background threads, results recorded
 - failure logs stored in /var/log/newpkg/hooks/<hook>.fail.N.log (rotated)
 - cycle detection in requires graph with readable report
 - environment sanitization before running a hook
 - performance recording via logger.perf_timer and db.record_phase
 - user-friendly CLI with JSON and color output
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import threading
import time
from collections import deque, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

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
    from newpkg_sandbox import get_sandbox  # type: ignore
except Exception:
    get_sandbox = None

# Optional niceties
try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    RICH = True
    _console = Console()
except Exception:
    RICH = False
    _console = None

try:
    import psutil  # for CPU/memory sampling
    PSUTIL = True
except Exception:
    PSUTIL = False

# fallback logger
import logging
_logger = logging.getLogger("newpkg.hooks")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.hooks: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)

# defaults
DEFAULT_HOOKS_DIR = "/etc/newpkg/hooks"
DEFAULT_HOOKS_LOG_DIR = "/var/log/newpkg/hooks"
DEFAULT_CACHE_TTL = 60  # seconds
DEFAULT_FAIL_LOG_KEEP = 5
DEFAULT_ASYNC_THREADPOOL = 8

# sensitive prefixes/keys to sanitize
_SENSITIVE_PREFIXES = ("SSH_", "GPG_", "AWS_", "AZURE_", "DOCKER_", "SECRET", "TOKEN", "API_KEY", "APIKEY")
_SENSITIVE_KEYS = {"PASSWORD", "PASS", "SECRET", "TOKEN", "API_KEY", "APIKEY", "SSH_AUTH_SOCK"}

# dataclasses
@dataclass
class HookEntry:
    name: str
    path: Path
    meta: Dict[str, Any]  # parsed metadata, may include requires, async, sandbox_profile, timeout, backend
    executable: bool

@dataclass
class HookResult:
    name: str
    ok: bool
    rc: int
    duration: float
    stdout: str
    stderr: str
    async_job: bool
    timestamp: float
    meta: Dict[str, Any]


# helpers
def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _ensure_dir(p: Path, mode: int = 0o755):
    try:
        p.mkdir(parents=True, exist_ok=True)
        try:
            p.chmod(mode)
        except Exception:
            pass
    except Exception:
        pass

def _sanitize_env(env: Optional[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    base_keep = ["PATH", "HOME", "LANG", "LC_ALL", "USER", "LOGNAME", "TMPDIR"]
    for k in base_keep:
        v = os.environ.get(k)
        if v:
            out[k] = v
    if not env:
        return out
    for k, v in env.items():
        ku = k.upper()
        if ku in _SENSITIVE_KEYS:
            continue
        if any(ku.startswith(pref) for pref in _SENSITIVE_PREFIXES):
            continue
        out[k] = v
    return out

def _rotate_fail_log(hook_name: str, content: str, keep: int = DEFAULT_FAIL_LOG_KEEP) -> str:
    logdir = Path(os.environ.get("NEWPKG_HOOKS_LOGDIR", DEFAULT_HOOKS_LOG_DIR))
    _ensure_dir(logdir, mode=0o755)
    prefix = logdir / f"{hook_name}.fail"
    # rotate older logs up to keep count
    try:
        # shift files: .fail.4 -> .fail.5, ... then write .fail.1
        for i in range(keep - 1, 0, -1):
            src = prefix.with_suffix(f".fail.{i}.log")
            dst = prefix.with_suffix(f".fail.{i+1}.log")
            if src.exists():
                try:
                    src.replace(dst)
                except Exception:
                    try:
                        shutil.copy2(src, dst)
                        src.unlink()
                    except Exception:
                        pass
        target = prefix.with_suffix(".fail.1.log")
        target.write_text(content, encoding="utf-8")
        return str(target)
    except Exception:
        try:
            fallback = prefix.with_suffix(".fail.tmp.log")
            fallback.write_text(content, encoding="utf-8")
            return str(fallback)
        except Exception:
            return ""

# parse simple metadata from top-of-file comments (YAML-ish or key: value lines)
def _parse_hook_meta(path: Path) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return meta
    # read first 20 lines for metadata block
    lines = txt.splitlines()[:40]
    for l in lines:
        s = l.strip()
        if not s:
            continue
        if s.startswith("#"):
            s = s.lstrip("#").strip()
            if ":" in s:
                k, v = s.split(":", 1)
                k = k.strip().lower()
                v = v.strip()
                # basic conversions
                if v.lower() in ("true", "yes", "1"):
                    vv = True
                elif v.lower() in ("false", "no", "0"):
                    vv = False
                else:
                    # try json parse
                    try:
                        vv = json.loads(v)
                    except Exception:
                        vv = v
                meta[k] = vv
            continue
        else:
            # stop reading once non-comment line encountered
            break
    # support legacy 'requires' value as comma separated
    if "requires" in meta and isinstance(meta["requires"], str):
        meta["requires"] = [x.strip() for x in meta["requires"].split(",") if x.strip()]
    return meta

# ------------------------------------------------------------------------------------
# Hooks manager
# ------------------------------------------------------------------------------------
class HooksManager:
    """
    Discover and run hooks. Designed to be resilient and integrated with newpkg_api.
    """

    def __init__(self, cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None):
        # API integration
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

        # config + components
        self.cfg = cfg or (self.api.cfg if self.api and getattr(self.api, "cfg", None) else (get_config() if get_config else None))
        self.logger = logger or (self.api.logger if self.api and getattr(self.api, "logger", None) else (get_logger(self.cfg) if get_logger else None))
        self.db = db or (self.api.db if self.api and getattr(self.api, "db", None) else (get_db() if get_db else None))
        self.sandbox = (self.api.sandbox if self.api and getattr(self.api, "sandbox", None) else (get_sandbox(self.cfg) if get_sandbox else None)) if get_sandbox else None

        # register
        try:
            if self.api:
                self.api.hooks = self
        except Exception:
            pass

        # hook discovery config
        self.hooks_dir = Path(os.environ.get("NEWPKG_HOOKS_DIR", DEFAULT_HOOKS_DIR))
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.hooks_dir = Path(self.cfg.get("hooks.dir") or str(self.hooks_dir))
        except Exception:
            pass

        # cache config
        self.cache_ttl = DEFAULT_CACHE_TTL
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.cache_ttl = int(self.cfg.get("hooks.cache_ttl") or self.cache_ttl)
        except Exception:
            pass

        self.fail_log_keep = DEFAULT_FAIL_LOG_KEEP
        try:
            if self.cfg and hasattr(self.cfg, "get"):
                self.fail_log_keep = int(self.cfg.get("hooks.fail_log_keep") or self.fail_log_keep)
        except Exception:
            pass

        # in-memory discovery cache
        self._cache_lock = threading.RLock()
        self._cached: Optional[Tuple[float, List[HookEntry]]] = None

        # async threadpool
        self._async_executor = threading.BoundedSemaphore(int(self.cfg.get("hooks.async_max") if (self.cfg and hasattr(self.cfg, "get") and self.cfg.get("hooks.async_max")) else DEFAULT_ASYNC_THREADPOOL))
        self._async_jobs: Dict[str, threading.Thread] = {}
        self._async_results: Dict[str, HookResult] = {}

    # ---------------- discovery ----------------
    def discover_hooks(self, force: bool = False) -> List[HookEntry]:
        """
        Discover executable files in hooks_dir and parse metadata. Cached for TTL unless force=True.
        """
        now = time.time()
        with self._cache_lock:
            if not force and self._cached:
                ts, entries = self._cached
                if now - ts < self.cache_ttl:
                    return entries
            entries: List[HookEntry] = []
            try:
                if not self.hooks_dir.exists():
                    return []
                for child in sorted(self.hooks_dir.iterdir()):
                    if not child.is_file():
                        continue
                    meta = _parse_hook_meta(child)
                    executable = os.access(str(child), os.X_OK)
                    he = HookEntry(name=child.name, path=child, meta=meta, executable=executable)
                    entries.append(he)
            except Exception as e:
                if self.logger:
                    self.logger.warning("hooks.discover.fail", "discovery failed", meta={"error": str(e)})
                else:
                    _logger.warning("discovery failed: %s", e)
            self._cached = (now, entries)
            return entries

    # ---------------- dependency resolution & cycle detection ----------------
    def _build_require_graph(self, entries: List[HookEntry]) -> Tuple[Dict[str, Set[str]], Dict[str, HookEntry]]:
        graph: Dict[str, Set[str]] = {}
        lookup: Dict[str, HookEntry] = {e.name: e for e in entries}
        for e in entries:
            reqs = e.meta.get("requires") or []
            if isinstance(reqs, str):
                reqs = [reqs]
            graph[e.name] = set(reqs)
        return graph, lookup

    def _detect_cycles(self, graph: Dict[str, Set[str]]) -> List[List[str]]:
        """
        Return list of cycles (each cycle is list of node names)
        Uses DFS
        """
        visited: Set[str] = set()
        stack: Set[str] = set()
        cycles: List[List[str]] = []
        path: List[str] = []

        def dfs(node: str):
            if node in stack:
                # cycle found; collect cycle path
                try:
                    idx = path.index(node)
                    cycles.append(path[idx:] + [node])
                except ValueError:
                    cycles.append([node])
                return
            if node in visited:
                return
            visited.add(node)
            stack.add(node)
            path.append(node)
            for nb in graph.get(node, []):
                dfs(nb)
            stack.remove(node)
            path.pop()

        for n in list(graph.keys()):
            dfs(n)
        return cycles

    # ---------------- run single hook ----------------
    def _run_hook_process(self, entry: HookEntry, env: Optional[Dict[str,str]] = None, timeout: Optional[int] = None, sandbox_profile: Optional[str] = None, backend: Optional[str] = None) -> HookResult:
        """
        Execute a hook entry synchronously (process-based). Uses sandbox when requested.
        """
        start = time.time()
        cmd = [str(entry.path)]
        env_clean = _sanitize_env(env)
        # sandbox selection: interpret sandbox_profile: none|light|full
        use_sandbox = False
        sandbox_opts = {}
        if sandbox_profile and sandbox_profile.lower() != "none":
            use_sandbox = True
            if sandbox_profile.lower() == "light":
                sandbox_opts["use_fakeroot"] = False
            elif sandbox_profile.lower() == "full":
                sandbox_opts["use_fakeroot"] = True
        # if entry.meta overrides
        sp = entry.meta.get("sandbox_profile")
        if sp is not None:
            if isinstance(sp, str) and sp.lower() != "none":
                use_sandbox = True
                sandbox_profile = sp
        # do not crash if no sandbox available
        rc = 1
        out = ""
        err = ""
        timed_out = False
        try:
            if use_sandbox and self.sandbox:
                # call sandbox.run_in_sandbox
                timeout_hard = int(timeout) if timeout else None
                res = self.sandbox.run_in_sandbox(cmd, cwd=None, env=env_clean, timeout_hard=timeout_hard, use_fakeroot=(sandbox_opts.get("use_fakeroot", True)))
                rc = res.rc
                out = res.stdout or ""
                err = res.stderr or ""
            else:
                # run directly
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env_clean, text=True)
                try:
                    out, err = proc.communicate(timeout=timeout)
                    rc = proc.returncode or 0
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, err = proc.communicate()
                    rc = 124
                    timed_out = True
        except Exception as e:
            err = f"exception: {e}\n"
            rc = 1
        duration = time.time() - start
        ok = (rc == 0 and not timed_out)
        return HookResult(name=entry.name, ok=ok, rc=rc, duration=duration, stdout=out, stderr=err, async_job=False, timestamp=time.time(), meta=dict(entry.meta))

    # ---------------- async wrapper ----------------
    def _async_wrapper(self, entry: HookEntry, env: Optional[Dict[str,str]], timeout: Optional[int], sandbox_profile: Optional[str], backend: Optional[str]):
        """
        Runs hook in background, stores result in self._async_results
        """
        thread_name = f"hook-async-{entry.name}"
        def _job():
            try:
                res = self._run_hook_process(entry, env=env, timeout=timeout, sandbox_profile=sandbox_profile, backend=backend)
                res.async_job = True
                self._async_results[entry.name] = res
                # DB and logger record
                try:
                    if self.db:
                        self.db.record_phase(entry.name, "hook.async.done", "ok" if res.ok else "fail", meta={"rc": res.rc, "duration": res.duration})
                except Exception:
                    pass
                if not res.ok:
                    _rotate_fail_log(entry.name, f"stderr:\n{res.stderr}\nstdout:\n{res.stdout}", keep=self.fail_log_keep)
                    if self.logger:
                        self.logger.warning("hook.async.fail", f"hook {entry.name} failed async", meta={"rc": res.rc, "duration": res.duration})
            finally:
                # release semaphore
                try:
                    self._async_executor.release()
                except Exception:
                    pass
        t = threading.Thread(target=_job, name=thread_name, daemon=True)
        self._async_jobs[entry.name] = t
        t.start()

    # ---------------- run hooks respecting requires & async ----------------
    def run_hooks(self, only: Optional[Iterable[str]] = None, env: Optional[Dict[str,str]] = None, dry_run: bool = False, sandbox_override: Optional[str] = None, fail_only: bool = False) -> List[HookResult]:
        """
        Run hooks discovered in hooks_dir. If `only` is provided, restrict to that set.
        Returns list of HookResult for synchronous runs; async results are stored in _async_results.
        """
        entries = self.discover_hooks(force=False)
        if only:
            only_set = set(only)
            entries = [e for e in entries if e.name in only_set]

        graph, lookup = self._build_require_graph(entries)
        cycles = self._detect_cycles(graph)
        if cycles:
            # report cycles via logger/db and continue but skip cycles to avoid infinite loops
            msg = {"cycles": cycles}
            if self.logger:
                self.logger.warning("hooks.cycles", "dependency cycles detected", meta=msg)
            if self.db:
                try:
                    self.db.record_phase(None, "hooks.cycles", "warn", meta=msg)
                except Exception:
                    pass

        # topological-ish scheduling: simple Kahn algorithm but skip nodes that are in cycles
        in_deg = {n: 0 for n in graph}
        for n, neigh in graph.items():
            for m in neigh:
                in_deg[m] = in_deg.get(m, 0) + 1
        q = deque([n for n, d in in_deg.items() if d == 0])
        ordered: List[str] = []
        while q:
            n = q.popleft()
            ordered.append(n)
            for m in graph.get(n, []):
                in_deg[m] -= 1
                if in_deg[m] == 0:
                    q.append(m)
        # append remaining nodes (cycles etc.) at end in deterministic order
        for n in sorted(graph.keys()):
            if n not in ordered:
                ordered.append(n)

        results: List[HookResult] = []
        env_clean = _sanitize_env(env)

        for name in ordered:
            entry = lookup.get(name)
            if not entry:
                # missing hook referenced by requires - log and continue
                if self.logger:
                    self.logger.warning("hooks.missing", f"missing hook referenced: {name}", meta={})
                continue
            # check execution flags
            if not entry.executable:
                if self.logger:
                    self.logger.info("hooks.skip_not_exec", f"skipping non-executable: {entry.name}", meta={})
                continue
            # check per-hook filter
            if only and entry.name not in set(only):
                continue
            meta = entry.meta or {}
            async_mode = bool(meta.get("async", False))
            # allow string values like "true" or "yes"
            if isinstance(meta.get("async"), str):
                async_mode = meta.get("async").lower() in ("1", "true", "yes", "y")
            timeout = int(meta.get("timeout")) if meta.get("timeout") else None
            sandbox_profile = sandbox_override or meta.get("sandbox_profile") or None
            backend = meta.get("backend") or None

            # if dry_run: only log planned action
            if dry_run:
                if self.logger:
                    self.logger.info("hook.plan", f"[DRY-RUN] would run hook: {entry.name}", meta={"meta": meta})
                continue

            # run async if requested
            if async_mode:
                # acquire async semaphore
                try:
                    self._async_executor.acquire()
                    try:
                        self._async_wrapper(entry, env_clean, timeout, sandbox_profile, backend)
                        # record pending phase
                        if self.db:
                            try:
                                self.db.record_phase(entry.name, "hook.async.start", "pending", meta={"meta": meta})
                            except Exception:
                                pass
                        if self.logger:
                            self.logger.info("hook.started.async", f"hook {entry.name} started async", meta={"meta": meta})
                    except Exception as e:
                        # if wrapper failed
                        try:
                            self._async_executor.release()
                        except Exception:
                            pass
                        if self.logger:
                            self.logger.error("hook.async.launch.fail", f"failed to launch async hook {entry.name}", meta={"error": str(e)})
                except Exception:
                    # semaphore acquire error: run sync fallback
                    res = self._run_hook_process(entry, env=env_clean, timeout=timeout, sandbox_profile=sandbox_profile, backend=backend)
                    results.append(res)
            else:
                # synchronous execution with perf_timer if available
                try:
                    if self.logger and hasattr(self.logger, "perf_timer"):
                        with self.logger.perf_timer(f"hook.{entry.name}", {"hook": entry.name}):
                            res = self._run_hook_process(entry, env=env_clean, timeout=timeout, sandbox_profile=sandbox_profile, backend=backend)
                    else:
                        res = self._run_hook_process(entry, env=env_clean, timeout=timeout, sandbox_profile=sandbox_profile, backend=backend)
                except Exception as e:
                    res = HookResult(name=entry.name, ok=False, rc=1, duration=0.0, stdout="", stderr=str(e), async_job=False, timestamp=time.time(), meta=dict(entry.meta))
                # store and log
                results.append(res)
                if not res.ok:
                    failpath = _rotate_fail_log(entry.name, f"stderr:\n{res.stderr}\nstdout:\n{res.stdout}", keep=self.fail_log_keep)
                    if self.db:
                        try:
                            self.db.record_phase(entry.name, "hook.fail", "fail", meta={"rc": res.rc, "fail_log": failpath})
                        except Exception:
                            pass
                    if self.logger:
                        self.logger.error("hook.fail", f"hook {entry.name} failed", meta={"rc": res.rc, "log": failpath})
                else:
                    if self.db:
                        try:
                            self.db.record_phase(entry.name, "hook.ok", "ok", meta={"rc": res.rc, "duration": res.duration})
                        except Exception:
                            pass
                    if self.logger:
                        self.logger.info("hook.ok", f"hook {entry.name} succeeded", meta={"duration": res.duration})

        # optionally filter only failures for caller
        if fail_only:
            return [r for r in results if not r.ok]
        return results

    # ---------------- helpers for external callers ----------------
    def run_named(self, names: Iterable[str], **kwargs) -> List[HookResult]:
        return self.run_hooks(only=names, **kwargs)

    def list_hooks(self, force: bool = False) -> List[HookEntry]:
        return self.discover_hooks(force=force)

    def get_async_result(self, name: str) -> Optional[HookResult]:
        return self._async_results.get(name)

# module-level singleton accessor
_default_hooks: Optional[HooksManager] = None
_hooks_lock = threading.RLock()

def get_hooks_manager(cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None) -> HooksManager:
    global _default_hooks
    with _hooks_lock:
        if _default_hooks is None:
            _default_hooks = HooksManager(cfg=cfg, logger=logger, db=db)
        return _default_hooks

# ---------------- CLI interface ----------------
if __name__ == "__main__":
    import argparse, pprint
    p = argparse.ArgumentParser(prog="newpkg-hooks", description="discover and run newpkg hooks")
    p.add_argument("--list", action="store_true", help="list discovered hooks")
    p.add_argument("--run", nargs="*", help="run specified hook(s); if omitted runs all")
    p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    p.add_argument("--sandbox", choices=["none", "light", "full"], help="override sandbox profile for all hooks")
    p.add_argument("--dry-run", action="store_true", help="do not actually run hooks")
    p.add_argument("--fail-only", action="store_true", help="only return failures")
    p.add_argument("--verbose", action="store_true", help="show stdout/stderr for failures")
    args = p.parse_args()

    mgr = get_hooks_manager()
    if args.list:
        entries = mgr.list_hooks()
        if args.json:
            print(json.dumps([{"name": e.name, "path": str(e.path), "meta": e.meta, "exec": e.executable} for e in entries], indent=2, ensure_ascii=False))
        else:
            if RICH:
                table = Table(title="Discovered hooks")
                table.add_column("name")
                table.add_column("path")
                table.add_column("exec")
                table.add_column("meta")
                for e in entries:
                    table.add_row(e.name, str(e.path), "yes" if e.executable else "no", json.dumps(e.meta or {}, ensure_ascii=False))
                _console.print(table)
            else:
                for e in entries:
                    print(f"{e.name}\t{str(e.path)}\texec={e.executable}\tmeta={e.meta}")
        raise SystemExit(0)

    to_run = None
    if args.run is None or len(args.run) == 0:
        to_run = None  # run all
    else:
        to_run = args.run

    res = mgr.run_hooks(only=to_run, dry_run=args.dry_run, sandbox_override=args.sandbox, fail_only=args.fail_only)
    # results may be synchronous results; async ones will be launched but not included
    if args.json:
        # convert dataclasses to json
        out = []
        for r in res:
            if isinstance(r, HookResult):
                out.append(asdict(r))
            else:
                try:
                    out.append(dict(r))
                except Exception:
                    out.append(str(r))
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        # human-friendly
        for r in res:
            prefix = "✅" if r.ok else "❌"
            if RICH:
                _console.print(f"{prefix} {r.name} (rc={r.rc}) {r.duration:.2f}s")
                if (not r.ok and args.verbose) or (args.verbose and r.stdout):
                    _console.print(f"[bold]stdout:[/bold]\n{r.stdout}")
                    _console.print(f"[bold]stderr:[/bold]\n{r.stderr}")
            else:
                print(f"{prefix} {r.name} (rc={r.rc}) {r.duration:.2f}s")
                if (not r.ok and args.verbose) or (args.verbose and r.stdout):
                    print("--- STDOUT ---")
                    print(r.stdout)
                    print("--- STDERR ---")
                    print(r.stderr)

    # notify user about async jobs count
    if mgr._async_jobs:
        if RICH:
            _console.print(f"[yellow]Launched {len(mgr._async_jobs)} async hooks - use get_hooks_manager().get_async_result(name) to check results[/yellow]")
        else:
            print(f"Async hooks launched: {len(mgr._async_jobs)}")
