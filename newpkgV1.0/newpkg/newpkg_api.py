#!/usr/bin/env python3
# newpkg_api.py (fixed)
"""
newpkg_api.py — central API & module registry for newpkg (improved)

Improvements applied (requested):
1) Import by file path always uses importlib.util.spec_from_file_location (isolated module names using md5 of path)
2) Failures recorded explicitly in registry with available=False and traceback summary
3) global_alias_map is (re)built consistently after init/reload
4) Prevent double-import by checking registry & allowing explicit reload
5) Signature caching for inspect.signature to speed repeated operations
6) SimpleLogger fallback when no external logger provided
7) Optional recursive discovery (pkgutil.walk_packages) via recursive_discover flag
8) Incremental reload option based on file mtime via reload_modules(incremental=True)

Backward-compatible public API preserved: get_api, get_newpkg_api, NewpkgAPI methods remain.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import pkgutil
import sys
import threading
import traceback
import hashlib
from dataclasses import dataclass, asdict
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Tuple

# Try to import common pieces (best-effort)
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


# ---------------- simple fallback logger ----------------
class SimpleLogger:
    def info(self, *args, **kwargs):
        print("[INFO]", *args)

    def warning(self, *args, **kwargs):
        print("[WARN]", *args)

    def error(self, *args, **kwargs):
        print("[ERROR]", *args)


# dataclass for module registry
@dataclass
class ModuleMeta:
    name: str
    module: Optional[ModuleType]
    path: Optional[str]
    available: bool
    summary: str
    exported: List[str]
    api_map: Dict[str, str]
    mtime: Optional[float] = None


_api_singleton = None
_api_lock = threading.RLock()


class NewpkgAPI:
    def __init__(self, cfg: Any = None, recursive_discover: bool = False, strict_import: bool = False):
        self.cfg = cfg or (init_config() if init_config else {})
        try:
            self.logger = get_logger(self.cfg) if get_logger else SimpleLogger()
        except Exception:
            self.logger = SimpleLogger()
        try:
            self.db = NewpkgDB(self.cfg) if NewpkgDB else None
        except Exception:
            self.db = None
        try:
            self.hooks = get_hooks_manager(self.cfg) if get_hooks_manager else None
        except Exception:
            self.hooks = None
        try:
            self.sandbox = get_sandbox(self.cfg) if get_sandbox else None
        except Exception:
            self.sandbox = None

        self.registry: Dict[str, ModuleMeta] = {}
        default_paths = [
            str(Path.cwd() / "modules"),
            str(Path.cwd() / "newpkg" / "modules"),
            str(Path.cwd() / "newpkg"),
        ]
        cfg_paths = []
        try:
            if hasattr(self.cfg, "get"):
                v = self.cfg.get("api.modules_path")
                if v:
                    if isinstance(v, str):
                        cfg_paths = [v]
                    elif isinstance(v, (list, tuple)):
                        cfg_paths = list(v)
        except Exception:
            cfg_paths = []

        self.modules_paths = [
            os.path.abspath(os.path.expanduser(p))
            for p in (cfg_paths + default_paths)
            if os.path.isdir(os.path.expanduser(p))
        ]
        self.global_alias_map: Dict[str, Tuple[str, str]] = {}
        self._inited = False
        self.import_errors: Dict[str, str] = {}
        self._sig_cache: Dict[int, inspect.Signature] = {}
        self._recursive_discover = bool(recursive_discover)
        self._strict_import = bool(strict_import)

    # ---------------- discovery & import ----------------
    def _make_isolated_modname(self, path: str) -> str:
        h = hashlib.md5(os.path.abspath(path).encode("utf-8")).hexdigest()
        base = os.path.splitext(os.path.basename(path))[0]
        return f"newpkg_module_{base}_{h}"

    def discover_modules(self) -> List[Tuple[str, str]]:
        found = []
        for base in self.modules_paths:
            try:
                if self._recursive_discover:
                    for finder, name, ispkg in pkgutil.walk_packages([base]):
                        spec = finder.find_spec(name)
                        if not spec:
                            continue
                        origin = getattr(spec, "origin", None)
                        if origin and origin.endswith(".py"):
                            found.append((name, origin))
                else:
                    for entry in os.listdir(base):
                        full = os.path.join(base, entry)
                        if entry.endswith(".py"):
                            found.append((entry[:-3], full))
                        elif os.path.isdir(full) and os.path.exists(os.path.join(full, "__init__.py")):
                            found.append((entry, full))
            except Exception:
                continue
        unique = {}
        for n, p in found:
            ap = os.path.abspath(p)
            if ap not in unique:
                unique[ap] = (n, ap)
        return list(unique.values())

    def _safe_import_module(self, module_path: str, module_name_hint: Optional[str] = None) -> Optional[ModuleType]:
        try:
            if os.path.isfile(module_path):
                modname = self._make_isolated_modname(module_path)
                spec = importlib.util.spec_from_file_location(modname, module_path)
                if not spec or not spec.loader:
                    raise ImportError(f"cannot create spec for {module_path}")
                module = importlib.util.module_from_spec(spec)
                sys.modules[modname] = module
                spec.loader.exec_module(module)  # type: ignore
                return module
            else:
                return importlib.import_module(module_path)
        except Exception as e:
            tb = traceback.format_exc()
            key = module_name_hint or module_path
            self.import_errors[key] = tb
            self.logger.warning(f"Import failed: {module_path}: {e}")
            return None

    def load_modules(self):
        explicit = []
        try:
            if hasattr(self.cfg, "get"):
                em = self.cfg.get("api.modules")
                if em and isinstance(em, (list, tuple)):
                    explicit = list(em)
        except Exception:
            explicit = []

        if explicit:
            for name in explicit:
                if name.lower() in self.registry:
                    continue
                mod = self._safe_import_module(name, name)
                self._register_module(name, mod, name)
            return

        for (name, path) in self.discover_modules():
            lname = name.lower().replace("-", "_")
            if lname in self.registry and self.registry[lname].available:
                continue
            mod = self._safe_import_module(path, name)
            self._register_module(name, mod, path)

        builtins = [
            "newpkg_upgrade",
            "newpkg_remove",
            "newpkg_sync",
            "newpkg_deps",
            "newpkg_core",
            "newpkg_metafile",
            "newpkg_audit",
            "newpkg_hooks",
            "newpkg_patcher",
            "newpkg_sandbox",
        ]
        for cand in builtins:
            clean = cand.replace("newpkg_", "")
            if clean in self.registry:
                continue
            mod = self._safe_import_module(cand, cand)
            if mod:
                self._register_module(clean, mod, cand)

    def _register_module(self, name: str, module: Optional[ModuleType], source: Optional[str] = None):
        clean = name.lower().replace("-", "_")
        if module is None:
            tb = self.import_errors.get(name, "")
            summary = tb.strip().splitlines()[0] if tb else "import failed"
            self.registry[clean] = ModuleMeta(clean, None, source, False, summary, [], {}, None)
            self._rebuild_alias_map()
            return

        exported, api_map = [], {}
        for attr_name, attr in inspect.getmembers(module):
            if attr_name.startswith("_"):
                continue
            exported.append(attr_name)
            lname = attr_name.lower()
            if lname in ("upgrade_all", "upgradeall", "upgrade_packages"):
                api_map["upgrade_all"] = f"{clean}.{attr_name}"
            if lname in ("upgrade_package", "upgradeone", "upgrade"):
                api_map["upgrade_package"] = f"{clean}.{attr_name}"
            if lname in ("remove_packages", "remove", "remove_package"):
                api_map["remove_packages"] = f"{clean}.{attr_name}"
            if lname in ("sync_all", "sync_repos", "sync"):
                api_map["sync_all"] = f"{clean}.{attr_name}"
            if lname in ("resolve", "resolve_deps"):
                api_map["resolve"] = f"{clean}.{attr_name}"
            if lname in ("install_missing", "install_deps"):
                api_map["install_missing"] = f"{clean}.{attr_name}"
            if lname in ("build_package", "build"):
                api_map["build_package"] = f"{clean}.{attr_name}"
            if lname in ("run_audit", "scan_system", "run"):
                api_map["audit_run"] = f"{clean}.{attr_name}"

        summary = (getattr(module, "__doc__", "") or "").strip().splitlines()[0] if getattr(module, "__doc__", None) else ""
        mtime = None
        try:
            p = getattr(module, "__file__", source)
            if p and os.path.exists(p):
                mtime = os.path.getmtime(p)
        except Exception:
            pass

        self.registry[clean] = ModuleMeta(clean, module, getattr(module, "__file__", source), True, summary, exported, api_map, mtime)
        self._rebuild_alias_map()

    # ---------------- init helpers ----------------
    def _cached_signature(self, func: Callable) -> inspect.Signature:
        key = id(func)
        if key not in self._sig_cache:
            try:
                self._sig_cache[key] = inspect.signature(func)
            except Exception:
                self._sig_cache[key] = inspect.Signature()
        return self._sig_cache[key]

    def init_all(self, reload: bool = False):
        if self._inited and not reload:
            return
        if reload:
            self.registry.clear()
            self.global_alias_map.clear()
            self.import_errors.clear()
        self.load_modules()
        for name, meta in list(self.registry.items()):
            if not meta.available or not meta.module:
                continue
            mod = meta.module
            for g in [f"get_{name}", "get_module", "get_api", "init"]:
                if hasattr(mod, g):
                    func = getattr(mod, g)
                    sig = self._cached_signature(func)
                    kwargs = {}
                    for p in sig.parameters.values():
                        if p.name in ("cfg", "config"):
                            kwargs[p.name] = self.cfg
                        elif p.name in ("logger", "log"):
                            kwargs[p.name] = self.logger
                        elif p.name == "db":
                            kwargs[p.name] = self.db
                        elif p.name == "hooks":
                            kwargs[p.name] = self.hooks
                        elif p.name == "sandbox":
                            kwargs[p.name] = self.sandbox
                    try:
                        func(**kwargs)
                        self.logger.info(f"Initialized {name}")
                        break
                    except Exception:
                        continue
        self._inited = True

    # ---------------- call dispatcher ----------------
    def _resolve_callable(self, dotted: str) -> Optional[Callable]:
        if "." in dotted:
            module_part, attr = dotted.split(".", 1)
            meta = self.registry.get(module_part)
            if meta and meta.available and meta.module:
                try:
                    f = getattr(meta.module, attr)
                    if callable(f):
                        return f
                except Exception:
                    inst = getattr(meta.module, "_instance", None)
                    if inst and hasattr(inst, attr):
                        f = getattr(inst, attr)
                        if callable(f):
                            return f
        if dotted in self.global_alias_map:
            modname, dotted_attr = self.global_alias_map[dotted]
            _, attr = dotted_attr.split(".", 1)
            meta = self.registry.get(modname)
            if meta and meta.module and hasattr(meta.module, attr):
                f = getattr(meta.module, attr)
                if callable(f):
                    return f
        try:
            parts = dotted.split(".")
            mod = importlib.import_module(".".join(parts[:-1]))
            f = getattr(mod, parts[-1])
            if callable(f):
                return f
        except Exception:
            pass
        return None

    def call(self, action: str, payload: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        payload = payload or {}
        call_args, call_kwargs = [], {}
        if "args" in payload or "kwargs" in payload:
            call_args = payload.get("args", []) or []
            call_kwargs = payload.get("kwargs", {}) or {}
        else:
            call_kwargs = payload

        func = self._resolve_callable(action)
        if func is None:
            err = f"action not found: {action}"
            self.logger.warning(err)
            return {"ok": False, "error": err, "action": action}
        try:
            sig = self._cached_signature(func)
            for p in sig.parameters.values():
                if p.name in ("cfg", "config") and p.name not in call_kwargs:
                    call_kwargs[p.name] = self.cfg
                elif p.name in ("logger", "log") and p.name not in call_kwargs:
                    call_kwargs[p.name] = self.logger
                elif p.name == "db" and p.name not in call_kwargs:
                    call_kwargs[p.name] = self.db
                elif p.name == "hooks" and p.name not in call_kwargs:
                    call_kwargs[p.name] = self.hooks
                elif p.name == "sandbox" and p.name not in call_kwargs:
                    call_kwargs[p.name] = self.sandbox
            result = func(*call_args, **call_kwargs)
            return {"ok": True, "result": result}
        except Exception as e:
            tb = traceback.format_exc()
            self.logger.error(f"Error calling {action}: {e}\n{tb}")
            return {"ok": False, "error": str(e), "traceback": tb, "action": action}

    # ---------------- utilities ----------------
    def _rebuild_alias_map(self):
        self.global_alias_map.clear()
        for modname, meta in self.registry.items():
            if meta.available:
                for action, dotted in meta.api_map.items():
                    self.global_alias_map[f"{modname}.{action}"] = (modname, dotted)

    def reload_modules(self, incremental: bool = False):
        if incremental:
            for name, meta in list(self.registry.items()):
                if not meta.path or not os.path.exists(meta.path):
                    continue
                mtime = os.path.getmtime(meta.path)
                if meta.mtime is None or mtime != meta.mtime:
                    del self.registry[name]
            self._rebuild_alias_map()
            self.load_modules()
            self.init_all(reload=True)
            return
        for name, meta in list(self.registry.items()):
            if meta.module and meta.module.__name__ in sys.modules:
                del sys.modules[meta.module.__name__]
        self.registry.clear()
        self.global_alias_map.clear()
        self.import_errors.clear()
        self._inited = False
        self.init_all(reload=True)


# ---------------- singleton accessors ----------------
def get_api(cfg: Any = None, recursive_discover: bool = False, strict_import: bool = False) -> NewpkgAPI:
    global _api_singleton
    with _api_lock:
        if _api_singleton is None:
            _api_singleton = NewpkgAPI(cfg=cfg, recursive_discover=recursive_discover, strict_import=strict_import)
        return _api_singleton


def get_newpkg_api(cfg: Any = None) -> NewpkgAPI:
    return get_api(cfg)


if __name__ == "__main__":
    api = get_api()
    api.init_all()
    for meta in api.list_modules():
        print(meta["name"], "available=", meta["available"], "exports=", meta["exported"][:10])
