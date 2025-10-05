#!/usr/bin/env python3
# newpkg_api.py
"""
newpkg_api.py — central API & module registry for newpkg

Responsabilidades:
 - descobrir e carregar módulos em modules/ (ou path configurado)
 - inicializar singletons compartilhados: config, logger, db, hooks, sandbox
 - manter registry de módulos com metadados
 - expor API: call(command, payload), get_module(name), list_modules(), init_all(), reload_modules()
 - detectar automaticamente funções públicas úteis em cada módulo e mapear aliases
 - degradar graciosamente quando um módulo falta ou falha na importação

Uso:
    from newpkg_api import get_api
    api = get_api()
    api.init_all()  # optional (lazy init will call it)
    api.call("upgrade.upgrade_all", {"packages": ["gcc"]})
    m = api.get_module("upgrade")
    mods = api.list_modules()
"""

from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import sys
import threading
import traceback
from dataclasses import dataclass, asdict
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Tuple

# Try to import common pieces (best-effort). Modules may or may not exist.
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

# dataclasses for registry
@dataclass
class ModuleMeta:
    name: str
    module: Optional[ModuleType]
    path: Optional[str]
    available: bool
    summary: str
    exported: List[str]
    api_map: Dict[str, str]  # action -> attribute path (module.attr)

# singleton holder
_api_singleton = None
_api_lock = threading.RLock()

class NewpkgAPI:
    def __init__(self, cfg: Any = None):
        # config: try central init_config or env defaults
        self.cfg = cfg or (init_config() if init_config else {})
        # logger singleton (best-effort)
        try:
            self.logger = get_logger(self.cfg) if get_logger else None
        except Exception:
            self.logger = None
        # db/hook/sandbox singletons (best-effort)
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

        # registry: name -> ModuleMeta
        self.registry: Dict[str, ModuleMeta] = {}
        # module search paths (configurable): list of directories
        default_paths = [
            str(Path.cwd() / "modules"),
            str(Path.cwd() / "newpkg" / "modules"),
            str(Path.cwd() / "newpkg"),
        ]
        cfg_paths = []
        try:
            # allow config to provide modules path list under api.modules_path
            if hasattr(self.cfg, "get"):
                v = self.cfg.get("api.modules_path")
                if v:
                    if isinstance(v, str):
                        cfg_paths = [v]
                    elif isinstance(v, (list, tuple)):
                        cfg_paths = list(v)
        except Exception:
            cfg_paths = []
        self.modules_paths = [p for p in (cfg_paths + default_paths) if p]
        # ensure unique and existing
        seen = []
        cleaned = []
        for p in self.modules_paths:
            pnorm = os.path.abspath(os.path.expanduser(p))
            if pnorm not in seen and os.path.isdir(pnorm):
                seen.append(pnorm)
                cleaned.append(pnorm)
        self.modules_paths = cleaned

        # map of simple aliases -> (module_name, attribute)
        self.global_alias_map: Dict[str, Tuple[str, str]] = {}
        # whether init_all() was executed
        self._inited = False
        # debug: store import errors
        self.import_errors: Dict[str, str] = {}

    # ---------------- logging helpers ----------------
    def _log_info(self, key: str, msg: str, **meta):
        if self.logger and hasattr(self.logger, "info"):
            try:
                self.logger.info(key, msg, **meta)
                return
            except Exception:
                pass
        # fallback
        try:
            print(f"[INFO] {key}: {msg}")
        except Exception:
            pass

    def _log_warn(self, key: str, msg: str, **meta):
        if self.logger and hasattr(self.logger, "warning"):
            try:
                self.logger.warning(key, msg, **meta)
                return
            except Exception:
                pass
        try:
            print(f"[WARN] {key}: {msg}")
        except Exception:
            pass

    def _log_error(self, key: str, msg: str, **meta):
        if self.logger and hasattr(self.logger, "error"):
            try:
                self.logger.error(key, msg, **meta)
                return
            except Exception:
                pass
        try:
            print(f"[ERROR] {key}: {msg}")
        except Exception:
            pass

    # ---------------- discovery & import ----------------
    def discover_modules(self) -> List[Tuple[str, str]]:
        """
        Scan configured module directories for candidate module names.
        Returns list of tuples (module_name, file_path).
        """
        found = []
        for base in self.modules_paths:
            try:
                for entry in os.listdir(base):
                    if entry.endswith(".py"):
                        name = entry[:-3]
                        path = os.path.join(base, entry)
                        found.append((name, path))
                    elif os.path.isdir(os.path.join(base, entry)) and os.path.exists(os.path.join(base, entry, "__init__.py")):
                        name = entry
                        path = os.path.join(base, entry)
                        found.append((name, path))
            except Exception:
                continue
        return found

    def _safe_import_module(self, module_path: str, module_name_hint: Optional[str] = None) -> Optional[ModuleType]:
        """
        Import a module by filepath or module name (best-effort).
        Returns module or None and logs import errors.
        """
        try:
            # if it's a path
            if os.path.isfile(module_path):
                # prepare a module name unique
                base = os.path.basename(module_path)
                modname = (module_name_hint or base.replace(".py", "")).replace("-", "_")
                # add directory to sys.path temporarily
                d = os.path.dirname(os.path.abspath(module_path))
                if d not in sys.path:
                    sys.path.insert(0, d)
                try:
                    m = importlib.import_module(modname)
                    return m
                except Exception:
                    # fallback: use importlib.machinery.SourceFileLoader
                    spec = importlib.util.spec_from_file_location(modname, module_path)
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)  # type: ignore
                        return mod
                    return None
            else:
                # try import by dotted name
                mod = importlib.import_module(module_path)
                return mod
        except Exception as e:
            tb = traceback.format_exc()
            key = module_name_hint or module_path
            self.import_errors[key] = tb
            self._log_warn("api.import_fail", f"failed to import {module_path}: {e}")
            return None

    def load_modules(self):
        """
        Discover and attempt to import modules found in modules_paths.
        For each successfully imported module, try to initialize and register metadata.
        """
        # allow explicit whitelist from config: api.modules (list of module names)
        explicit = []
        try:
            if hasattr(self.cfg, "get"):
                em = self.cfg.get("api.modules")
                if em and isinstance(em, (list, tuple)):
                    explicit = list(em)
        except Exception:
            explicit = []

        # first try explicit names (preferred)
        if explicit:
            for name in explicit:
                try:
                    mod = self._safe_import_module(name, module_name_hint=name)
                    self._register_module(name, mod, source="explicit")
                except Exception:
                    continue
            # done with explicit list
            return

        # else discover
        discovered = self.discover_modules()
        for (name, path) in discovered:
            try:
                mod = self._safe_import_module(path, module_name_hint=name)
                self._register_module(name, mod, source=path)
            except Exception:
                continue

        # Additionally, attempt to import top-level newpkg.* modules if present (fallback)
        builtin_candidates = ["newpkg_upgrade", "newpkg_remove", "newpkg_sync", "newpkg_deps", "newpkg_core", "newpkg_metafile", "newpkg_audit", "newpkg_hooks", "newpkg_patcher", "newpkg_sandbox"]
        for cand in builtin_candidates:
            if cand in self.registry:
                continue
            try:
                mod = self._safe_import_module(cand, module_name_hint=cand)
                if mod:
                    self._register_module(cand.replace("newpkg_", ""), mod, source=cand)
            except Exception:
                continue

    def _register_module(self, name: str, module: Optional[ModuleType], source: Optional[str] = None):
        """
        Inspect module to create ModuleMeta and register it under a cleaned name.
        Detect exported callable names and map common aliases.
        """
        clean_name = name.lower().replace("-", "_")
        if module is None:
            # register as unavailable
            meta = ModuleMeta(
                name=clean_name,
                module=None,
                path=source,
                available=False,
                summary="import failed",
                exported=[],
                api_map={}
            )
            self.registry[clean_name] = meta
            return

        exported = []
        api_map = {}
        # list all callables and attrs
        try:
            for attr_name, attr in inspect.getmembers(module):
                # skip private
                if attr_name.startswith("_"):
                    continue
                exported.append(attr_name)
                # map common functions to simple actions
                lname = attr_name.lower()
                # mapping heuristics
                if lname in ("upgrade_all", "upgradeall", "upgrade_packages"):
                    api_map["upgrade_all"] = f"{clean_name}.{attr_name}"
                if lname in ("upgrade_package", "upgradeone", "upgrade"):
                    api_map["upgrade_package"] = f"{clean_name}.{attr_name}"
                if lname in ("remove_packages", "remove", "remove_package"):
                    api_map["remove_packages"] = f"{clean_name}.{attr_name}"
                if lname in ("sync_all", "sync_repos", "sync"):
                    api_map["sync_all"] = f"{clean_name}.{attr_name}"
                if lname in ("resolve", "resolve_deps"):
                    api_map["resolve"] = f"{clean_name}.{attr_name}"
                if lname in ("install_missing", "install_deps"):
                    api_map["install_missing"] = f"{clean_name}.{attr_name}"
                if lname in ("build_package", "build"):
                    api_map["build_package"] = f"{clean_name}.{attr_name}"
                if lname in ("package_and_install", "package_and_install"):
                    api_map["package_and_install"] = f"{clean_name}.{attr_name}"
                if lname in ("run_audit", "scan_system", "run"):
                    api_map["audit_run"] = f"{clean_name}.{attr_name}"
                if lname in ("get", "get_module"):
                    api_map[attr_name] = f"{clean_name}.{attr_name}"
            # also include module docstring as summary
            summary = (getattr(module, "__doc__", "") or "").strip().splitlines()[0] if getattr(module, "__doc__", None) else ""
        except Exception:
            exported = []
            api_map = {}
            summary = ""

        meta = ModuleMeta(
            name=clean_name,
            module=module,
            path=getattr(module, "__file__", source),
            available=True,
            summary=summary or f"module {clean_name}",
            exported=exported,
            api_map=api_map
        )
        self.registry[clean_name] = meta

        # populate global alias map for convenient calls (e.g., "upgrade.upgrade_all")
        for action, dotted in api_map.items():
            alias = f"{clean_name}.{action}"
            # store dotted mapping
            self.global_alias_map[alias] = (clean_name, api_map[action])

    # ---------------- init helpers ----------------
    def init_all(self, reload: bool = False):
        """
        Discover, import, and initialize all modules (best-effort).
        If reload=True, clears registry and re-imports.
        """
        if self._inited and not reload:
            return
        if reload:
            self.registry.clear()
            self.global_alias_map.clear()
            self.import_errors.clear()
        # discover and load
        self.load_modules()
        # attempt to initialize modules that expose get_* or init constructors
        for name, meta in list(self.registry.items()):
            if not meta.available or meta.module is None:
                continue
            try:
                module = meta.module
                # try common patterns: get_<name>(), get_<module>(), or init(cfg, logger, db, hooks, sandbox)
                got = False
                getter_names = [f"get_{name}", f"get_{meta.name}", "get_module", "get_api"]
                for g in getter_names:
                    if hasattr(module, g):
                        try:
                            func = getattr(module, g)
                            # call with available singletons if signature accepts them
                            sig = inspect.signature(func)
                            kwargs = {}
                            for p in sig.parameters.values():
                                if p.name in ("cfg", "config"):
                                    kwargs[p.name] = self.cfg
                                elif p.name in ("logger", "log"):
                                    kwargs[p.name] = self.logger
                                elif p.name in ("db",):
                                    kwargs[p.name] = self.db
                                elif p.name in ("hooks",):
                                    kwargs[p.name] = self.hooks
                                elif p.name in ("sandbox",):
                                    kwargs[p.name] = self.sandbox
                            try:
                                instance = func(**kwargs) if kwargs else func()
                                # if it returns an object, try to attach it to module for convenience (best-effort)
                                if instance:
                                    # attach to meta.module._instance if desirable
                                    setattr(module, "_instance", instance)
                                got = True
                                break
                            except Exception:
                                # ignore and continue best-effort
                                pass
                        except Exception:
                            continue
                if not got and hasattr(module, "init"):
                    try:
                        init_fn = getattr(module, "init")
                        # attempt to call init(cfg, logger, db, hooks, sandbox)
                        sig = inspect.signature(init_fn)
                        kwargs = {}
                        for p in sig.parameters.values():
                            if p.name in ("cfg", "config"):
                                kwargs[p.name] = self.cfg
                            elif p.name in ("logger", "log"):
                                kwargs[p.name] = self.logger
                            elif p.name in ("db",):
                                kwargs[p.name] = self.db
                            elif p.name in ("hooks",):
                                kwargs[p.name] = self.hooks
                            elif p.name in ("sandbox",):
                                kwargs[p.name] = self.sandbox
                        try:
                            init_fn(**kwargs)
                            got = True
                        except Exception:
                            pass
                    except Exception:
                        pass
                # record that module was initialized (best-effort)
                if got:
                    self._log_info("api.module_init", f"initialized module {name}", module=name)
            except Exception:
                self._log_warn("api.module_init_fail", f"failed to init module {name}", module=name)

        self._inited = True

    # ---------------- module accessors ----------------
    def get_module(self, name: str) -> Optional[ModuleMeta]:
        return self.registry.get(name.lower())

    def list_modules(self) -> List[Dict[str, Any]]:
        return [asdict(m) for m in self.registry.values()]

    # ---------------- call dispatcher ----------------
    def _resolve_callable(self, dotted: str) -> Optional[Callable]:
        """
        Resolve a dotted string like "upgrade.upgrade_all" to a callable.
        Accept forms:
            - "module.action" (both known)
            - "action" if global_alias_map maps it
            - "module:attr" or full dotted module path
        """
        if "." in dotted:
            module_part, attr = dotted.split(".", 1)
            meta = self.registry.get(module_part)
            if meta and meta.available and meta.module:
                try:
                    func = getattr(meta.module, attr)
                    if callable(func):
                        return func
                except Exception:
                    # maybe the module exported instance at _instance with method attr
                    inst = getattr(meta.module, "_instance", None)
                    if inst and hasattr(inst, attr):
                        f = getattr(inst, attr)
                        if callable(f):
                            return f
        # check global alias map
        if dotted in self.global_alias_map:
            modname, dotted_attr = self.global_alias_map[dotted]
            # dotted_attr looks like "modname.attr"
            if "." in dotted_attr:
                _, attr = dotted_attr.split(".", 1)
                meta = self.registry.get(modname)
                if meta and meta.module and hasattr(meta.module, attr):
                    f = getattr(meta.module, attr)
                    if callable(f):
                        return f
        # try direct import dotted path
        try:
            parts = dotted.split(".")
            modpath = ".".join(parts[:-1])
            attr = parts[-1]
            mod = importlib.import_module(modpath)
            if hasattr(mod, attr):
                f = getattr(mod, attr)
                if callable(f):
                    return f
        except Exception:
            pass
        return None

    def call(self, action: str, payload: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Call an action. action can be:
          - "module.action" (preferred)
          - "action" if mapped in aliases
          - dotted module path "pkg.submodule.func"
        payload is dict of keyword args or {'args': [...], 'kwargs': {...}}.
        Returns standardized dict: {'ok': bool, 'result': any, 'error': str}
        """
        payload = payload or {}
        # prepare call args
        call_args = []
        call_kwargs = {}
        if isinstance(payload, dict) and ("args" in payload or "kwargs" in payload):
            call_args = payload.get("args", []) or []
            call_kwargs = payload.get("kwargs", {}) or {}
        elif isinstance(payload, dict):
            call_kwargs = payload

        func = self._resolve_callable(action)
        if func is None:
            # try 'module.action' where action contains slash? support alias
            if action in self.global_alias_map:
                modname, dotted = self.global_alias_map[action]
                func = self._resolve_callable(f"{modname}.{dotted.split('.')[-1]}")
        if func is None:
            err = f"action not found: {action}"
            self._log_warn("api.call_not_found", err)
            return {"ok": False, "error": err, "action": action}

        # call with best-effort injection of common singletons (cfg, logger, db, hooks, sandbox)
        try:
            sig = inspect.signature(func)
            # prepare kwargs injection for parameters named cfg/config/logger/db/hooks/sandbox
            injected = {}
            for p in sig.parameters.values():
                if p.name in ("cfg", "config") and p.name not in call_kwargs:
                    injected[p.name] = self.cfg
                elif p.name in ("logger", "log") and p.name not in call_kwargs:
                    injected[p.name] = self.logger
                elif p.name == "db" and p.name not in call_kwargs:
                    injected[p.name] = self.db
                elif p.name == "hooks" and p.name not in call_kwargs:
                    injected[p.name] = self.hooks
                elif p.name == "sandbox" and p.name not in call_kwargs:
                    injected[p.name] = self.sandbox
            # merge injected into call_kwargs without overwriting user-supplied
            for k, v in injected.items():
                if k not in call_kwargs:
                    call_kwargs[k] = v
            # invoke
            result = func(*call_args, **call_kwargs)
            return {"ok": True, "result": result}
        except Exception as e:
            tb = traceback.format_exc()
            self._log_error("api.call_exception", f"exception calling {action}: {e}", traceback=tb)
            return {"ok": False, "error": str(e), "traceback": tb, "action": action}

    # ---------------- utilities ----------------
    def reload_modules(self):
        """Clear cache and reload modules from disk."""
        # attempt to remove modules we've imported that came from modules_paths
        for name, meta in list(self.registry.items()):
            if meta.path and meta.path.endswith(".py"):
                modname = None
                try:
                    if meta.module:
                        modname = meta.module.__name__
                        if modname in sys.modules:
                            del sys.modules[modname]
                except Exception:
                    pass
        self.registry.clear()
        self.global_alias_map.clear()
        self.import_errors.clear()
        self._inited = False
        self.init_all(reload=True)

# ---------------- convenience singleton accessor ----------------
def get_api(cfg: Any = None) -> NewpkgAPI:
    global _api_singleton
    with _api_lock:
        if _api_singleton is None:
            _api_singleton = NewpkgAPI(cfg=cfg)
        return _api_singleton

# backward-compatible alias
def get_newpkg_api(cfg: Any = None) -> NewpkgAPI:
    return get_api(cfg)

# small CLI for debugging discovery
def _debug_list_modules():
    api = get_api()
    api.init_all()
    for meta in api.list_modules():
        print(meta.get("name"), "available=", meta.get("available"), "exports=", meta.get("exported")[:10])

if __name__ == "__main__":
    _debug_list_modules()
