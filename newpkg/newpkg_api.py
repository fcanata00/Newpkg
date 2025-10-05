#!/usr/bin/env python3
# newpkg_api.py
"""
newpkg_api.py — Auto-discovery and dynamic loading of newpkg modules (plugins)

Principais funções exportadas:
 - load_all_modules(cli, reload=False): descobre e carrega módulos em ./modules ou path do config
 - reload_module(name, cli=None): recarrega módulo específico
 - list_available_modules(path=None): lista arquivos detectáveis
 - get_loaded_modules(): retorna dict com módulos carregados e metadados

Comportamento:
 - procura por arquivos com padrão newpkg_*.py no diretório configurado (core.modules_dir)
 - importa cada arquivo com importlib.util.spec_from_file_location (isolado)
 - se existir função register(cli) no módulo, chama-a (passando a instância do CLI)
 - se não existir register(), mas houver classe cujo nome começa por "Newpkg", tenta instanciá-la
   passando (cfg, logger, db) quando o construtor aceitar esses parâmetros
 - grava cache simples em /var/log/newpkg/cache/modules.json com nomes e mtimes
 - falhas de import/registro são logadas e não abortam o processo
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import os
import sys
import traceback
from dataclasses import dataclass, asdict
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Optional, Tuple

# Optional integrations
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

# fallback stdlib logger (used if newpkg_logger missing)
import logging
_logger = logging.getLogger("newpkg.api")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.api: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


CACHE_DIR_DEFAULT = "/var/log/newpkg/cache"
CACHE_FILE = "modules.json"
MODULE_FILE_PATTERN = "newpkg_*.py"
DEFAULT_MODULES_DIRS = ["./newpkg/modules", "./modules", "/usr/share/newpkg/modules", "/usr/local/lib/newpkg/modules"]

@dataclass
class LoadedModuleInfo:
    name: str  # modulename (without .py)
    path: str  # absolute path
    mtime: float
    module: Optional[ModuleType]
    registered: bool
    registration_info: Optional[Dict[str, Any]] = None

    def to_dict(self):
        d = asdict(self)
        # module object is not serializable
        d.pop("module", None)
        return d


# internal registry of loaded modules (name -> LoadedModuleInfo)
_LOADED_MODULES: Dict[str, LoadedModuleInfo] = {}

# helper to get config/logger/db singletons if available
_DEF_CFG = init_config() if init_config else None
_DEF_LOGGER = None
try:
    if NewpkgLogger and _DEF_CFG:
        _DEF_LOGGER = NewpkgLogger.from_config(_DEF_CFG, NewpkgDB(_DEF_CFG) if NewpkgDB and _DEF_CFG else None)
except Exception:
    _DEF_LOGGER = None
_DEF_DB = NewpkgDB(_DEF_CFG) if NewpkgDB and _DEF_CFG else None


# ----------------- utilities -----------------
def _ensure_cache_dir(cfg: Optional[Any] = None) -> Path:
    try:
        cd = None
        if cfg and hasattr(cfg, "get"):
            cd = cfg.get("core.cache_dir") or cfg.get("core.modules_cache_dir")
        if not cd:
            cd = CACHE_DIR_DEFAULT
        p = Path(os.path.expanduser(cd))
        p.mkdir(parents=True, exist_ok=True)
        return p
    except Exception:
        p = Path(CACHE_DIR_DEFAULT)
        p.mkdir(parents=True, exist_ok=True)
        return p


def _cache_path(cfg: Optional[Any] = None) -> Path:
    return _ensure_cache_dir(cfg) / CACHE_FILE


def _read_cache(cfg: Optional[Any] = None) -> Dict[str, Any]:
    path = _cache_path(cfg)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_cache(data: Dict[str, Any], cfg: Optional[Any] = None) -> None:
    path = _cache_path(cfg)
    try:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        _logger.exception("failed to write modules cache")


def _candidate_module_paths(modules_dir: Optional[str] = None) -> List[Path]:
    paths = []
    # if config provided, prefer it
    if modules_dir:
        p = Path(os.path.expanduser(modules_dir))
        if p.exists():
            paths.append(p)
    # fallback to conventional directories
    for d in DEFAULT_MODULES_DIRS:
        p = Path(os.path.expanduser(d))
        if p.exists():
            paths.append(p)
    # also consider package directory of this file: "modules" next to it
    local = Path(__file__).parent / "modules"
    if local.exists():
        paths.append(local)
    # deduplicate and collect files
    candidates: List[Path] = []
    for base in paths:
        try:
            for f in base.glob("newpkg_*.py"):
                if f.is_file():
                    candidates.append(f.resolve())
        except Exception:
            continue
    return sorted(set(candidates), key=lambda p: str(p))


def _safe_import_module_from_path(path: Path) -> Optional[ModuleType]:
    """
    Import a module from path using importlib.util in a way that isolates name clashes.
    Returns the module object or None on failure.
    """
    try:
        mod_name = f"newpkg_module_{abs(hash(str(path)))}"
        spec = importlib.util.spec_from_file_location(mod_name, str(path))
        if not spec or not spec.loader:
            return None
        mod = importlib.util.module_from_spec(spec)
        # ensure it's importable in sys.modules under the unique name
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)  # type: ignore
        except Exception:
            # remove from sys.modules on exec failure to avoid partial state
            sys.modules.pop(mod_name, None)
            raise
        return mod
    except Exception:
        _logger.debug(f"import failure for {path}:\n{traceback.format_exc()}")
        return None


def _try_call_register(mod: ModuleType, cli: Any, cfg: Optional[Any], logger: Optional[Any], db: Optional[Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    If module exposes register(cli) call it. Returns (called, info)
    """
    try:
        reg = getattr(mod, "register", None)
        if callable(reg):
            # call with cli; module can introspect cli and register commands
            try:
                # prefer providing commonly useful objects if function accepts them
                sig = inspect.signature(reg)
                kwargs = {}
                if "cli" in sig.parameters:
                    kwargs["cli"] = cli
                # allow optional injection of cfg/logger/db
                if "cfg" in sig.parameters:
                    kwargs["cfg"] = cfg
                if "logger" in sig.parameters:
                    kwargs["logger"] = logger
                if "db" in sig.parameters:
                    kwargs["db"] = db
                reg(**kwargs)
            except TypeError:
                # fallback call with just cli
                reg(cli)
            return True, {"type": "register"}
    except Exception:
        _logger.debug("register() failed: " + traceback.format_exc())
    return False, None


def _try_instantiate_newpkg_class(mod: ModuleType, cfg: Optional[Any], logger: Optional[Any], db: Optional[Any]) -> Tuple[bool, Optional[Any]]:
    """
    Look for a class named Newpkg* in module and try to instantiate it.
    Returns (instantiated, instance_or_None)
    """
    try:
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if name.startswith("Newpkg"):
                # try to instantiate with common parameters if constructor permits
                ctor = obj
                try:
                    sig = inspect.signature(ctor)
                    # build kwargs depending on ctor parameters
                    kwargs = {}
                    if "cfg" in sig.parameters:
                        kwargs["cfg"] = cfg
                    if "logger" in sig.parameters:
                        kwargs["logger"] = logger
                    if "db" in sig.parameters:
                        kwargs["db"] = db
                    inst = ctor(**kwargs) if kwargs else ctor()
                except Exception:
                    # try parameterless
                    try:
                        inst = ctor()
                    except Exception:
                        _logger.debug(f"failed to instantiate {name} in {mod}: {traceback.format_exc()}")
                        continue
                return True, inst
    except Exception:
        _logger.debug("instantiate class failed: " + traceback.format_exc())
    return False, None


# ----------------- public API -----------------
def list_available_modules(modules_dir: Optional[str] = None) -> List[str]:
    """
    Retorna a lista de caminhos (strings) dos módulos candidatos detectados.
    """
    paths = _candidate_module_paths(modules_dir)
    return [str(p) for p in paths]


def get_loaded_modules() -> Dict[str, Dict[str, Any]]:
    """
    Retorna um dicionário com informações dos módulos carregados.
    """
    return {name: info.to_dict() for name, info in _LOADED_MODULES.items()}


def load_all_modules(cli: Any, reload: bool = False, cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None, modules_dir: Optional[str] = None) -> List[LoadedModuleInfo]:
    """
    Descobre e carrega automaticamente todos os módulos detectados.
    - cli: instância do NewpkgCLI (passada para register)
    - reload: se True força recarregar módulos mesmo se cache estiver igual
    - cfg/logger/db: objetos opcionais a passar para instanciar classes/register
    - modules_dir: override do diretório de busca (opcional)
    Retorna lista de LoadedModuleInfo.
    """
    cfg = cfg or _DEF_CFG
    logger = logger or _DEF_LOGGER
    db = db or _DEF_DB

    # se auto-load desabilitado via config, sai rapidamente
    try:
        auto = True
        if cfg and hasattr(cfg, "get"):
            auto = bool(cfg.get("core.auto_load_modules", True))
    except Exception:
        auto = True
    if not auto:
        _logger.info("auto module loading disabled in config")
        return list(_LOADED_MODULES.values())

    # scan candidate files
    candidate_paths = _candidate_module_paths(modules_dir or (cfg.get("core.modules_dir") if cfg and hasattr(cfg, "get") else None))
    cache = _read_cache(cfg)
    cache_modules = cache.get("modules", {})
    updated_cache = {}

    loaded_infos: List[LoadedModuleInfo] = []

    for path in candidate_paths:
        try:
            mtime = float(path.stat().st_mtime)
        except Exception:
            mtime = 0.0
        key = str(path)
        prev = cache_modules.get(key)
        # skip if unchanged and not reload and previously loaded
        already_loaded = key in _LOADED_MODULES
        if not reload and prev and prev.get("mtime") == mtime and already_loaded:
            loaded_infos.append(_LOADED_MODULES[key])
            updated_cache[key] = {"mtime": mtime}
            continue

        # attempt import
        mod = _safe_import_module_from_path(path)
        registered = False
        reg_info = None
        inst_info = None

        if not mod:
            _logger.warning(f"failed to import module at {path}")
            updated_cache[key] = {"mtime": mtime, "loaded": False}
            continue

        # try register(cli)
        try:
            called, info = _try_call_register(mod, cli, cfg=cfg, logger=logger, db=db)
            if called:
                registered = True
                reg_info = info or {}
        except Exception:
            _logger.debug("register call exception: " + traceback.format_exc())

        # if not registered, try to instantiate Newpkg* class
        if not registered:
            try:
                instantiated, inst = _try_instantiate_newpkg_class(mod, cfg=cfg, logger=logger, db=db)
                if instantiated:
                    registered = True
                    # if we can, attach instance into cli.modules (best-effort)
                    try:
                        mod_name = inst.__class__.__name__
                        if hasattr(cli, "modules") and isinstance(cli.modules, dict):
                            cli.modules[mod_name] = inst
                    except Exception:
                        pass
                    inst_info = {"class": inst.__class__.__name__}
            except Exception:
                _logger.debug("instantiate attempt failed: " + traceback.format_exc())

        # record loaded module info keyed by path
        lm = LoadedModuleInfo(
            name=path.stem,
            path=str(path),
            mtime=mtime,
            module=mod,
            registered=registered,
            registration_info=reg_info or inst_info,
        )
        _LOADED_MODULES[str(path)] = lm
        loaded_infos.append(lm)
        updated_cache[key] = {"mtime": mtime, "loaded": True, "registered": registered}

        # log success
        if registered:
            _logger.info(f"module loaded & registered: {path.name}")
            try:
                if db and hasattr(db, "record_event"):
                    db.record_event(event="api.module.loaded", ts=int(os.time()) if hasattr(os, "time") else int(__import__("time").time()), meta={"module": path.name})
            except Exception:
                pass
        else:
            _logger.info(f"module imported (no register/inst) : {path.name}")

    # write updated cache
    try:
        _write_cache({"modules": updated_cache, "ts": int(__import__("time").time())}, cfg)
    except Exception:
        pass

    return loaded_infos


def reload_module(module_path: str, cli: Any = None, cfg: Optional[Any] = None, logger: Optional[Any] = None, db: Optional[Any] = None) -> Optional[LoadedModuleInfo]:
    """
    Recarrega um módulo por caminho absoluto (ou relativo). Retorna LoadedModuleInfo ou None.
    """
    try:
        p = Path(module_path).resolve()
        if not p.exists():
            _logger.warning(f"module path not found: {module_path}")
            return None
        # remove previous entry if present
        _LOADED_MODULES.pop(str(p), None)
        # attempt to load again
        loaded = load_all_modules(cli or None, reload=True, cfg=cfg, logger=logger, db=db, modules_dir=str(p.parent))
        # find matching
        for lm in loaded:
            if Path(lm.path).resolve() == p:
                return lm
    except Exception:
        _logger.debug("reload_module failed: " + traceback.format_exc())
    return None
