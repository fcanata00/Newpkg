#!/usr/bin/env python3
# newpkg_config.py
"""
newpkg_config.py — configuration loader & small registry for newpkg

Features / fixes in this revision:
 - Default system config paths include /etc/newpkg/newpkg_config.toml (and fallback names)
 - Robust parsing for TOML (tomllib/toml/tomli), YAML (PyYAML) and JSON
 - Consistent dotted-key get()/set() support (e.g. 'profiles.system.CFLAGS')
 - Safe, well-behaved variable expansion ${VAR} using config values then env vars
 - expand_all() handles nested dicts/lists and joins lists for env-like values
 - as_env() flattens config into NEWPKG_* uppercase env vars; lists joined by ':' by default
 - _expand_cache invalidated on set()
 - validate() is adaptive to expected keys (checks build_root/work_root/destdir)
 - ModuleRegistry.discover() only lists candidates by default (no import side-effects).
   Use load(name, safe=True) to import under control.
 - Logging via Python's logging module (minimal), and safe fallbacks
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# Parsers: prefer stdlib tomllib (py3.11+), fallback to toml/tomli. YAML optional.
try:
    import tomllib as _toml_lib  # Python 3.11
    _TOML_LOADER = "tomllib"
except Exception:
    _toml_lib = None
    _TOML_LOADER = None

if _TOML_LOADER is None:
    try:
        import tomli as _toml_lib  # read-only TOML
        _TOML_LOADER = "tomli"
    except Exception:
        _toml_lib = None
        _TOML_LOADER = None

if _TOML_LOADER is None:
    try:
        import toml as _toml_lib  # third-party toml (read+write)
        _TOML_LOADER = "toml"
    except Exception:
        _toml_lib = None
        _TOML_LOADER = None

try:
    import yaml as _yaml_lib
    _YAML_AVAILABLE = True
except Exception:
    _yaml_lib = None
    _YAML_AVAILABLE = False

# Basic logger for this module; external newpkg_logger can be used by the app
_logger = logging.getLogger("newpkg.config")
if not _logger.handlers:
    # basic default handler (can be reconfigured by the application)
    h = logging.StreamHandler()
    fmt = logging.Formatter("[%(levelname)s] newpkg.config: %(message)s")
    h.setFormatter(fmt)
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)


DEFAULT_FILES = [
    "/etc/newpkg/newpkg_config.toml",
    "/etc/newpkg/config.toml",
    "/etc/newpkg/newpkg_config.yaml",
    "/etc/newpkg/config.yaml",
    os.path.expanduser("~/.config/newpkg/config.toml"),
    os.path.expanduser("~/.config/newpkg/config.yaml"),
]


_RE_VAR = re.compile(r"\$\{([^}]+)\}")


def _deep_get(data: Dict[str, Any], dotted_key: str, default: Any = None) -> Any:
    """Fetch nested dict value using dotted key (a.b.c)."""
    if not dotted_key:
        return default
    parts = dotted_key.split(".")
    cur = data
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def _deep_set(data: Dict[str, Any], dotted_key: str, value: Any):
    """Set nested dict value using dotted key, creating intermediate dicts as needed."""
    parts = dotted_key.split(".")
    cur = data
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


@dataclass
class ModuleRegistry:
    """
    Simple registry for discovered newpkg modules.

    discover() will *list* candidate module names (no import) to avoid side-effects.
    Use load(name, safe=True) to import on demand.
    """
    search_paths: Iterable[str] = field(default_factory=lambda: [""])
    prefix: str = "newpkg_"
    discovered: List[str] = field(default_factory=list)

    def discover(self, package_root: Optional[str] = None) -> List[str]:
        """
        Discover candidate module names by prefix in sys.path and optional package_root.
        This method only returns module names (no import).
        """
        import pkgutil
        self.discovered = []
        # search sys.path and package_root (if given)
        for finder, name, ispkg in pkgutil.iter_modules():
            if name.startswith(self.prefix):
                self.discovered.append(name)
        # also try scanning a provided package_root directory for py files (no import)
        if package_root:
            p = Path(package_root)
            if p.exists() and p.is_dir():
                for f in p.iterdir():
                    if f.is_file() and f.suffix == ".py" and f.stem.startswith(self.prefix):
                        self.discovered.append(f.stem)
        # uniq preserve order
        seen = set()
        out = []
        for n in self.discovered:
            if n not in seen:
                seen.add(n)
                out.append(n)
        self.discovered = out
        return out

    def load(self, module_name: str, safe: bool = True):
        """
        Import the module by name. If safe=True, swallow exceptions and return None on failure.
        """
        try:
            import importlib
            return importlib.import_module(module_name)
        except Exception as e:
            if safe:
                _logger.warning("ModuleRegistry.load: failed to import %s: %s", module_name, e)
                return None
            raise


class ConfigStore:
    """
    ConfigStore: loads configuration from files (TOML/YAML/JSON), merges hierarchy, expands variables.

    Usage:
       cfg = init_config()  # will read system/user defaults
       cfg.get('general.build_root')
       cfg.as_env()
    """

    def __init__(self, sources: Optional[List[Union[str, Path]]] = None, defaults: Optional[Dict[str, Any]] = None):
        self._raw: Dict[str, Any] = {}
        self._sources: List[str] = []
        self._expand_cache: Dict[str, Any] = {}
        self._module_registry = ModuleRegistry()
        if defaults:
            # copy defaults into raw
            self._raw = json.loads(json.dumps(defaults)) if isinstance(defaults, dict) else {}
        self._sources = []
        if sources:
            self.load_files(sources)

    # ---------- file loading ----------
    @staticmethod
    def _read_file(path: Union[str, Path]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        p = Path(path)
        if not p.exists():
            return None, f"missing:{path}"
        try:
            text = p.read_text(encoding="utf-8")
        except Exception as e:
            return None, f"read_error:{path}:{e}"
        # try toml
        if _toml_lib is not None:
            try:
                if _TOML_LOADER in ("tomllib", "tomli"):
                    # tomli/tomllib expect bytes or text only for tomllib
                    parsed = _toml_lib.loads(text)
                else:
                    parsed = _toml_lib.loads(text)
                return parsed, str(path)
            except Exception:
                pass
        # try yaml
        if _YAML_AVAILABLE:
            try:
                parsed = _yaml_lib.safe_load(text)
                if isinstance(parsed, dict):
                    return parsed, str(path)
            except Exception:
                pass
        # try json
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed, str(path)
        except Exception:
            pass
        return None, f"parse_error:{path}"

    def load_files(self, files: Iterable[Union[str, Path]]):
        for f in files:
            p = Path(f)
            parsed, source_tag = self._read_file(p)
            if parsed:
                self._merge(parsed)
                self._sources.append(source_tag or str(p))
                _logger.info("Loaded config from %s", p)
            else:
                _logger.debug("Skipped config %s (%s)", p, source_tag)

    def _merge(self, other: Dict[str, Any]):
        # deep merge (other into self._raw)
        def _rec_merge(a: Dict[str, Any], b: Dict[str, Any]):
            for k, v in b.items():
                if k in a and isinstance(a[k], dict) and isinstance(v, dict):
                    _rec_merge(a[k], v)
                else:
                    a[k] = v
        _rec_merge(self._raw, other)
        # invalidate caches
        self._expand_cache.clear()

    # ---------- accessors ----------
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a config value using dotted notation. e.g. 'profiles.system.CFLAGS'.
        """
        if not key:
            return default
        # direct fetch from cache if expanded fully
        if key in self._expand_cache:
            return self._expand_cache[key]
        # try raw dotted-key
        v = _deep_get(self._raw, key, default)
        return v if v is not None else default

    def set(self, key: str, value: Any):
        """Set dotted-key value and invalidate caches."""
        _deep_set(self._raw, key, value)
        self._expand_cache.clear()

    def items(self) -> Dict[str, Any]:
        return self._raw

    # ---------- expansion ----------
    def _expand_str(self, s: str) -> str:
        """
        Expand ${VAR} occurrences. Try config dotted keys first, then environment.
        If substituted value is list/dict, convert to JSON/string.
        """
        def repl(m):
            key = m.group(1)
            val = self.get(key)
            if val is None:
                val = os.environ.get(key)
            if val is None:
                return ""  # unknown -> empty
            if isinstance(val, (list, tuple)):
                # join lists with ":" for common PATH-like items
                return ":".join(map(str, val))
            if isinstance(val, dict):
                return json.dumps(val)
            return str(val)
        return _RE_VAR.sub(repl, s)

    def expand_all(self):
        """Return a copy of config with all strings expanded."""
        # memoize expansions for performance
        def _expand(obj):
            if isinstance(obj, str):
                return self._expand_str(obj)
            if isinstance(obj, dict):
                out = {}
                for k, v in obj.items():
                    out[k] = _expand(v)
                return out
            if isinstance(obj, list):
                return [_expand(x) for x in obj]
            return obj
        expanded = _expand(self._raw)
        # update cache for top-level dotted keys (flatten)
        def _flatten_assign(prefix: str, obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    _flatten_assign(f"{prefix}.{k}" if prefix else k, v)
            else:
                self._expand_cache[prefix] = obj
        _flatten_assign("", expanded)
        return expanded

    # ---------- environment export ----------
    def as_env(self, prefix: str = "NEWPKG") -> Dict[str, str]:
        """
        Flatten configuration into environment variables.
        Keys are uppercased and joined with underscores:
          e.g. NEWPKG_GENERAL_BUILD_ROOT="/var/tmp/newpkg"
        Lists are joined by ':' by default.
        """
        out: Dict[str, str] = {}

        def _norm_key(parts: List[str]) -> str:
            return ("_".join([p.upper() for p in parts if p != ""]))

        def _walk(obj: Any, path_parts: List[str]):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    _walk(v, path_parts + [k])
            elif isinstance(obj, list):
                # join lists with ':' unless inner items are dicts -> JSON encode list
                if all(not isinstance(i, dict) for i in obj):
                    out_key = f"{prefix}_{_norm_key(path_parts)}"
                    out[out_key] = ":".join(map(str, obj))
                else:
                    out_key = f"{prefix}_{_norm_key(path_parts)}"
                    out[out_key] = json.dumps(obj)
            else:
                out_key = f"{prefix}_{_norm_key(path_parts)}"
                out[out_key] = str(obj) if obj is not None else ""

        _walk(self.expand_all(), [])
        return out

    # ---------- utility ----------
    def get_path(self, key: str, default: Optional[str] = None, expand_user: bool = True) -> Optional[str]:
        v = self.get(key, default)
        if v is None:
            return None
        s = str(v)
        if expand_user:
            s = os.path.expanduser(s)
        return os.path.abspath(self._expand_str(s))

    def sources(self) -> List[str]:
        return list(self._sources)

    # ---------- validation ----------
    def validate(self) -> Tuple[bool, List[str]]:
        """
        Basic validation: ensure essential paths exist or sensible defaults.
        Returns (ok, errors).
        """
        errs: List[str] = []
        # check for presence of build root/work_root/destdir at least one naming variant
        build_root = self.get("general.build_root") or self.get("general.work_root") or self.get("build_root") or self.get("work_root")
        if not build_root:
            errs.append("missing: general.build_root or general.work_root (set build_root/work_root)")
        destdir = self.get("general.destdir") or self.get("destdir")
        if not destdir:
            errs.append("missing: general.destdir (set destdir)")
        # more semantic checks
        use_sandbox = self.get("general.use_sandbox")
        if use_sandbox is not None and not isinstance(use_sandbox, bool):
            errs.append("general.use_sandbox must be true/false")
        ok = len(errs) == 0
        return ok, errs

    # ---------- convenience / persistence ----------
    def save(self, path: Union[str, Path]):
        p = Path(path)
        # write as JSON for safety; user-managed config files should be authoritative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self._raw, indent=2), encoding="utf-8")
        _logger.info("Saved config to %s", p)

    # ---------- small registry helper ----------
    @property
    def module_registry(self) -> ModuleRegistry:
        return self._module_registry


# ---------- top-level convenience ----------
def init_config(paths: Optional[Iterable[str]] = None, defaults: Optional[Dict[str, Any]] = None, strict: bool = False) -> ConfigStore:
    """
    Create & return a ConfigStore loaded from default system/user paths unless `paths` provided.
    If strict=True, raise RuntimeError when validate() fails.
    """
    sources = list(paths) if paths else DEFAULT_FILES
    cfg = ConfigStore(defaults=defaults)
    cfg.load_files(sources)
    ok, errs = cfg.validate()
    if not ok:
        _logger.warning("Config validation warnings: %s", errs)
        if strict:
            raise RuntimeError(f"Configuration validation failed: {errs}")
    return cfg


# If this module executed directly, demonstrate loading defaults (non-invasive)
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="newpkg_config debug")
    p.add_argument("--list-sources", action="store_true", help="print loaded sources")
    p.add_argument("--dump-env", action="store_true", help="print flattened env")
    p.add_argument("--strict", action="store_true", help="strict validation (raise on errors)")
    args = p.parse_args()
    cfg = init_config(strict=args.strict)
    if args.list_sources:
        print("Sources:", cfg.sources())
    if args.dump_env:
        env = cfg.as_env()
        for k, v in env.items():
            print(k, "=", v)
