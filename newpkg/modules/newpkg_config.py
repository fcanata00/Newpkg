#!/usr/bin/env python3
# newpkg_config.py
"""
newpkg_config.py — configuration manager for newpkg

Features:
 - Loads configuration from JSON/TOML/YAML (auto-detect if libraries are available)
 - Respects NEWPKG_CONFIG_PATH environment variable (single path or colon-separated list)
 - Supports dotted keys for get/set and basic list indexing (a.b[0].c)
 - Profile support: load_profile(name) merges profiles.<name> onto main config
 - Variable expansion ${VAR} with recursion limit to avoid infinite loops
 - as_env() to export configuration as environment variables (safe truncation)
 - Atomic save (temp file + os.replace)
 - Optional integration with newpkg_logger and newpkg_api (module discovery delegation)
 - Basic validation with optional auto_fix (creates directories when applicable)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import time
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# Optional libs
try:
    import toml as _toml_lib  # type: ignore
except Exception:
    _toml_lib = None

try:
    import yaml as _yaml_lib  # type: ignore
except Exception:
    _yaml_lib = None

# Optional integrations
try:
    from newpkg_logger import NewpkgLogger
except Exception:
    NewpkgLogger = None

# Optional delegation to newpkg_api for module discovery (import lazily to avoid cycles)
# newpkg_api may live in parent package; import inside method

# Fallback stdlib logger (used only if newpkg_logger missing)
import logging
_logger = logging.getLogger("newpkg.config")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] newpkg.config: %(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)

# Constants
ENV_CONFIG_PATH = "NEWPKG_CONFIG_PATH"
DEFAULT_CONFIG_FILES = [
    "/etc/newpkg/newpkg.toml",
    "/etc/newpkg/newpkg.yaml",
    "/etc/newpkg/newpkg.json",
    str(Path.home() / ".config" / "newpkg" / "newpkg.toml"),
    str(Path.cwd() / "newpkg.toml"),
]
CACHE_DIR = "/var/log/newpkg/cache"
CACHE_FILE = "config_hash.json"
MAX_EXPAND_DEPTH = 10
MAX_ENV_VALUE_LEN = 16_384  # truncate huge values for env safety

# Regex for ${VAR} expansion
_RE_VAR = re.compile(r"\$\{([^}]+)\}")

# Helper types
ConfigDict = Dict[str, Any]


@dataclass
class Config:
    """
    Config object that holds loaded configuration and offers helper APIs.
    """
    _raw: ConfigDict = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)
    profile_active: Optional[str] = None
    _cache_path: Path = field(default=Path(CACHE_DIR) / CACHE_FILE)

    # logger (optional integration)
    _logger: Any = field(default=None, repr=False)

    def __post_init__(self):
        # prefer newpkg_logger if available
        if NewpkgLogger and self._logger is None:
            try:
                self._logger = NewpkgLogger.from_config(self, None)
            except Exception:
                self._logger = None
        if self._logger is None:
            self._logger = _logger

    # ----------------- loading -----------------
    @classmethod
    def load_any(cls, paths: Optional[Iterable[str]] = None) -> "Config":
        """
        Load first existing config file among provided `paths` or fallback defaults.
        `paths` may be a list, or if None, will read from ENV NEWPKG_CONFIG_PATH then DEFAULT_CONFIG_FILES.
        If multiple paths specified in NEWPKG_CONFIG_PATH (colon-separated), they will be merged in order.
        """
        cfg = cls()
        sources = []

        # build search list
        if paths:
            candidates = list(paths)
        else:
            env_paths = os.environ.get(ENV_CONFIG_PATH)
            if env_paths:
                candidates = env_paths.split(":")
            else:
                candidates = DEFAULT_CONFIG_FILES

        for p in candidates:
            if not p:
                continue
            path = Path(p).expanduser()
            if path.exists():
                try:
                    loaded = cls._read_file(path)
                    cfg._raw = cls._deep_merge(cfg._raw, loaded)
                    sources.append(str(path))
                except Exception as e:
                    cfg._log("warning", "config.load.fail", f"Failed to parse config {path}: {e}", path=str(path), error=str(e))
                    continue

        cfg.sources = sources
        if not sources:
            cfg._log("info", "config.load.empty", "No config file found; using defaults")
        return cfg

    @staticmethod
    def _read_file(path: Path) -> ConfigDict:
        """
        Read JSON/TOML/YAML based on extension or auto-detect.
        """
        text = path.read_text(encoding="utf-8")
        suffix = path.suffix.lower()
        if suffix in (".toml",) and _toml_lib:
            return _toml_lib.loads(text)
        if suffix in (".yaml", ".yml") and _yaml_lib:
            return _yaml_lib.safe_load(text) or {}
        if suffix in (".json",):
            return json.loads(text)
        # try auto-detect: JSON -> TOML -> YAML
        # try JSON
        try:
            return json.loads(text)
        except Exception:
            pass
        if _toml_lib:
            try:
                return _toml_lib.loads(text)
            except Exception:
                pass
        if _yaml_lib:
            try:
                return _yaml_lib.safe_load(text) or {}
            except Exception:
                pass
        # fallback: try to eval as simple JSON-ish
        try:
            return json.loads(text)
        except Exception:
            raise ValueError(f"Unsupported config format or parse error for {path}")

    # ----------------- getters / setters -----------------
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get dotted key, supports list index like a.b[0].c partially.
        """
        if not key:
            return deepcopy(self._raw) if self._raw else default
        parts = self._split_key(key)
        cur: Any = self._raw
        try:
            for part in parts:
                if isinstance(cur, list) and isinstance(part, int):
                    cur = cur[part]
                elif isinstance(cur, dict):
                    cur = cur.get(part)
                else:
                    return default
            return deepcopy(cur)
        except Exception:
            return default

    def set(self, key: str, value: Any) -> None:
        parts = self._split_key(key)
        cur = self._raw
        for i, part in enumerate(parts):
            last = (i == len(parts) - 1)
            if isinstance(part, int):
                # ensure cur is list
                if not isinstance(cur, list):
                    raise TypeError(f"Cannot set index on non-list for part {part} (key={key})")
                while len(cur) <= part:
                    cur.append({})
                if last:
                    cur[part] = value
                else:
                    cur = cur[part]
            else:
                if last:
                    cur[part] = value
                else:
                    if part not in cur or not isinstance(cur[part], (dict, list)):
                        cur[part] = {}
                    cur = cur[part]

    def has(self, key: str) -> bool:
        return self.get(key, None) is not None

    # ----------------- key helpers -----------------
    @staticmethod
    def _split_key(key: str) -> List[Union[str, int]]:
        """
        Splits a dotted key into parts, support for indices like 'a.b[0].c'
        Example: "profiles.system.packages[2].name" -> ["profiles","system","packages",2,"name"]
        """
        parts: List[Union[str, int]] = []
        # simple parser
        token = ""
        i = 0
        while i < len(key):
            ch = key[i]
            if ch == ".":
                if token:
                    parts.append(token)
                    token = ""
                i += 1
                continue
            if ch == "[":
                if token:
                    parts.append(token)
                    token = ""
                j = key.find("]", i + 1)
                if j == -1:
                    raise ValueError("Malformed key: missing ']'")
                idx_str = key[i + 1:j]
                try:
                    idx = int(idx_str)
                except Exception:
                    raise ValueError("Only integer indices supported in keys")
                parts.append(idx)
                i = j + 1
                continue
            token += ch
            i += 1
        if token:
            parts.append(token)
        return parts

    # ----------------- variable expansion -----------------
    def expand_all(self, commit: bool = False, max_depth: int = MAX_EXPAND_DEPTH) -> Dict[str, Any]:
        """
        Expand ${VAR} occurrences across the config values into resolved strings.
        If commit=True, modifies self._raw in-place; otherwise returns expanded copy.
        Prevents infinite recursion by max_depth.
        """
        def expand_value(v, depth):
            if depth <= 0:
                return v
            if isinstance(v, str):
                return self._expand_str(v, depth)
            if isinstance(v, dict):
                return {k: expand_value(val, depth) for k, val in v.items()}
            if isinstance(v, list):
                return [expand_value(x, depth) for x in v]
            return v

        expanded = expand_value(deepcopy(self._raw), max_depth)
        if commit:
            self._raw = expanded
        return expanded

    def _expand_str(self, s: str, depth: int) -> str:
        # safe expansion using env, config keys, and fallback to empty string
        def repl(m):
            name = m.group(1)
            # prefer environment variables first
            if name in os.environ:
                return os.environ.get(name, "")
            # then config keys (dotted)
            val = self.get(name, None)
            if val is None:
                return ""
            if isinstance(val, (dict, list)):
                try:
                    return json.dumps(val, ensure_ascii=False)
                except Exception:
                    return ""
            return str(val)
        prev = s
        for _ in range(depth):
            new = _RE_VAR.sub(repl, prev)
            if new == prev:
                return new
            prev = new
        # depth exhausted; return current best
        return prev

    # ----------------- as_env -----------------
    def as_env(self, prefix: str = "NEWPKG_", include: Optional[Iterable[str]] = None, exclude: Optional[Iterable[str]] = None) -> Dict[str, str]:
        """
        Build an environment mapping from configuration.
        - prefix: prefix for env var names (default NEWPKG_)
        - include/exclude: optional lists of dotted keys to include/exclude
        Complex structures (dict/list) are JSON-encoded.
        Large strings are truncated for safety (MAX_ENV_VALUE_LEN).
        """
        env: Dict[str, str] = {}
        # flatten dictionary
        flat = self._flatten(self._raw)
        inc = set(include) if include else None
        exc = set(exclude) if exclude else set()
        for dotted, val in flat.items():
            if inc is not None and dotted not in inc:
                continue
            if dotted in exc:
                continue
            key = prefix + dotted.upper().replace(".", "_")
            try:
                if isinstance(val, (dict, list)):
                    v = json.dumps(val, ensure_ascii=False)
                else:
                    v = str(val) if val is not None else ""
                if len(v) > MAX_ENV_VALUE_LEN:
                    v = v[:MAX_ENV_VALUE_LEN]
                env[key] = v
            except Exception:
                env[key] = ""
        return env

    @staticmethod
    def _flatten(d: Dict[str, Any], parent: str = "") -> Dict[str, Any]:
        items: Dict[str, Any] = {}
        for k, v in d.items():
            new_key = f"{parent}.{k}" if parent else k
            if isinstance(v, dict):
                items.update(Config._flatten(v, new_key))
            else:
                items[new_key] = v
        return items

    # ----------------- save / atomic -----------------
    def save(self, path: Optional[Union[str, Path]] = None, format: Optional[str] = None) -> Path:
        """
        Save config to path (atomic). If path is None, uses first source or defaults to ~/.config/newpkg/newpkg.json
        format: "json" | "toml" | "yaml" - defaults to inferred from path or json fallback.
        Returns path saved.
        """
        if path is None:
            target = Path.home() / ".config" / "newpkg" / "newpkg.json"
            target.parent.mkdir(parents=True, exist_ok=True)
        else:
            target = Path(path).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True)

        if format is None:
            suffix = target.suffix.lower()
            if suffix in (".toml",):
                format = "toml"
            elif suffix in (".yaml", ".yml"):
                format = "yaml"
            else:
                format = "json"

        # produce text
        text = ""
        if format == "toml" and _toml_lib:
            text = _toml_lib.dumps(self._raw)
        elif format in ("yaml", "yml") and _yaml_lib:
            text = _yaml_lib.safe_dump(self._raw)
        else:
            # default json
            text = json.dumps(self._raw, indent=2, ensure_ascii=False)

        # atomic write: tmp -> replace
        fd, tmp_path = tempfile.mkstemp(prefix="newpkg_cfg_", dir=str(target.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(tmp_path, str(target))
            self._log("info", "config.save.ok", f"Saved config to {target}", path=str(target))
            return target
        except Exception as e:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            self._log("error", "config.save.fail", f"Failed saving config: {e}", error=str(e))
            raise

    # ----------------- merge / profiles -----------------
    @staticmethod
    def _deep_merge(a: ConfigDict, b: ConfigDict) -> ConfigDict:
        """
        Deep merge b into a and return result (a not modified).
        Arrays are replaced by default.
        """
        res = deepcopy(a)
        for k, v in b.items():
            if k in res and isinstance(res[k], dict) and isinstance(v, dict):
                res[k] = Config._deep_merge(res[k], v)
            else:
                res[k] = deepcopy(v)
        return res

    def load_profile(self, name: str, commit: bool = True) -> None:
        """
        Merge profiles.<name> onto the main config and set profile_active.
        """
        profiles = self.get("profiles", {})
        if not isinstance(profiles, dict) or name not in profiles:
            self._log("warning", "config.profile.missing", f"Profile {name} not found")
            return
        profile_data = profiles[name] or {}
        merged = self._deep_merge(self._raw, profile_data)
        if commit:
            self._raw = merged
            self.profile_active = name

    # ----------------- validation -----------------
    def validate(self, auto_fix: bool = False) -> Tuple[bool, List[str]]:
        """
        Validate common config keys; returns (ok, list_of_issues).
        If auto_fix=True, create directories that are missing (build_root, cache_dir, report_dir).
        """
        issues: List[str] = []
        # Example required dirs
        dir_keys = [
            "core.build_root",
            "core.root_dir",
            "core.modules_dir",
            "cli.report_dir",
            "core.cache_dir",
        ]
        for k in dir_keys:
            v = self.get(k, None)
            if not v:
                issues.append(f"missing: {k}")
                continue
            try:
                p = Path(v).expanduser()
                if not p.exists():
                    issues.append(f"not_found: {v}")
                    if auto_fix:
                        try:
                            p.mkdir(parents=True, exist_ok=True)
                            issues.append(f"created: {v}")
                        except Exception as e:
                            issues.append(f"cannot_create: {v} ({e})")
            except Exception as e:
                issues.append(f"invalid_path: {k} -> {e}")

        # logger level check
        log_lvl = self.get("logger.level", None) or self.get("output.log_level", None)
        if log_lvl and str(log_lvl).lower() not in ("debug", "info", "warning", "error", "critical"):
            issues.append(f"invalid_logger_level: {log_lvl}")

        ok = len([i for i in issues if not i.startswith("created:")]) == 0
        return ok, issues

    # ----------------- module registry delegation -----------------
    def list_modules(self) -> List[str]:
        """
        Return available modules. Attempt delegation to newpkg_api if available;
        fallback to ModuleRegistry inside config (if present).
        """
        try:
            # dynamic import to avoid circular
            sys.path.append(str(Path(__file__).resolve().parent))
            from newpkg_api import list_available_modules  # type: ignore
            paths = list_available_modules(self.get("core.modules_dir", None))
            # convert to stem names
            return [Path(p).stem for p in paths]
        except Exception:
            # fallback: check modules dir(s)
            modules_dir = self.get("core.modules_dir", None)
            search_dirs = []
            if modules_dir:
                search_dirs.append(Path(modules_dir).expanduser())
            # add default module dirs
            search_dirs.extend([
                Path(__file__).resolve().parent / "modules",
                Path.cwd() / "modules",
                Path("/usr/share/newpkg/modules"),
                Path("/usr/local/lib/newpkg/modules"),
            ])
            found = []
            for d in search_dirs:
                try:
                    if d.exists():
                        for f in d.glob("newpkg_*.py"):
                            found.append(f.stem)
                except Exception:
                    continue
            return sorted(set(found))

    # ----------------- utility -----------------
    def _flatten_for_debug(self) -> Dict[str, Any]:
        return self._flatten(self._raw)

    # logging wrapper to use newpkg_logger if present
    def _log(self, level: str, event: str, msg: str = "", **meta) -> None:
        """
        level: 'info','warning','error','debug'
        """
        try:
            if self._logger:
                fn = getattr(self._logger, level.lower(), None)
                if fn:
                    fn(event, msg, **meta)
                    return
        except Exception:
            pass
        getattr(_logger, level.lower(), _logger.info)(f"{event}: {msg} - {meta}")


# ----------------- singleton initializer -----------------
_CONFIG_SINGLETON: Optional[Config] = None


def init_config(paths: Optional[Iterable[str]] = None, reload: bool = False) -> Config:
    """
    Initialize or return the global Config singleton.
    Optionally take `paths` iterable (list of config paths), or fall back to environment/defaults.
    Set reload=True to force reloading from files.
    """
    global _CONFIG_SINGLETON
    if _CONFIG_SINGLETON is None or reload:
        cfg = Config.load_any(paths)
        # set sensible defaults if missing
        defaults = {
            "core": {
                "build_root": "/tmp/newpkg-build",
                "root_dir": "/",
                "modules_dir": str(Path(__file__).resolve().parent / "modules"),
                "cache_dir": CACHE_DIR,
            },
            "cli": {
                "report_dir": "/var/log/newpkg/cli",
            },
            "output": {
                "quiet": False,
                "json": False,
                "use_rich": True,
            },
            "general": {
                "dry_run": False,
                "use_sandbox": True,
            }
        }
        cfg._raw = Config._deep_merge(defaults, cfg._raw)
        _CONFIG_SINGLETON = cfg
    return _CONFIG_SINGLETON


# ----------------- convenience helpers -----------------
def get_config() -> Config:
    return init_config()


# ----------------- simple command-line tester -----------------
if __name__ == "__main__":
    cfg = init_config()
    print("Sources:", cfg.sources)
    print("Active profile:", cfg.profile_active)
    print("Modules available:", cfg.list_modules())
    ok, issues = cfg.validate(auto_fix=False)
    print("Validate OK:", ok)
    if issues:
        print("Issues:")
        for it in issues:
            print(" -", it)
