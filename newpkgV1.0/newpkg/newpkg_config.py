#!/usr/bin/env python3
# newpkg_config.py
"""
Central configuration loader for newpkg.

Features:
 - Load JSON/TOML/YAML (best-effort) and ENV overrides
 - Support `include = [file1, file2]` with recursive merge (includes overridden by main)
 - Profiles support (profiles.<name>) and automatic activation of `cli.default_profile`
 - Expose `to_dict(expanded=True)` and `as_env()` helpers
 - `reload()` to re-read files and reapply profile
 - `dump_debug()` to return sanitized debug info (hides secrets)
 - Cache config hash (SHA256) to avoid unnecessary reloads
 - Register config instance with newpkg_api (if available)
 - Sanitize sensitive keys in exports (password/token/secret/ssh_key)
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import threading
import typing
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Optional parsers
try:
    import tomllib  # Python 3.11+
except Exception:
    tomllib = None

try:
    import toml as _toml  # type: ignore
except Exception:
    _toml = None

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# Optional integration points (best-effort)
try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

try:
    from newpkg_api import get_api  # type: ignore
except Exception:
    get_api = None

# Thread-safe singleton
_config_singleton = None
_config_lock = threading.RLock()

# Keys considered sensitive (will be redacted in dumps/as_env unless explicit allow)
DEFAULT_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey", "ssh_key", "private_key"}

# Utility functions
def _read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()

def _file_exists(path: str) -> bool:
    try:
        return pathlib.Path(path).expanduser().exists()
    except Exception:
        return False

def _normalize_path(p: str) -> str:
    try:
        return os.path.abspath(os.path.expanduser(p))
    except Exception:
        return p

def _merge_dict(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge override into base. Values in override take precedence.
    For lists, override replaces the base list.
    """
    out = deepcopy(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge_dict(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out

def _detect_format_and_parse(path: str) -> Optional[Dict[str, Any]]:
    """
    Try to detect and parse JSON/TOML/YAML. Returns dict or None.
    """
    try:
        raw = _read_file_bytes(path)
    except Exception:
        return None
    # try tomllib (py311) if file extension .toml or content looks like toml
    suffix = pathlib.Path(path).suffix.lower()
    if suffix in (".toml",) and tomllib:
        try:
            return tomllib.loads(raw.decode("utf-8"))
        except Exception:
            pass
    if suffix in (".toml",) and _toml:
        try:
            return _toml.loads(raw.decode("utf-8"))
        except Exception:
            pass
    # json
    if suffix in (".json",):
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            pass
    # yaml
    if suffix in (".yml", ".yaml") and yaml:
        try:
            return yaml.safe_load(raw.decode("utf-8"))
        except Exception:
            pass
    # Heuristic tries
    txt = raw.decode("utf-8", errors="ignore").strip()
    # JSON likely starts with { or [
    if txt.startswith("{") or txt.startswith("["):
        try:
            return json.loads(txt)
        except Exception:
            pass
    # TOML heuristic: contains '=' on lines
    if "=" in txt and "\n" in txt and (tomllib or _toml):
        try:
            if tomllib:
                return tomllib.loads(txt)
            if _toml:
                return _toml.loads(txt)
        except Exception:
            pass
    # YAML fallback
    if yaml:
        try:
            return yaml.safe_load(txt)
        except Exception:
            pass
    # last resort: attempt JSON
    try:
        return json.loads(txt)
    except Exception:
        return None

def _expand_vars_in_value(value: Any, env: Dict[str, str]) -> Any:
    """
    Expand ${VAR} and $VAR references inside strings recursively.
    """
    if isinstance(value, str):
        out = value
        # simple loop to support nested references
        for _ in range(5):
            # replace ${VAR} and $VAR
            try:
                out_new = os.path.expandvars(out)
                # also substitute using provided env
                for k, v in env.items():
                    out_new = out_new.replace("${" + k + "}", v).replace("$" + k, v)
                if out_new == out:
                    break
                out = out_new
            except Exception:
                break
        return out
    elif isinstance(value, dict):
        return {k: _expand_vars_in_value(v, env) for k, v in value.items()}
    elif isinstance(value, list):
        return [_expand_vars_in_value(v, env) for v in value]
    else:
        return value

def _deep_walk_and_redact(d: Any, sensitive: set) -> Any:
    """
    Return a copy of structure with sensitive keys redacted.
    """
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            if any(sk in k.lower() for sk in sensitive):
                out[k] = "<REDACTED>"
            else:
                out[k] = _deep_walk_and_redact(v, sensitive)
        return out
    elif isinstance(d, list):
        return [_deep_walk_and_redact(x, sensitive) for x in d]
    else:
        return d

class NewpkgConfig:
    """
    Main configuration object.
    """

    def __init__(self, paths: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None, sensitive_keys: Optional[List[str]] = None):
        # list of config files (primary first). If None, search defaults.
        self.paths = [ _normalize_path(p) for p in (paths or []) ]
        # env mapping used for expansion (defaults to os.environ)
        self.env = env or dict(os.environ)
        # sensitive keys set
        self.sensitive_keys = set([k.lower() for k in (sensitive_keys or [])]) | set(DEFAULT_SENSITIVE_KEYS)
        # loaded merged config
        self._config: Dict[str, Any] = {}
        # last computed expanded config
        self._expanded_cache: Optional[Dict[str, Any]] = None
        # file hash to detect changes
        self._hash_cache: Optional[str] = None
        # logger
        try:
            self.logger = get_logger(self) if get_logger else None
        except Exception:
            self.logger = None
        # detect default config locations if none provided
        if not self.paths:
            self.paths = self._default_search_paths()
        # internal: loaded include chain to avoid cycles
        self._loaded_files: List[str] = []
        # active profile
        self.active_profile: Optional[str] = None
        # load immediately
        self.reload()
        # auto-activate default profile from config if present
        dp = self.get("cli.default_profile")
        if dp:
            try:
                self.activate_profile(dp)
            except Exception:
                pass
        # register into newpkg_api if present
        try:
            api = get_api() if get_api else None
            if api:
                try:
                    # attach this config instance to api.cfg for other modules
                    api.cfg = self
                    if self.logger:
                        self.logger.info("config.register", f"registered config with newpkg_api")
                except Exception:
                    pass
        except Exception:
            pass

    def _default_search_paths(self) -> List[str]:
        """
        Return reasonable default config files in order of precedence:
         - $PWD/newpkg.toml
         - /etc/newpkg.conf(.toml/.json/.yaml)
         - ~/.config/newpkg/config.toml
        """
        candidates = []
        cwd = os.getcwd()
        candidates.append(os.path.join(cwd, "newpkg.toml"))
        etc1 = "/etc/newpkg.toml"
        etc2 = "/etc/newpkg/config.toml"
        candidates.extend([etc1, etc2])
        home = os.path.expanduser("~/.config/newpkg/config.toml")
        candidates.append(home)
        return [p for p in candidates if _file_exists(p)]

    # ---------------- load/merge logic ----------------
    def reload(self, force: bool = False) -> None:
        """
        Reload configuration from files. If force=False, uses cached hash to avoid reloading unchanged files.
        """
        # reset loaded file chain
        self._loaded_files = []
        # gather files that exist from self.paths
        files = [p for p in self.paths if _file_exists(p)]
        if not files:
            # nothing to load -> empty config
            self._config = {}
            self._expanded_cache = None
            self._hash_cache = None
            return

        # compute combined hash of files
        try:
            hasher = hashlib.sha256()
            for f in files:
                try:
                    hasher.update(_read_file_bytes(f))
                except Exception:
                    continue
            new_hash = hasher.hexdigest()
        except Exception:
            new_hash = None

        if not force and new_hash and new_hash == self._hash_cache:
            # nothing changed
            return

        merged: Dict[str, Any] = {}
        for f in files:
            loaded = self._load_with_includes(f, seen=set())
            if loaded:
                merged = _merge_dict(merged, loaded)

        self._config = merged
        self._expanded_cache = None
        self._hash_cache = new_hash
        # apply profile if one is set in config cli.default_profile
        try:
            dp = self.get("cli.default_profile")
            if dp:
                self.activate_profile(dp)
        except Exception:
            pass

        if self.logger:
            try:
                self.logger.info("config.reload", f"loaded config from {files}")
            except Exception:
                pass

    def _load_with_includes(self, path: str, seen: set) -> Optional[Dict[str, Any]]:
        """
        Load a config file and recursively process its `include` key if present.
        Includes are evaluated and merged such that entries in the including file override included ones.
        Prevent cycles using 'seen' set.
        """
        path = _normalize_path(path)
        if path in seen:
            return {}
        seen.add(path)
        parsed = _detect_format_and_parse(path)
        if not parsed:
            return {}
        # handle includes: supports include: [file1, file2] or include: file1
        includes = parsed.get("include") or parsed.get("includes")
        included_merged: Dict[str, Any] = {}
        if includes:
            if isinstance(includes, str):
                includes = [includes]
            for inc in includes:
                inc_path = _normalize_path(inc)
                if not _file_exists(inc_path):
                    # try relative to current file directory
                    alt = os.path.join(os.path.dirname(path), inc)
                    if _file_exists(alt):
                        inc_path = alt
                if _file_exists(inc_path):
                    try:
                        sub = self._load_with_includes(inc_path, seen)
                        if sub:
                            included_merged = _merge_dict(included_merged, sub)
                        # log include
                        if self.logger:
                            try:
                                self.logger.info("config.include.load", f"merged include {inc_path}", path=inc_path)
                            except Exception:
                                pass
                    except Exception:
                        continue
        # merge included first, then parsed (so parsed overrides included)
        merged = _merge_dict(included_merged, parsed)
        # record loaded file
        self._loaded_files.append(path)
        return merged

    # ---------------- accessors ----------------
    def get(self, key: str, default: Any = None) -> Any:
        """
        Dot-separated key access, e.g. get("audit.jobs", 4)
        """
        parts = key.split(".")
        cur = self._config
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return default
        return cur

    def set(self, key: str, value: Any) -> None:
        """
        Set a dot-separated key in runtime (in-memory only).
        """
        parts = key.split(".")
        cur = self._config
        for p in parts[:-1]:
            if p not in cur or not isinstance(cur[p], dict):
                cur[p] = {}
            cur = cur[p]
        cur[parts[-1]] = value
        # invalidate expanded cache
        self._expanded_cache = None

    def activate_profile(self, profile_name: str) -> None:
        """
        Apply settings from profiles.<profile_name> onto the main config.
        Profile entries override base config.
        """
        profiles = self._config.get("profiles") or {}
        if not isinstance(profiles, dict):
            return
        prof = profiles.get(profile_name)
        if not prof or not isinstance(prof, dict):
            # nothing to apply
            return
        # merge current config with profile (profile overrides)
        base = deepcopy(self._config)
        merged = _merge_dict(base, prof)
        # ensure profiles key remains as is
        merged["profiles"] = self._config.get("profiles", {})
        self._config = merged
        self.active_profile = profile_name
        self._expanded_cache = None
        if self.logger:
            try:
                self.logger.info("config.profile.activate", f"activated profile {profile_name}")
            except Exception:
                pass

    def to_dict(self, expanded: bool = True) -> Dict[str, Any]:
        """
        Return config as dictionary. If expanded=True, variables like ${VAR} are expanded using provided env.
        """
        if expanded:
            if self._expanded_cache is not None:
                return deepcopy(self._expanded_cache)
            # expand variables across the config
            try:
                expanded = _expand_vars_in_value(self._config, self.env)
                self._expanded_cache = expanded
                return deepcopy(expanded)
            except Exception:
                return deepcopy(self._config)
        else:
            return deepcopy(self._config)

    def as_env(self, keys: Optional[List[str]] = None, expanded: bool = True, redact_secrets: bool = True) -> Dict[str, str]:
        """
        Convert selected config values into an environment dict.
        If keys is None, flatten top-level keys.
        Sensitive keys are redacted by default.
        """
        conf = self.to_dict(expanded=expanded)
        out: Dict[str, str] = {}
        def _flatten(prefix: str, val: Any):
            if isinstance(val, dict):
                for k, v in val.items():
                    _flatten(f"{prefix}_{k}" if prefix else k, v)
            elif isinstance(val, list):
                out[prefix] = json.dumps(val)
            else:
                out[prefix] = str(val)

        if keys:
            for key in keys:
                v = self.get(key)
                if v is not None:
                    _flatten(key.replace(".", "_"), v)
        else:
            # flatten top-level
            for k, v in conf.items():
                _flatten(k, v)
        # redact if needed
        if redact_secrets:
            for k in list(out.keys()):
                key_lower = k.lower()
                if any(sk in key_lower for sk in self.sensitive_keys):
                    out[k] = "<REDACTED>"
        return out

    def dump_debug(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Return debugging info: loaded files, active profile, config hash, and config (sanitized).
        """
        cfg = self.to_dict(expanded=True)
        if not include_sensitive:
            cfg = _deep_walk_and_redact(cfg, self.sensitive_keys)
        return {
            "loaded_files": list(self._loaded_files),
            "active_profile": self.active_profile,
            "hash": self._hash_cache,
            "config": cfg,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    # ---------------- helpers for CLI/config introspection ----------------
    def list_modules_via_api(self) -> List[Dict[str, Any]]:
        """
        If newpkg_api is present, return api.list_modules(); otherwise empty list.
        """
        try:
            api = get_api() if get_api else None
            if api:
                api.init_all()
                return api.list_modules()
        except Exception:
            pass
        return []

    # ---------------- utility: sanitize for printing/logging ----------------
    def sanitized_export(self, expanded: bool = True, include_sensitive: bool = False) -> Dict[str, Any]:
        d = self.to_dict(expanded=expanded)
        if not include_sensitive:
            d = _deep_walk_and_redact(d, self.sensitive_keys)
        return d

# ---------------- convenience functions ----------------
def init_config(paths: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None, sensitive_keys: Optional[List[str]] = None) -> NewpkgConfig:
    """
    Initialize and return the singleton NewpkgConfig instance.
    """
    global _config_singleton
    with _config_lock:
        if _config_singleton is None:
            _config_singleton = NewpkgConfig(paths=paths, env=env, sensitive_keys=sensitive_keys)
        return _config_singleton

def get_config() -> NewpkgConfig:
    global _config_singleton
    if _config_singleton is None:
        return init_config()
    return _config_singleton

def reload_config() -> None:
    cfg = get_config()
    cfg.reload(force=True)

# ---------------- module CLI for debugging ----------------
if __name__ == "__main__":
    cfg = init_config()
    import argparse
    p = argparse.ArgumentParser(prog="newpkg-config", description="inspect newpkg configuration")
    p.add_argument("--dump", action="store_true", help="print expanded config (sanitized)")
    p.add_argument("--show-files", action="store_true", help="list loaded files and hash")
    p.add_argument("--include-sensitive", action="store_true", help="include sensitive values in dump")
    args = p.parse_args()
    if args.show_files:
        print("loaded files:", cfg._loaded_files)
        print("hash:", cfg._hash_cache)
        print("active_profile:", cfg.active_profile)
    if args.dump:
        dd = cfg.dump_debug(include_sensitive=args.include_sensitive)
        print(json.dumps(dd, indent=2, ensure_ascii=False))
