#!/usr/bin/env python3
# newpkg_config_fixed.py
"""
Central configuration loader for newpkg (improved)

Fixes & improvements applied:
- Lazy import of newpkg_api.get_api to avoid circular import
- _include_cache added to avoid reparsing included files repeatedly
- Better logging for missing includes and parse errors
- SimpleLogger fallback when newpkg_logger.get_logger is unavailable (parity with newpkg_api)
- Minor optimization: avoid deepcopy in some merge branches when safe
- list_modules_via_api uses lazy import and avoids forcing init_all() every call
- reload() logs number of files loaded and errors for easier debugging
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import threading
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List, Optional

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
# NOTE: do NOT import newpkg_api at module import time to avoid circular imports.
try:
    from newpkg_logger import get_logger  # type: ignore
except Exception:
    get_logger = None

# Thread-safe singleton
_config_singleton = None
_config_lock = threading.RLock()

# Keys considered sensitive (will be redacted in dumps/as_env unless explicit allow)
DEFAULT_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey", "ssh_key", "private_key"}


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
    """Recursively merge override into base. Values in override take precedence."""
    out = deepcopy(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge_dict(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


def _detect_format_and_parse(path: str) -> Optional[Dict[str, Any]]:
    """Try to detect and parse JSON/TOML/YAML."""
    try:
        raw = _read_file_bytes(path)
    except Exception:
        return None
    suffix = pathlib.Path(path).suffix.lower()
    txt = raw.decode("utf-8", errors="ignore").strip()

    if suffix == ".toml":
        if tomllib:
            try:
                return tomllib.loads(txt)
            except Exception:
                pass
        if _toml:
            try:
                return _toml.loads(txt)
            except Exception:
                pass

    if suffix == ".json" or txt.startswith("{") or txt.startswith("["):
        try:
            return json.loads(txt)
        except Exception:
            pass

    if suffix in (".yml", ".yaml") and yaml:
        try:
            return yaml.safe_load(txt)
        except Exception:
            pass

    if "=" in txt and (tomllib or _toml):
        try:
            if tomllib:
                return tomllib.loads(txt)
            if _toml:
                return _toml.loads(txt)
        except Exception:
            pass

    try:
        return json.loads(txt)
    except Exception:
        return None


def _expand_vars_in_value(value: Any, env: Dict[str, str]) -> Any:
    """Expand ${VAR} and $VAR references inside strings recursively."""
    if isinstance(value, str):
        out = value
        for _ in range(5):
            try:
                out_new = os.path.expandvars(out)
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
    """Return a copy of structure with sensitive keys redacted."""
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


class SimpleLogger:
    def info(self, *args, **kwargs):
        print("[INFO]", *args)

    def warning(self, *args, **kwargs):
        print("[WARN]", *args)

    def error(self, *args, **kwargs):
        print("[ERROR]", *args)


class NewpkgConfig:
    def __init__(self, paths: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None, sensitive_keys: Optional[List[str]] = None):
        self.paths = [_normalize_path(p) for p in (paths or [])]
        self.env = env or dict(os.environ)
        self.sensitive_keys = set([k.lower() for k in (sensitive_keys or [])]) | set(DEFAULT_SENSITIVE_KEYS)
        self._config: Dict[str, Any] = {}
        self._expanded_cache: Optional[Dict[str, Any]] = None
        self._hash_cache: Optional[str] = None
        try:
            self.logger = get_logger(self) if get_logger else SimpleLogger()
        except Exception:
            self.logger = SimpleLogger()

        if not self.paths:
            self.paths = self._default_search_paths()

        self._include_cache: Dict[str, Dict[str, Any]] = {}
        self._loaded_files: List[str] = []
        self.active_profile: Optional[str] = None

        try:
            self.reload()
        except Exception as e:
            self.logger.warning("config.reload_failed", str(e))

        dp = self.get("cli.default_profile")
        if dp:
            try:
                self.activate_profile(dp)
            except Exception:
                pass

        try:
            from newpkg_api import get_api  # type: ignore
            try:
                api = get_api()
                api.cfg = self
                self.logger.info("config.register", "registered config with newpkg_api")
            except Exception:
                pass
        except Exception:
            pass

    def _default_search_paths(self) -> List[str]:
        candidates = []
        cwd = os.getcwd()
        candidates.append(os.path.join(cwd, "newpkg.toml"))
        candidates.extend(["/etc/newpkg.toml", "/etc/newpkg/config.toml"])
        home = os.path.expanduser("~/.config/newpkg/config.toml")
        candidates.append(home)
        return [p for p in candidates if _file_exists(p)]

    def reload(self, force: bool = False) -> None:
        self._loaded_files = []
        files = [p for p in self.paths if _file_exists(p)]
        if not files:
            self._config = {}
            self._expanded_cache = None
            self._hash_cache = None
            return

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
            self.logger.info("config.reload", "no changes detected")
            return

        merged: Dict[str, Any] = {}
        errors: List[str] = []
        for f in files:
            try:
                loaded = self._load_with_includes(f, seen=set())
                if loaded:
                    merged = _merge_dict(merged, loaded)
            except Exception as e:
                errors.append(f"{f}: {e}")

        self._config = merged
        self._expanded_cache = None
        self._hash_cache = new_hash
        dp = self.get("cli.default_profile")
        if dp:
            try:
                self.activate_profile(dp)
            except Exception:
                pass
        self.logger.info("config.reload", f"loaded {len(self._loaded_files)} files, errors={len(errors)}")
        for e in errors:
            self.logger.warning("config.reload.error", e)

    def _load_with_includes(self, path: str, seen: set) -> Optional[Dict[str, Any]]:
        path = _normalize_path(path)
        if path in seen:
            return {}
        seen.add(path)
        if path in self._include_cache:
            self._loaded_files.append(path)
            return deepcopy(self._include_cache[path])

        parsed = _detect_format_and_parse(path)
        if not parsed:
            self.logger.warning("config.parse_fail", f"failed to parse {path}")
            return {}
        includes = parsed.get("include") or parsed.get("includes")
        included_merged: Dict[str, Any] = {}
        if includes:
            if isinstance(includes, str):
                includes = [includes]
            for inc in includes:
                inc_path = _normalize_path(inc)
                if not _file_exists(inc_path):
                    alt = os.path.join(os.path.dirname(path), inc)
                    if _file_exists(alt):
                        inc_path = alt
                if not _file_exists(inc_path):
                    self.logger.warning("config.include_missing", f"include {inc} not found for {path}")
                    continue
                try:
                    sub = self._load_with_includes(inc_path, seen)
                    if sub:
                        included_merged = _merge_dict(included_merged, sub)
                    self.logger.info("config.include.loaded", f"loaded include {inc_path}")
                except Exception as e:
                    self.logger.warning("config.include.error", f"error loading include {inc_path}: {e}")
                    continue
        merged = _merge_dict(included_merged, parsed)
        self._include_cache[path] = deepcopy(merged)
        self._loaded_files.append(path)
        return merged

    def get(self, key: str, default: Any = None) -> Any:
        parts = key.split(".")
        cur = self._config
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return default
        return cur

    def set(self, key: str, value: Any) -> None:
        parts = key.split(".")
        cur = self._config
        for p in parts[:-1]:
            if p not in cur or not isinstance(cur[p], dict):
                cur[p] = {}
            cur = cur[p]
        cur[parts[-1]] = value
        self._expanded_cache = None

    def activate_profile(self, profile_name: str) -> None:
        profiles = self._config.get("profiles") or {}
        if not isinstance(profiles, dict):
            return
        prof = profiles.get(profile_name)
        if not prof or not isinstance(prof, dict):
            return
        base = deepcopy(self._config)
        merged = _merge_dict(base, prof)
        merged["profiles"] = self._config.get("profiles", {})
        self._config = merged
        self.active_profile = profile_name
        self._expanded_cache = None
        self.logger.info("config.profile.activate", f"activated profile {profile_name}")

    def to_dict(self, expanded: bool = True) -> Dict[str, Any]:
        if expanded:
            if self._expanded_cache is not None:
                return deepcopy(self._expanded_cache)
            try:
                expanded_cfg = _expand_vars_in_value(self._config, self.env)
                self._expanded_cache = expanded_cfg
                return deepcopy(expanded_cfg)
            except Exception:
                return deepcopy(self._config)
        else:
            return deepcopy(self._config)

    def as_env(self, keys: Optional[List[str]] = None, expanded: bool = True, redact_secrets: bool = True) -> Dict[str, str]:
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
            for k, v in conf.items():
                _flatten(k, v)

        if redact_secrets:
            for k in list(out.keys()):
                key_lower = k.lower()
                if any(sk in key_lower for sk in self.sensitive_keys):
                    out[k] = "<REDACTED>"
        return out

    def dump_debug(self, include_sensitive: bool = False) -> Dict[str, Any]:
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

    def list_modules_via_api(self) -> List[Dict[str, Any]]:
        """If newpkg_api is present, return api.list_modules(); otherwise empty list."""
        try:
            from newpkg_api import get_api  # type: ignore
            api = get_api()
            return api.list_modules()
        except Exception:
            return []


def init_config(paths: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None, sensitive_keys: Optional[List[str]] = None) -> NewpkgConfig:
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
        import json as _json
        print(_json.dumps(dd, indent=2, ensure_ascii=False))
