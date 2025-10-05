"""
newpkg_config.py

Config manager for newpkg.

Features:
- hierarchical loading: defaults -> /etc/newpkg/config.toml -> ~/.config/newpkg/config.toml -> project_dir/newpkg.toml -> environment overrides
- supports TOML (tomllib/tomli) and YAML (PyYAML optional)
- variable expansion ${VAR} and nested references with caching
- convenience helpers: get_path(), as_env(), save_state(), init_config()
- ModuleRegistry for autodiscovery of newpkg modules
- alias ConfigManager for compatibility

This module is intentionally defensive: it works even if optional parsers are missing.
"""
from __future__ import annotations

import os
import re
import json
import shutil
import pkgutil
import importlib
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple

# Try tomllib (py3.11+), fallback to tomli
try:
    import tomllib as _toml
except Exception:
    try:
        import tomli as _toml  # type: ignore
    except Exception:
        _toml = None

# YAML optional
try:
    import yaml
    _HAS_YAML = True
except Exception:
    yaml = None
    _HAS_YAML = False

ENV_RE = re.compile(r"\$\{([^}]+)\}")


class ConfigError(Exception):
    pass


class ModuleRegistry:
    """Simple autodiscovery for newpkg modules under package path 'newpkg' or provided paths.

    It scans sys.path for packages named 'newpkg_*' or modules under 'newpkg' package.
    The registry exposes `discover()` and `get(module_name)`.
    """

    def __init__(self, search_prefix: str = 'newpkg'):
        self.search_prefix = search_prefix
        self.modules: Dict[str, Dict[str, Any]] = {}

    def discover(self) -> Dict[str, Dict[str, Any]]:
        # scan for top-level packages that start with 'newpkg_'
        for finder, name, ispkg in pkgutil.iter_modules():
            if name.startswith(self.search_prefix + '_') or name == self.search_prefix:
                try:
                    mod = importlib.import_module(name)
                    self.modules[name] = {'module': mod, 'is_package': ispkg}
                except Exception:
                    # best-effort: record name only
                    self.modules[name] = {'module': None, 'is_package': ispkg}
        # also try submodules under 'newpkg' package
        try:
            pkg = importlib.import_module(self.search_prefix)
            prefix = getattr(pkg, '__path__', None)
            if prefix:
                for finder, subname, ispkg in pkgutil.iter_modules(prefix):
                    full = f'{self.search_prefix}.{subname}'
                    try:
                        mod = importlib.import_module(full)
                        self.modules[full] = {'module': mod, 'is_package': ispkg}
                    except Exception:
                        self.modules[full] = {'module': None, 'is_package': ispkg}
        except Exception:
            # package not present, that's fine
            pass
        return self.modules

    def get(self, module_name: str) -> Optional[Dict[str, Any]]:
        return self.modules.get(module_name)


class ConfigStore:
    DEFAULT_FILES = [
        '/etc/newpkg/config.toml',
        str(Path.home() / '.config' / 'newpkg' / 'config.toml')
    ]

    def __init__(self, data: Optional[Dict[str, Any]] = None, sources: Optional[List[str]] = None):
        self._raw: Dict[str, Any] = data or {}
        self._sources: List[str] = sources or []
        self._expand_cache: Dict[str, str] = {}

    # ---------------- load/save ----------------
    @classmethod
    def load(cls, project_dir: Optional[str] = None, extra_paths: Optional[List[str]] = None) -> 'ConfigStore':
        """Load configuration from defaults, system, user, project and environment.

        Precedence (low -> high):
          - built-in defaults (empty)
          - /etc/newpkg/config.toml
          - ~/.config/newpkg/config.toml
          - extra_paths (in listed order)
          - project_dir/newpkg.toml
          - environment variables (NEWPKG_<SECTION>__<KEY> style) override
        """
        data: Dict[str, Any] = {}
        sources: List[str] = []

        # load defaults (none for now)
        # load default files
        for p in cls.DEFAULT_FILES:
            fp = Path(p)
            if fp.exists():
                try:
                    d = cls._read_file(fp)
                    ConfigStore._deep_update(data, d)
                    sources.append(str(fp))
                except Exception:
                    pass

        # extra paths
        if extra_paths:
            for p in extra_paths:
                fp = Path(p)
                if fp.exists():
                    try:
                        d = cls._read_file(fp)
                        ConfigStore._deep_update(data, d)
                        sources.append(str(fp))
                    except Exception:
                        pass

        # project dir override
        if project_dir:
            projf = Path(project_dir) / 'newpkg.toml'
            if projf.exists():
                try:
                    d = cls._read_file(projf)
                    ConfigStore._deep_update(data, d)
                    sources.append(str(projf))
                except Exception:
                    pass

        # environment overrides: NEWPKG_SECTION__KEY=value  (double underscore between section and key)
        for k, v in os.environ.items():
            if not k.startswith('NEWPKG_'):
                continue
            # strip prefix
            tail = k[len('NEWPKG_'):]
            # SECTION__KEY__SUBKEY
            parts = tail.split('__')
            if not parts:
                continue
            target = data
            for part in parts[:-1]:
                target = target.setdefault(part.lower(), {})
            target[parts[-1].lower()] = ConfigStore._coerce_env_value(v)
            sources.append(f'env:{k}')

        cfg = cls(data, sources)
        return cfg

    @staticmethod
    def _read_file(path: Path) -> Dict[str, Any]:
        content = path.read_bytes()
        if path.suffix in ('.toml', '.tml') and _toml:
            try:
                return _toml.loads(content.decode('utf-8'))
            except Exception:
                # try binary toml loader if available
                try:
                    return _toml.loads(content)
                except Exception:
                    return {}
        if path.suffix in ('.yaml', '.yml') and _HAS_YAML:
            try:
                return yaml.safe_load(content.decode('utf-8'))
            except Exception:
                return {}
        # try json
        try:
            return json.loads(content.decode('utf-8'))
        except Exception:
            return {}

    @staticmethod
    def _coerce_env_value(v: str) -> Any:
        # basic coercion for booleans and ints
        if v.lower() in ('true', 'yes', 'on'):
            return True
        if v.lower() in ('false', 'no', 'off'):
            return False
        try:
            if '.' in v:
                f = float(v)
                return f
            i = int(v)
            return i
        except Exception:
            return v

    @staticmethod
    def _deep_update(base: Dict[str, Any], new: Dict[str, Any]) -> None:
        for k, v in (new or {}).items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                ConfigStore._deep_update(base[k], v)
            else:
                base[k] = v

    def save_state(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({'config': self._raw, 'sources': self._sources}, indent=2), encoding='utf-8')

    # ---------------- accessors ----------------
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dotted key: section.key.subkey"""
        parts = key.split('.') if key else []
        cur = self._raw
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return default
        return cur

    def set(self, key: str, value: Any) -> None:
        parts = key.split('.')
        cur = self._raw
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value

    def get_path(self, key: str, default: Optional[str] = None) -> Optional[Path]:
        v = self.get(key, default)
        if v is None:
            return None
        try:
            return Path(str(v)).expanduser().resolve()
        except Exception:
            return Path(str(v)).expanduser()

    def as_env(self) -> Dict[str, str]:
        """Return flattened config suitable for passing to environment of subprocesses."""
        out: Dict[str, str] = {}
        def _flatten(prefix: str, d: Any):
            if isinstance(d, dict):
                for k, vv in d.items():
                    _flatten(f'{prefix}_{k.upper()}' if prefix else k.upper(), vv)
            else:
                out[prefix] = str(d)
        _flatten('NEWPKG', self._raw)
        return out

    # ---------------- expansion ----------------
    def _expand_str(self, s: str) -> str:
        # cache hits
        if s in self._expand_cache:
            return self._expand_cache[s]

        def repl(m):
            key = m.group(1)
            # support dotted keys
            val = self.get(key) if '.' in key else self._raw.get(key)
            if val is None:
                # fallback to env var
                val = os.environ.get(key, '')
            if isinstance(val, (dict, list)):
                return json.dumps(val)
            return str(val)

        res = ENV_RE.sub(repl, s)
        self._expand_cache[s] = res
        return res

    def expand_all(self) -> None:
        # walk config and expand strings
        def walk(obj: Any):
            if isinstance(obj, dict):
                for k, v in list(obj.items()):
                    if isinstance(v, str):
                        obj[k] = self._expand_str(v)
                    else:
                        walk(v)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    if isinstance(v, str):
                        obj[i] = self._expand_str(v)
                    else:
                        walk(v)
        walk(self._raw)

    # ---------------- utility / validation ----------------
    def validate(self) -> Tuple[bool, List[str]]:
        errs: List[str] = []
        # example checks
        if not self.get('general.src_dir'):
            errs.append('general.src_dir is not set')
        if not self.get('general.build_dir'):
            errs.append('general.build_dir is not set')
        return (len(errs) == 0, errs)

    def autodiscover_modules(self) -> ModuleRegistry:
        mr = ModuleRegistry()
        mr.discover()
        return mr


# compatibility aliases
ConfigManager = ConfigStore


# convenience initializer used by CLI and modules
def init_config(project_dir: Optional[str] = None, extra_paths: Optional[List[str]] = None) -> ConfigStore:
    cfg = ConfigStore.load(project_dir=project_dir, extra_paths=extra_paths)
    cfg.expand_all()
    return cfg


# small CLI for debugging/loading the config
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(prog='newpkg-config')
    ap.add_argument('--project', help='project dir to load config from')
    ap.add_argument('--dump', action='store_true', help='dump resolved config')
    args = ap.parse_args()
    cfg = init_config(project_dir=args.project)
    if args.dump:
        print(json.dumps(cfg._raw, indent=2))
    else:
        ok, errs = cfg.validate()
        if not ok:
            print('Config validation errors:')
            for e in errs:
                print(' -', e)
        else:
            print('Config loaded OK')
