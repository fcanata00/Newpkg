"""
newpkg.config

Módulo de configuração para o projeto `newpkg` (LFS/BLFS builder).
- Carrega TOML (arquivo único + config.d fragments)
- Prioridade: defaults < system < user < project < env < cli-overrides
- Expansão de variáveis com detecção de ciclos
- Perfis (profiles)
- Exporta ConfigStore e helpers
- Autodiscovery minimal de módulos em Newpkg/newpkg/modules (AST-based, sem executar código)

Este arquivo implementa um módulo autônomo. Testes e integração com CLI são esperados separadamente.
"""

from __future__ import annotations

import os
import sys
import re
import tomllib as _tomllib  # Python 3.11+
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Tuple
import json
import shutil
import textwrap
import ast
from dataclasses import dataclass, field
from string import Template

# Fallback for older runtimes: try tomli
try:
    import tomllib as toml
except Exception:
    try:
        import tomli as toml  # type: ignore
    except Exception:
        raise RuntimeError("tomllib/tomli is required to parse TOML. Install tomli for older Pythons.")


# -------------------------- Utilities --------------------------
VAR_PATTERN = re.compile(r"\$(?:\{([^}\s:]+)(?:[:-]([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))")


def _is_truthy(val: Any) -> bool:
    return bool(val) and val not in ("0", "false", "False", "no", "No")


def _read_toml_file(path: Path) -> dict:
    with path.open("rb") as f:
        return toml.load(f)


def _merge_dict(a: dict, b: dict) -> dict:
    """Merge b into a (deep), returning new dict."""
    out = dict(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge_dict(out[k], v)
        else:
            out[k] = v
    return out


# ----------------------- ConfigStore ---------------------------

class ConfigError(Exception):
    pass


@dataclass
class ConfigStore:
    _raw: Dict[str, Any] = field(default_factory=dict)
    _expanded_cache: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1
    fail_on_missing: bool = True

    # ---------------------------------
    # Construction / loading helpers
    # ---------------------------------
    @classmethod
    def load(
        cls,
        project_dir: Optional[Path] = None,
        extra_paths: Optional[List[Path]] = None,
        env_prefix: str = "NEWPKG_",
        strict: bool = True,
    ) -> "ConfigStore":
        """Load config following priorities and merge into a ConfigStore.

        Defaults (internal) < /etc/newpkg/config.toml < ~/.config/newpkg/config.toml < project_dir/newpkg.toml & config.d/* < extra_paths (ordered) < ENV vars
        """
        store = cls()
        # 1) defaults
        defaults = {
            "general": {
                "LFS": "/mnt/lfs",
                "BUILD_DIR": "${LFS}/build",
                "SRC_DIR": "${LFS}/sources",
                "PKG_DIR": "${LFS}/pkgs",
                "DESTDIR": "${LFS}/dest",
                "JOBS": 4,
                "MAKEFLAGS": "-j${JOBS}",
            },
            "sandbox": {"backend": "bubblewrap"},
            "packaging": {"format": "tar.xz", "compress_level": 6},
            "logging": {"level": "INFO", "log_dir": "./logs"},
        }
        store._raw = defaults

        # 2) system
        sys_conf = Path("/etc/newpkg/config.toml")
        if sys_conf.exists():
            store._raw = _merge_dict(store._raw, _read_toml_file(sys_conf))

        # 3) user
        user_conf = Path.home() / ".config" / "newpkg" / "config.toml"
        if user_conf.exists():
            store._raw = _merge_dict(store._raw, _read_toml_file(user_conf))

        # 4) project
        if project_dir:
            project_main = Path(project_dir) / "newpkg.toml"
            if project_main.exists():
                store._raw = _merge_dict(store._raw, _read_toml_file(project_main))
            configd = Path(project_dir) / "config.d"
            if configd.exists() and configd.is_dir():
                for p in sorted(configd.iterdir()):
                    if p.suffix in (".toml",) and p.is_file():
                        store._raw = _merge_dict(store._raw, _read_toml_file(p))

        # 5) extra_paths
        if extra_paths:
            for p in extra_paths:
                if p.exists():
                    store._raw = _merge_dict(store._raw, _read_toml_file(p))

        # 6) env overrides
        for k, v in os.environ.items():
            if k.startswith(env_prefix):
                key = k[len(env_prefix) :]
                # simple mapping: NEWPKG_LFS -> general.LFS
                parts = key.split("__")
                dest = store._raw
                for part in parts[:-1]:
                    dest = dest.setdefault(part.lower(), {})
                dest[parts[-1].lower()] = v

        store.fail_on_missing = strict
        return store

    # -------------------------------
    # Accessors
    # -------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        """Get a dotted key, expanded.
        Example: get('general.LFS')
        """
        parts = key.split(".")
        node = self._raw
        for p in parts:
            if isinstance(node, dict) and p in node:
                node = node[p]
            else:
                return default
        return self._expand_value(node)

    def set(self, key: str, value: Any) -> None:
        parts = key.split(".")
        node = self._raw
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
        # invalidate cache
        self._expanded_cache.clear()

    def as_dict(self, expanded: bool = True) -> Dict[str, Any]:
        if not expanded:
            return dict(self._raw)
        # naive expansion for mapping
        def _expand_node(v):
            if isinstance(v, dict):
                return {k: _expand_node(vv) for k, vv in v.items()}
            return self._expand_value(v)

        return _expand_node(self._raw)

    # -------------------------------
    # Expansion logic
    # -------------------------------
    def _expand_value(self, value: Any, _stack: Optional[List[str]] = None) -> Any:
        if isinstance(value, str):
            return self._expand_str(value, _stack=_stack)
        if isinstance(value, dict):
            return {k: self._expand_value(v, _stack=_stack) for k, v in value.items()}
        if isinstance(value, list):
            return [self._expand_value(v, _stack=_stack) for v in value]
        return value

    def _expand_str(self, s: str, _stack: Optional[List[str]] = None) -> str:
        if _stack is None:
            _stack = []

        # handle escaped \${...}
        s = s.replace("\\${", "__ESCAPED_DOLLAR__{")

        def _repl(m: re.Match) -> str:
            var_name = m.group(1) or m.group(3)
            default = m.group(2)
            if var_name in _stack:
                chain = " -> ".join(_stack + [var_name])
                raise ConfigError(f"Cycle detected when expanding variables: {chain}")
            _stack.append(var_name)
            # try dotted lookup first
            val = self._lookup_variable(var_name)
            if val is None:
                if default is not None:
                    res = default
                else:
                    if self.fail_on_missing:
                        raise ConfigError(f"Variable '{var_name}' not found during expansion and no default provided")
                    res = ""
            else:
                res = str(self._expand_value(val, _stack=_stack))
            _stack.pop()
            return res

        out = VAR_PATTERN.sub(_repl, s)
        out = out.replace("__ESCAPED_DOLLAR__{", "${")
        return out

    def _lookup_variable(self, name: str) -> Optional[Any]:
        # support dotted names on lookup: e.g. 'general.LFS'
        if "." in name:
            parts = name.split(".")
            node = self._raw
            for p in parts:
                if isinstance(node, dict) and p in node:
                    node = node[p]
                else:
                    return None
            return node
        # try top-level keys and env var fallbacks
        low = name.lower()
        if low in self._raw:
            return self._raw[low]
        # try common sections
        for sec in ("general", "sandbox", "packaging", "logging"):
            secd = self._raw.get(sec)
            if isinstance(secd, dict) and name in secd:
                return secd[name]
            if isinstance(secd, dict) and low in secd:
                return secd[low]
        # environment variables as last resort
        if name in os.environ:
            return os.environ[name]
        if low in os.environ:
            return os.environ[low]
        return None

    # -------------------------------
    # Template rendering
    # -------------------------------
    def render_template(self, template_str: str) -> str:
        # Using string.Template for simplicity; user can plug jinja externally.
        mapping = self.as_dict(expanded=True)

        # flattened mapping with dotted keys for convenience
        flat = {}

        def _flatten(prefix: str, node: Any):
            if isinstance(node, dict):
                for k, v in node.items():
                    _flatten(f"{prefix}.{k}" if prefix else k, v)
            else:
                flat[prefix] = node

        _flatten("", mapping)
        # string.Template expects mapping with simple keys
        safe_map = {k.replace(".", "_"): v for k, v in flat.items()}
        t = Template(template_str)
        return t.safe_substitute(safe_map)

    # -------------------------------
    # Profiles
    # -------------------------------
    def profile(self, name: str) -> "ConfigStore":
        # returns a new ConfigStore with profile overrides applied (does not mutate self)
        profs = self._raw.get("profiles") or {}
        p = profs.get(name) or {}
        new_raw = _merge_dict(self._raw, p)
        return ConfigStore(_raw=new_raw, schema_version=self.schema_version, fail_on_missing=self.fail_on_missing)

    # -------------------------------
    # Save
    # -------------------------------
    def save(self, path: Path) -> None:
        try:
            import tomli_w  # type: ignore

            out = tomli_w.dumps(self._raw)
            path.write_text(out, encoding="utf-8")
        except Exception:
            # fallback: json pretty print for portability
            path.write_text(json.dumps(self._raw, indent=2), encoding="utf-8")


# ----------------------- Module autodiscovery ------------------------
# Minimal AST based metadata extractor; DOES NOT execute module code.

MODULE_SEARCH_DIR = Path("Newpkg") / "newpkg" / "modules"


@dataclass
class ModuleMeta:
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    requires: List[str] = field(default_factory=list)
    path: Optional[Path] = None


class ModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, ModuleMeta] = {}

    def discover(self, base: Optional[Path] = None) -> None:
        base = base or MODULE_SEARCH_DIR
        if not base.exists():
            return
        for p in sorted(base.rglob("*.py")):
            try:
                meta = self._extract_meta_from_file(p)
                if meta:
                    meta.path = p
                    self._modules[meta.name] = meta
            except Exception as e:
                # don't raise: keep discovery robust
                print(f"[newpkg.config] warning: failed to parse module {p}: {e}", file=sys.stderr)

    def list(self) -> List[ModuleMeta]:
        return list(self._modules.values())

    def get(self, name: str) -> Optional[ModuleMeta]:
        return self._modules.get(name)

    @staticmethod
    def _extract_meta_from_file(path: Path) -> Optional[ModuleMeta]:
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(path))
        name = None
        version = None
        descr = None
        requires = []
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id == "NAME" and isinstance(node.value, (ast.Constant, ast.Str)):
                            name = getattr(node.value, "s", None) or getattr(node.value, "value", None)
                        if target.id == "VERSION" and isinstance(node.value, (ast.Constant, ast.Str)):
                            version = getattr(node.value, "s", None) or getattr(node.value, "value", None)
                        if target.id == "DESCRIPTION" and isinstance(node.value, (ast.Constant, ast.Str)):
                            descr = getattr(node.value, "s", None) or getattr(node.value, "value", None)
                        if target.id == "REQUIRES":
                            # try to extract list of strings
                            if isinstance(node.value, (ast.List, ast.Tuple)):
                                reqs = []
                                for el in node.value.elts:
                                    if isinstance(el, ast.Constant):
                                        reqs.append(el.value)
                                requires = reqs
        if name:
            return ModuleMeta(name=name, version=version, description=descr, requires=requires, path=path)
        return None


# ----------------------- CLI utility (minimal) ------------------------

def _dump_cli(project_dir: Optional[str] = None, extra: Optional[List[str]] = None) -> int:
    p = Path(project_dir) if project_dir else None
    cfg = ConfigStore.load(project_dir=p, extra_paths=[Path(x) for x in (extra or [])])
    print("# newpkg: resolved config (expanded)\n")
    print(json.dumps(cfg.as_dict(expanded=True), indent=2, ensure_ascii=False))
    # module discovery demo
    mr = ModuleRegistry()
    mr.discover()
    mods = [dict(name=m.name, version=m.version or "", path=str(m.path)) for m in mr.list()]
    print("\n# discovered modules:\n")
    print(json.dumps(mods, indent=2, ensure_ascii=False))
    return 0


# ------------------------------ Demo / Entrypoint ------------------------------
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(prog="newpkg-config")
    ap.add_argument("--project-dir", help="project dir to load project-level config from", default=None)
    ap.add_argument("--extra", help="extra toml paths (comma separated)", default=None)
    ap.add_argument("--dump", help="dump resolved config", action="store_true")
    args = ap.parse_args()
    extra = args.extra.split(",") if args.extra else None
    if args.dump:
        sys.exit(_dump_cli(args.project_dir, extra))

    print("newpkg config module loaded. Use --dump to print resolved config.")
