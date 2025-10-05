"""
newpkg_deps.py

Gerencia dependências (build/runtime/optional) para newpkg.
- Cache local em .newpkg/deps_cache.json
- Resolução recursiva por tipo (build/runtime/all)
- Integração com newpkg_db, newpkg_logger, newpkg_sandbox
- Exportação de grafo em JSON, DOT (Graphviz) e árvore textual
- Parsing simples de arquivos .dep/.toml/.spec (flexível)

Uso básico:
    deps = NewpkgDeps(cfg, db, logger=logger, sandbox=sandbox)
    resolved = deps.resolve('xorg-server', dep_type='runtime')
    deps.graph('xorg-server', format='dot')

"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import deque

# toml parsing fallback
try:
    import tomllib as _toml
except Exception:
    try:
        import tomli as _toml  # type: ignore
    except Exception:
        _toml = None


class DepsError(Exception):
    pass


class NewpkgDeps:
    def __init__(self, cfg: Any, db: Any, logger: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.db = db
        self.logger = logger
        self.sandbox = sandbox

        # cache filepath
        cache_path = None
        try:
            cache_path = self.cfg.get("NEWPKG_DEPS_CACHE")
        except Exception:
            cache_path = None
        if not cache_path:
            # default inside project dir .newpkg/deps_cache.json or in cwd
            self.cache_file = Path('.newpkg') / 'deps_cache.json'
        else:
            self.cache_file = Path(cache_path)

        # ensure directory
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # in-memory cache
        self._cache: Dict[str, Dict[str, List[str]]] = {}
        self._load_cache()

    # ---------------- cache I/O ----------------
    def _load_cache(self) -> None:
        if self.cache_file.exists():
            try:
                self._cache = json.loads(self.cache_file.read_text(encoding='utf-8'))
            except Exception:
                self._cache = {}
        else:
            self._cache = {}

    def _save_cache(self) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self._cache, indent=2, ensure_ascii=False), encoding='utf-8')
        except Exception:
            # ignore cache write failures
            pass

    def clear_cache(self) -> None:
        self._cache = {}
        try:
            if self.cache_file.exists():
                self.cache_file.unlink()
        except Exception:
            pass

    # ---------------- parse dep files ----------------
    def parse_depfile(self, pkg_dir: Path) -> Dict[str, List[str]]:
        """Tenta ler dependências do diretório do pacote.

        Retorna dict: { 'build': [...], 'runtime': [...], 'optional': [...] }
        Suporta heurísticas:
          - pkg_dir/pkg.dep (simple lines)
          - pkg_dir/pkg.toml with [deps]
          - pkg_dir/depends (custom)
        """
        out = {'build': [], 'runtime': [], 'optional': []}
        pkg_dir = Path(pkg_dir)
        if not pkg_dir.exists():
            return out

        # look for common filenames
        candidates = [p for p in (pkg_dir.glob('*.dep'))] + [pkg_dir / 'pkg.toml', pkg_dir / 'package.toml', pkg_dir / 'depends']
        for c in candidates:
            if not c.exists():
                continue
            try:
                if c.suffix == '.dep' or c.name == 'depends':
                    # simple lines, optionally prefixed with type: name
                    for ln in c.read_text(encoding='utf-8').splitlines():
                        ln = ln.strip()
                        if not ln or ln.startswith('#'):
                            continue
                        if ':' in ln:
                            typ, name = [x.strip() for x in ln.split(':', 1)]
                            if typ.lower() in ('build', 'b'):
                                out['build'].append(name)
                            elif typ.lower() in ('runtime', 'r'):
                                out['runtime'].append(name)
                            elif typ.lower() in ('optional', 'opt'):
                                out['optional'].append(name)
                            else:
                                out['runtime'].append(ln)
                        else:
                            out['runtime'].append(ln)
                elif c.suffix == '.toml' and _toml is not None:
                    data = _toml.loads(c.read_text(encoding='utf-8'))
                    # accept [deps] with keys build/runtime/optional or list under deps
                    deps = data.get('deps') or data.get('dependencies')
                    if isinstance(deps, dict):
                        for k in ('build', 'runtime', 'optional'):
                            if k in deps:
                                val = deps[k]
                                if isinstance(val, (list, tuple)):
                                    out[k].extend(val)
                    elif isinstance(deps, list):
                        out['runtime'].extend(deps)
                    # fallback keys
                    for k in ('build-deps', 'build_deps'):
                        if k in data:
                            out['build'].extend(data[k])
                else:
                    # try to read as simple list
                    for ln in c.read_text(encoding='utf-8').splitlines():
                        ln = ln.strip()
                        if ln and not ln.startswith('#'):
                            out['runtime'].append(ln)
            except Exception:
                continue
        # dedupe
        for k in out.keys():
            seen = []
            for x in out[k]:
                if x not in seen:
                    seen.append(x)
            out[k] = seen
        return out

    # ---------------- resolve deps ----------------
    def resolve(self, pkg_name: str, dep_type: str = 'all', include_optional: bool = False, use_cache: bool = True) -> List[str]:
        """Resolve deps recursively.

        dep_type: 'build' | 'runtime' | 'all'
        """
        pkg = pkg_name
        cache_key = f"{pkg}::{dep_type}::opt={include_optional}"
        if use_cache and cache_key in self._cache:
            return list(self._cache[cache_key].get('deps', [])) if isinstance(self._cache[cache_key], dict) else list(self._cache[cache_key])

        # BFS/DFS over DB dependency graph
        visited: Set[str] = set()
        queue = deque()

        # start from direct deps in DB
        direct = []
        try:
            drows = self.db.get_deps(pkg)
            for d in drows:
                dep = d.get('depends_on')
                dtype = d.get('dep_type') or d.get('type') or 'runtime'
                optional = bool(d.get('optional'))
                if optional and not include_optional:
                    continue
                if dep_type == 'build' and dtype != 'build':
                    continue
                if dep_type == 'runtime' and dtype != 'runtime':
                    continue
                direct.append(dep)
        except Exception:
            # if db unavailable, try cache per-package entry
            cached = self._cache.get(pkg)
            if cached:
                # flatten according to dep_type
                result = set()
                if dep_type in ('all', 'build'):
                    result.update(cached.get('build', []))
                if dep_type in ('all', 'runtime'):
                    result.update(cached.get('runtime', []))
                if include_optional:
                    result.update(cached.get('optional', []))
                return list(result)

        for d in direct:
            queue.append(d)

        result: List[str] = []
        while queue:
            cur = queue.popleft()
            if cur in visited:
                continue
            visited.add(cur)
            result.append(cur)
            # get deps of cur
            try:
                subdeps = self.db.get_deps(cur)
                for sd in subdeps:
                    dep = sd.get('depends_on')
                    dtype = sd.get('dep_type') or sd.get('type') or 'runtime'
                    optional = bool(sd.get('optional'))
                    if optional and not include_optional:
                        continue
                    if dep_type == 'build' and dtype != 'build':
                        continue
                    if dep_type == 'runtime' and dtype != 'runtime':
                        continue
                    if dep not in visited:
                        queue.append(dep)
            except Exception:
                # cannot get deeper, skip
                continue

        # cache result
        try:
            self._cache[cache_key] = {'deps': result}
            self._save_cache()
        except Exception:
            pass
        return result

    # ---------------- check missing ----------------
    def check_missing(self, pkg_name: str, dep_type: str = 'all', include_optional: bool = False) -> List[str]:
        resolved = self.resolve(pkg_name, dep_type=dep_type, include_optional=include_optional)
        missing = []
        try:
            installed = {p.name for p in self.db.list_packages()}
        except Exception:
            installed = set()
        for r in resolved:
            if r not in installed:
                missing.append(r)
        return missing

    # ---------------- sync from DB -> cache ----------------
    def sync_from_db(self) -> None:
        # rebuild cache by scanning DB packages and their deps
        try:
            pkgs = [p.name for p in self.db.list_packages()]
        except Exception:
            pkgs = []
        newcache: Dict[str, Dict[str, List[str]]] = {}
        for p in pkgs:
            entry = {'build': [], 'runtime': [], 'optional': []}
            try:
                deps = self.db.get_deps(p)
                for d in deps:
                    dep = d.get('depends_on')
                    dtype = d.get('dep_type') or d.get('type') or 'runtime'
                    opt = bool(d.get('optional'))
                    if opt:
                        entry['optional'].append(dep)
                    else:
                        if dtype == 'build':
                            entry['build'].append(dep)
                        else:
                            entry['runtime'].append(dep)
            except Exception:
                pass
            newcache[p] = entry
        self._cache = newcache
        self._save_cache()

    # ---------------- graph export ----------------
    def graph(self, pkg_name: str, output: Optional[Path] = None, format: str = 'json', dep_type: str = 'all', include_optional: bool = False) -> str:
        """Export dependency graph for pkg_name.

        format: 'json' | 'dot' | 'tree'
        Returns the generated string. If output is provided, writes to file and also returns string.
        """
        # collect nodes and edges
        nodes: Set[str] = set()
        edges: Set[Tuple[str, str]] = set()

        # BFS gather up to reasonable depth
        q = deque([pkg_name])
        seen: Set[str] = set()
        while q:
            cur = q.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            nodes.add(cur)
            try:
                deps = self.db.get_deps(cur)
                for d in deps:
                    dep = d.get('depends_on')
                    dtype = d.get('dep_type') or d.get('type') or 'runtime'
                    opt = bool(d.get('optional'))
                    if opt and not include_optional:
                        continue
                    if dep_type == 'build' and dtype != 'build':
                        continue
                    if dep_type == 'runtime' and dtype != 'runtime':
                        continue
                    edges.add((cur, dep))
                    if dep not in seen:
                        q.append(dep)
            except Exception:
                # fall back to cache
                cache_entry = self._cache.get(cur)
                if cache_entry:
                    for dtype_key in ('build', 'runtime'):
                        if dep_type != 'all' and dtype_key != dep_type:
                            continue
                        for dep in cache_entry.get(dtype_key, []):
                            edges.add((cur, dep))
                            nodes.add(dep)

        if format == 'json':
            out = {'nodes': sorted(list(nodes)), 'edges': [{'from': a, 'to': b} for a, b in sorted(edges)]}
            s = json.dumps(out, indent=2, ensure_ascii=False)
        elif format == 'dot':
            lines = ['digraph deps {']
            for n in sorted(nodes):
                lines.append(f'  "{n}";')
            for a, b in sorted(edges):
                lines.append(f'  "{a}" -> "{b}";')
            lines.append('}')
            s = '\n'.join(lines)
        elif format == 'tree':
            s = self._render_tree(pkg_name, edges)
        else:
            raise DepsError('Unsupported format')

        if output:
            try:
                Path(output).write_text(s, encoding='utf-8')
            except Exception:
                pass
        return s

    def _render_tree(self, root: str, edges: Set[Tuple[str, str]]) -> str:
        # build adjacency
        adj: Dict[str, List[str]] = {}
        for a, b in edges:
            adj.setdefault(a, []).append(b)
        lines: List[str] = []

        def _walk(node: str, prefix: str = ''):
            lines.append(f"{prefix}{node}")
            for child in sorted(adj.get(node, [])):
                _walk(child, prefix + '  ')

        _walk(root)
        return '\n'.join(lines)

    # ---------------- DB helpers ----------------
    def add_dep(self, pkg: str, depends_on: str, dep_type: str = 'runtime', optional: bool = False) -> None:
        try:
            self.db.add_dependency(pkg, depends_on, optional=optional)
        except Exception:
            # try fallback generic add via SQL-like method if db interface differs
            try:
                self.db.add_dep(pkg, depends_on, dep_type=dep_type, optional=optional)
            except Exception as e:
                raise DepsError(f'Failed to add dependency: {e}')
        # update cache
        self.sync_from_db()

    def remove_dep(self, pkg: str, depends_on: str) -> None:
        try:
            # db expected to have a remove facility; if not, ignore
            self.db.remove_dependency(pkg, depends_on)
        except Exception:
            # best-effort: rebuild cache without touching DB
            pass
        self.sync_from_db()

    # ---------------- installation placeholder ----------------
    def install_missing(self, pkg_name: str, dep_type: str = 'all', include_optional: bool = False, use_sandbox: bool = True) -> Dict[str, Any]:
        """Placeholder: attempts to install missing dependencies using sandbox.

        This function does not implement a package manager; it is a hook for integrating
        with `newpkg_builder` or external installer. Returns a report dict.
        """
        missing = self.check_missing(pkg_name, dep_type=dep_type, include_optional=include_optional)
        report = {'pkg': pkg_name, 'missing': missing, 'installed': [], 'failed': []}
        if not missing:
            return report
        if use_sandbox and self.sandbox:
            for m in missing:
                try:
                    builddir = self.sandbox.sandbox_for_package(m)
                    # hook: user should implement real fetch/build/install steps here
                    res = self.sandbox.run(['/bin/true'], cwd=builddir)
                    if res.returncode == 0:
                        report['installed'].append(m)
                    else:
                        report['failed'].append(m)
                except Exception:
                    report['failed'].append(m)
        else:
            # cannot install, mark as failed
            report['failed'] = missing
        # after attempt, sync cache
        self.sync_from_db()
        return report


# ---------------- CLI helper ----------------
if __name__ == '__main__':
    import argparse

    ap = argparse.ArgumentParser(prog='newpkg-deps')
    ap.add_argument('--pkg', '-p', required=True)
    ap.add_argument('--resolve', action='store_true')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--graph', choices=['json', 'dot', 'tree'], default='json')
    ap.add_argument('--output', '-o', default=None)
    ap.add_argument('--no-cache', action='store_true')
    args = ap.parse_args()

    # try to find DB path
    db = None
    try:
        from newpkg_db import NewpkgDB
    except Exception:
        try:
            from .newpkg_db import NewpkgDB  # type: ignore
        except Exception:
            NewpkgDB = None
    cfg = None
    try:
        # minimal cfg shim
        class CfgShim:
            def get(self, k):
                if k == 'NEWPKG_DEPS_CACHE':
                    return None
                return None
        cfg = CfgShim()
    except Exception:
        cfg = None

    if NewpkgDB is None:
        print('newpkg_db not available in PYTHONPATH. The module can still be imported programmatically.')
        sys.exit(0)

    # find db path from env
    dbp = os.environ.get('NEWPKG_DB_PATH')
    if not dbp:
        print('Please set NEWPKG_DB_PATH to point to sqlite DB for newpkg_db')
        sys.exit(2)

    db = NewpkgDB(db_path=dbp)
    db.init_db()
    deps = NewpkgDeps(cfg, db)
    if args.resolve:
        res = deps.resolve(args.pkg, use_cache=not args.no_cache)
        print(json.dumps(res, indent=2))
    if args.check:
        miss = deps.check_missing(args.pkg, dep_type='all')
        print(json.dumps(miss, indent=2))
    if args.graph:
        s = deps.graph(args.pkg, format=args.graph, output=Path(args.output) if args.output else None)
        print(s)
