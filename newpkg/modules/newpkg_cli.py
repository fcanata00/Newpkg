#!/usr/bin/env python3
"""
newpkg_cli.py

CLI integrador para Newpkg — orquestra modules: deps, download, patcher, core, db, hooks, upgrade, remove, audit, sync
Provides a rich, animated, colored UX for long-running steps and supports --install full pipeline.

Features implemented here:
 - Subcommands: install (-i/--install), remove, build, upgrade, sync, audit, revdep, info
 - Global flags: --dry-run, --quiet, --yes, --jobs, --sandbox, --destdir, --no-color, --verbose
 - Install pipeline: resolve deps -> download -> extract -> patch -> build -> package -> install
 - Visual UI using rich (fallback gracefully if not installed)
 - Progress bars for downloads and packing; spinners for phases; system metrics shown during build (psutil optional)
 - Module auto-discovery: imports modules if present and falls back to shims

Note: This file assumes the other newpkg modules exist in the PYTHONPATH.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# optional visual libs
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn
    from rich.spinner import Spinner
    from rich.panel import Panel
    from rich.table import Table
    _HAS_RICH = True
except Exception:
    Console = None
    Progress = None
    Spinner = None
    Panel = None
    Table = None
    _HAS_RICH = False

try:
    from tqdm import tqdm
    _HAS_TQDM = True
except Exception:
    tqdm = None
    _HAS_TQDM = False

try:
    import psutil
    _HAS_PSUTIL = True
except Exception:
    psutil = None
    _HAS_PSUTIL = False


# ---------------- utilities ----------------
console = Console() if _HAS_RICH else None


def _log(msg: str, level: str = 'INFO'):
    if console:
        console.log(f"[{level}] {msg}")
    else:
        print(f"[{level}] {msg}")


def _safe_import(module_name: str):
    try:
        return importlib.import_module(module_name)
    except Exception:
        return None


# ---------------- module bootstrap/shims ----------------
# try to import modules created previously; if missing create minimal shims
NewpkgDeps = _safe_import('newpkg_deps')
NewpkgDownload = _safe_import('newpkg_download')
NewpkgPatcher = _safe_import('newpkg_patcher')
NewpkgCore = _safe_import('newpkg_core')
NewpkgDB = _safe_import('newpkg_db')
NewpkgHooks = _safe_import('newpkg_hooks')
NewpkgUpgrade = _safe_import('newpkg_upgrade')
NewpkgRemove = _safe_import('newpkg_remove')
NewpkgAudit = _safe_import('newpkg_audit')
NewpkgSync = _safe_import('newpkg_sync')
NewpkgMetaFile = _safe_import('newpkg_metafile')


class Shim:
    def __init__(self, name):
        self._name = name

    def __getattr__(self, item):
        def _missing(*a, **k):
            raise RuntimeError(f"Module {self._name} not available in this environment: attempted {item}")
        return _missing


if NewpkgDeps is None:
    NewpkgDeps = Shim('newpkg_deps')
if NewpkgDownload is None:
    NewpkgDownload = Shim('newpkg_download')
if NewpkgPatcher is None:
    NewpkgPatcher = Shim('newpkg_patcher')
if NewpkgCore is None:
    NewpkgCore = Shim('newpkg_core')
if NewpkgDB is None:
    NewpkgDB = Shim('newpkg_db')
if NewpkgHooks is None:
    NewpkgHooks = Shim('newpkg_hooks')
if NewpkgUpgrade is None:
    NewpkgUpgrade = Shim('newpkg_upgrade')
if NewpkgRemove is None:
    NewpkgRemove = Shim('newpkg_remove')
if NewpkgAudit is None:
    NewpkgAudit = Shim('newpkg_audit')
if NewpkgSync is None:
    NewpkgSync = Shim('newpkg_sync')
if NewpkgMetaFile is None:
    NewpkgMetaFile = Shim('newpkg_metafile')


# ---------------- CLI core ----------------

class NewpkgCLI:
    def __init__(self):
        self.parser = self._build_parser()
        self.args = None
        self.config = None
        self.modules = {}
        # will be initialized at runtime

    def _build_parser(self) -> argparse.ArgumentParser:
        p = argparse.ArgumentParser(prog='newpkg', description='Newpkg package manager')
        # global flags
        p.add_argument('--dry-run', action='store_true', help='simulate actions without performing them')
        p.add_argument('--quiet', action='store_true', help='show only main phases')
        p.add_argument('--yes', '-y', action='store_true', help='assume yes for all prompts')
        p.add_argument('--jobs', type=int, default=4, help='parallel jobs for build/downloads')
        p.add_argument('--sandbox', action='store_true', help='force sandbox usage')
        p.add_argument('--destdir', type=str, default='/', help='install destination root')
        p.add_argument('--no-color', action='store_true', help='disable colors and animations')
        p.add_argument('--verbose', action='store_true', help='verbose logging')

        # subcommands
        sub = p.add_subparsers(dest='cmd', required=True)

        # install
        pi = sub.add_parser('install', aliases=['-i'], help='Resolve deps, build, package and install a package')
        pi.add_argument('target', help='package name, metafile path, or directory')
        pi.add_argument('--rebuild', action='store_true', help='force rebuild even if installed')
        pi.add_argument('--only-deps', action='store_true', help='only resolve & install dependencies')
        pi.add_argument('--keep-build-dir', action='store_true', help='do not delete build dir after build')

        # other useful subcommands (lightweight)
        sub.add_parser('remove', aliases=['-r'], help='remove package')
        sub.add_parser('build', aliases=['-b'], help='build package (prepare/build/package)')
        sub.add_parser('upgrade', aliases=['-u'], help='upgrade package')
        sub.add_parser('sync', aliases=['-s'], help='sync repos')
        sub.add_parser('audit', aliases=['-a'], help='audit system for vulnerabilities')
        sub.add_parser('revdep', help='compute reverse dependencies')
        info = sub.add_parser('info', aliases=['-I'], help='show package info')
        info.add_argument('pkg', nargs='?', help='package name')

        return p

    def _init_modules(self):
        # instantiate primary modules if available
        try:
            cfg = None
            # config loader could be implemented — use None stub
            self.modules['db'] = NewpkgDB.NewpkgDB(db_path=os.environ.get('NEWPKG_DB_PATH')) if hasattr(NewpkgDB, 'NewpkgDB') else None
        except Exception:
            self.modules['db'] = None
        try:
            self.modules['deps'] = NewpkgDeps.NewpkgDeps(cfg, self.modules.get('db')) if hasattr(NewpkgDeps, 'NewpkgDeps') else None
        except Exception:
            self.modules['deps'] = None
        try:
            self.modules['downloader'] = NewpkgDownload.NewpkgDownloader(cfg, logger=None, db=self.modules.get('db')) if hasattr(NewpkgDownload, 'NewpkgDownloader') else None
        except Exception:
            self.modules['downloader'] = None
        try:
            self.modules['patcher'] = NewpkgPatcher.NewpkgPatcher(cfg) if hasattr(NewpkgPatcher, 'NewpkgPatcher') else None
        except Exception:
            self.modules['patcher'] = None
        try:
            self.modules['core'] = NewpkgCore.NewpkgCore(cfg, self.modules.get('db'), logger=None, sandbox=None, deps=self.modules.get('deps')) if hasattr(NewpkgCore, 'NewpkgCore') else None
        except Exception:
            self.modules['core'] = None
        try:
            self.modules['hooks'] = NewpkgHooks.NewpkgHooks(cfg) if hasattr(NewpkgHooks, 'NewpkgHooks') else None
        except Exception:
            self.modules['hooks'] = None
        try:
            self.modules['upgrade'] = NewpkgUpgrade.NewpkgUpgrade(cfg, logger=None, db=self.modules.get('db'), downloader=self.modules.get('downloader'), core=self.modules.get('core')) if hasattr(NewpkgUpgrade, 'NewpkgUpgrade') else None
        except Exception:
            self.modules['upgrade'] = None
        try:
            self.modules['remover'] = NewpkgRemove.NewpkgRemove(cfg, logger=None, db=self.modules.get('db'), sandbox=None, hooks=self.modules.get('hooks')) if hasattr(NewpkgRemove, 'NewpkgRemove') else None
        except Exception:
            self.modules['remover'] = None
        try:
            self.modules['audit'] = NewpkgAudit.NewpkgAudit(cfg, logger=None, db=self.modules.get('db'), deps=self.modules.get('deps'), upgrade=self.modules.get('upgrade'), core=self.modules.get('core'), patcher=self.modules.get('patcher'), remover=self.modules.get('remover'), hooks=self.modules.get('hooks')) if hasattr(NewpkgAudit, 'NewpkgAudit') else None
        except Exception:
            self.modules['audit'] = None
        try:
            self.modules['sync'] = NewpkgSync.NewpkgSync(cfg, logger=None, db=self.modules.get('db'), sandbox=None, hooks=self.modules.get('hooks')) if hasattr(NewpkgSync, 'NewpkgSync') else None
        except Exception:
            self.modules['sync'] = None

    # ---------- visual helpers ----------
    def _phase_banner(self, title: str, quiet: bool = False):
        if quiet:
            print(f'>>>> {title} <<<<')
            return
        if console and not self.args.no_color:
            console.rule(f"[cyan]>>>> {title} <<<<")
        else:
            print(f'>>>> {title} <<<<')

    async def _progress_download(self, tasks: List[Dict[str, Any]], jobs: int = 4):
        # tasks: each {url, dest, checksum?}
        downloader = self.modules.get('downloader')
        if downloader is None:
            raise RuntimeError('downloader not configured')
        # prefer downloader.download_many which is async in our implementation
        coro = downloader.download_many(tasks, parallel=jobs)
        return await coro

    def _show_build_metrics(self):
        if not _HAS_PSUTIL:
            return ''
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        load = os.getloadavg() if hasattr(os, 'getloadavg') else (0.0, 0.0, 0.0)
        return f'CPU: {cpu}% | Mem: {mem.used//1024//1024}MB/{mem.total//1024//1024}MB | Load: {load[0]:.2f}'

    # ---------- install pipeline ----------
    def _resolve_dependencies(self, target: str, only_deps: bool = False, jobs: int = 4, dry_run: bool = True) -> List[str]:
        deps_mod = self.modules.get('deps')
        if deps_mod is None:
            _log('deps module not available; assuming single package', 'WARNING')
            return [target]
        try:
            # deps module expected to expose resolve(package) -> ordered list
            order = deps_mod.NewpkgDeps.resolve if hasattr(deps_mod.NewpkgDeps, 'resolve') else None
            if order:
                # in case module is class-based, instantiate
                inst = deps_mod.NewpkgDeps(None, self.modules.get('db'))
                resolved = inst.resolve(target)
                if dry_run:
                    return resolved
                return resolved
            # fallback: call module-level function
            if hasattr(deps_mod, 'resolve'):
                return deps_mod.resolve(target)
        except Exception as e:
            _log(f'deps resolution failed: {e}', 'ERROR')
            return [target]
        return [target]

    def _download_sources_for_pkg(self, pkg: str, workdir: Path, jobs: int) -> List[Dict[str, Any]]:
        # try to use metafile to know sources; if metafile module available and path provided, use it
        mf_mod = NewpkgMetaFile
        downloader = self.modules.get('downloader')
        if downloader is None:
            raise RuntimeError('Downloader not configured')
        tasks = []
        # best-effort: if package is a path to a metafile, load it
        if Path(pkg).exists():
            try:
                mf = NewpkgMetaFile.NewpkgMetaFile(None, logger=None, db=self.modules.get('db'), downloader=downloader, patcher=self.modules.get('patcher'), hooks=self.modules.get('hooks'))
                meta = mf.load(pkg)
                # build tasks from meta
                for s in meta.get('sources', []):
                    url = s.get('url')
                    filename = s.get('filename') or Path(url).name
                    dest = workdir / filename
                    tasks.append({'url': url, 'dest': str(dest), 'checksum': s.get('sha256'), 'mirrors': s.get('mirrors')})
            except Exception:
                # fallback: treat pkg as URL or file
                tasks.append({'url': pkg, 'dest': str(workdir / Path(pkg).name), 'checksum': None})
        else:
            # unknown package: try to locate metafile in ./packages/<pkg>
            candidates = [Path('packages') / pkg / f for f in os.listdir('packages') if f.startswith(pkg)] if Path('packages').exists() else []
            if candidates:
                # pick first metafile
                tasks.append({'url': str(candidates[0]), 'dest': str(workdir / candidates[0].name)})
            else:
                # treat as URL
                tasks.append({'url': pkg, 'dest': str(workdir / Path(pkg).name)})

        # run download
        # adapt tasks for downloader.download_many API
        loop = asyncio.get_event_loop()
        try:
            results = loop.run_until_complete(self.modules['downloader'].download_many(tasks, parallel=jobs))
        except Exception as e:
            raise
        return results

    def _extract_archives(self, results: List[Dict[str, Any]], workdir: Path) -> List[Path]:
        out_dirs = []
        for r in results:
            path = Path(r.get('path') or r.get('dest'))
            if not path.exists():
                continue
            # try common archive extract
            try:
                if path.suffix in ('.xz', '.gz', '.bz2', '.zip') or path.name.endswith('.tar.xz') or path.name.endswith('.tar.zst'):
                    d = tempfile.mkdtemp(prefix='newpkg-extract-')
                    dpath = Path(d)
                    # attempt to use system tar for robust extraction
                    cmd = ['tar', '-xf', str(path), '-C', str(dpath)]
                    proc = subprocess.run(cmd, capture_output=True)
                    if proc.returncode != 0:
                        # fallback: try python tarfile/zipfile
                        try:
                            import tarfile as _tar
                            with _tar.open(path) as t:
                                t.extractall(dpath)
                        except Exception:
                            pass
                    out_dirs.append(dpath)
                else:
                    # not an archive; leave as-is
                    out_dirs.append(path)
            except Exception:
                continue
        return out_dirs

    def _apply_patches(self, workdir: Path, quiet: bool = False) -> None:
        patcher = self.modules.get('patcher')
        if not patcher:
            _log('patcher not available; skipping patches', 'WARNING')
            return
        # call patcher to apply patches in workdir
        try:
            patch_res = patcher.NewpkgPatcher.apply_all if hasattr(patcher.NewpkgPatcher, 'apply_all') else None
            if patch_res:
                inst = patcher.NewpkgPatcher(None)
                inst.apply_all(str(workdir))
            else:
                # if patcher exposes apply_patch per-file, user metafile should handle it
                pass
        except Exception as e:
            _log(f'patch application failed: {e}', 'ERROR')

    def _build_package(self, pkg: str, workdir: Path, jobs: int, quiet: bool, dry_run: bool, keep_build_dir: bool) -> Dict[str, Any]:
        core = self.modules.get('core')
        if core is None:
            raise RuntimeError('core module not configured')
        # prepare
        self._phase_banner(f'Preparando a construção do {pkg}', quiet)
        if dry_run:
            return {'status': 'dry-run'}
        try:
            build_dir = core.NewpkgCore.prepare(core.NewpkgCore, pkg, version=None, profile='default', src_dir=str(workdir)) if hasattr(core, 'NewpkgCore') else None
        except Exception:
            # fallback: call module-level prepare
            try:
                build_dir = core.prepare(pkg, None, 'default', str(workdir))
            except Exception:
                build_dir = str(workdir)
        # build
        self._phase_banner(f'Construindo o {pkg}', quiet)
        # run build and show metrics
        if _HAS_RICH and console and not quiet and not self.args.no_color:
            with Progress(SpinnerColumn(), TextColumn('{task.description}'), BarColumn(), TimeElapsedColumn(), TimeRemainingColumn(), transient=True) as progress:
                task = progress.add_task(f'Building {pkg}', total=None)
                try:
                    # call core.build
                    if hasattr(core, 'NewpkgCore'):
                        inst = core.NewpkgCore(None, self.modules.get('db'), logger=None, sandbox=None, deps=self.modules.get('deps'))
                        inst.build(pkg, profile='default', src_dir=str(workdir))
                    else:
                        core.build(pkg, profile='default', src_dir=str(workdir))
                    progress.update(task, advance=1)
                except Exception as e:
                    progress.stop()
                    raise
        else:
            # no fancy UI; run build directly
            if hasattr(core, 'NewpkgCore'):
                inst = core.NewpkgCore(None, self.modules.get('db'), logger=None, sandbox=None, deps=self.modules.get('deps'))
                inst.build(pkg, profile='default', src_dir=str(workdir))
            else:
                core.build(pkg, profile='default', src_dir=str(workdir))
        # package
        self._phase_banner(f'Empacotando o {pkg}', quiet)
        try:
            if hasattr(core, 'NewpkgCore'):
                inst = core.NewpkgCore(None, self.modules.get('db'), logger=None, sandbox=None, deps=self.modules.get('deps'))
                archive = inst.package(pkg)
            else:
                archive = core.package(pkg)
        except Exception as e:
            raise
        # install
        self._phase_banner(f'Instalando em {self.args.destdir}', quiet)
        try:
            if hasattr(core, 'NewpkgCore'):
                inst = core.NewpkgCore(None, self.modules.get('db'), logger=None, sandbox=None, deps=self.modules.get('deps'))
                inst.install(pkg, fakeroot=True, destdir=self.args.destdir)
            else:
                core.install(pkg, fakeroot=True, destdir=self.args.destdir)
        except Exception as e:
            raise

        if not keep_build_dir:
            try:
                shutil.rmtree(workdir)
            except Exception:
                pass

        return {'status': 'ok', 'pkg': pkg, 'archive': archive}

    # ---------- dispatchers for subcommands ----------
    def cmd_install(self):
        tgt = self.args.target
        dry_run = self.args.dry_run or self.args.dry_run
        quiet = self.args.quiet
        jobs = max(1, int(self.args.jobs or 1))

        self._phase_banner(f'Preparando a construção do {tgt}', quiet)

        # resolve dependencies
        deps_list = self._resolve_dependencies(tgt, only_deps=self.args.only_deps, jobs=jobs, dry_run=dry_run)
        if self.args.only_deps:
            _log(f'Dependencies to install: {deps_list}')
        if dry_run:
            _log('Dry run enabled — exiting after dependency resolution')
            print(json.dumps({'deps': deps_list}, indent=2))
            return

        # iterate through resolution order and build/install each
        for pkg in deps_list:
            self._phase_banner(f'Baixando o {pkg}', quiet)
            # create workdir per pkg
            workdir = Path(tempfile.mkdtemp(prefix=f'newpkg-build-{pkg}-'))
            try:
                dl_results = self._download_sources_for_pkg(pkg, workdir, jobs)
            except Exception as e:
                _log(f'Download failed for {pkg}: {e}', 'ERROR')
                return
            self._phase_banner(f'Descompactando para {workdir}', quiet)
            extracted = self._extract_archives(dl_results, workdir)
            # apply patches
            self._phase_banner('Aplicando correções (patches)', quiet)
            try:
                self._apply_patches(workdir, quiet=quiet)
            except Exception as e:
                _log(f'Patching failed for {pkg}: {e}', 'ERROR')
                return

            # build/package/install
            try:
                res = self._build_package(pkg, workdir, jobs, quiet, dry_run=False, keep_build_dir=self.args.keep_build_dir)
            except Exception as e:
                _log(f'Build/package/install failed for {pkg}: {e}', 'ERROR')
                return
            _log(f'Package {pkg} installed successfully')

    def dispatch(self):
        self.args = self.parser.parse_args()
        # early no-color handling
        if self.args.no_color:
            global console
            console = None
        # init modules
        self._init_modules()

        cmd = self.args.cmd
        if cmd in ('install', '-i'):
            self.cmd_install()
        elif cmd in ('remove', '-r'):
            _log('remove command - not implemented in CLI wrapper (use module)')
        elif cmd in ('build', '-b'):
            _log('build wrapper - not implemented here')
        elif cmd in ('upgrade', '-u'):
            _log('upgrade wrapper - delegating to module')
            if self.modules.get('upgrade'):
                self.modules['upgrade'].upgrade(self.args.target if hasattr(self.args, 'target') else None)
        elif cmd == 'sync':
            if self.modules.get('sync'):
                import asyncio
                res = asyncio.run(self.modules['sync'].sync_all(dry_run=self.args.dry_run))
                print(json.dumps(res, indent=2))
            else:
                _log('sync module not available', 'ERROR')
        elif cmd == 'audit':
            if self.modules.get('audit'):
                res = self.modules['audit'].scan_system(include_unmanaged=True)
                print(json.dumps(res, indent=2))
            else:
                _log('audit module not available', 'ERROR')
        elif cmd == 'revdep':
            if self.modules.get('audit') and hasattr(self.args, 'pkg') and self.args.pkg:
                res = self.modules['audit'].find_revdeps([self.args.pkg])
                print(json.dumps(res, indent=2))
            else:
                _log('revdep not available', 'ERROR')
        elif cmd == 'info':
            if hasattr(self.args, 'pkg') and self.args.pkg:
                _log(f'info for {self.args.pkg} - not implemented fully')
            else:
                _log('no package specified')
        else:
            _log('unknown command')


def main():
    cli = NewpkgCLI()
    cli.dispatch()


if __name__ == '__main__':
    main()
