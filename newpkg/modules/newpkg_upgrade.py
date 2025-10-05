"""
newpkg_upgrade.py

Gerencia upgrades de pacotes no ecossistema newpkg.

Funcionalidades implementadas:
- check_updates(pkg_name): verifica se há versão mais recente (a partir de metadata no DB ou a partir de source_url/git)
- fetch_new_source(pkg_name): usa NewpkgDownloader para baixar novas fontes
- upgrade(pkg_name): fluxo completo (pre_upgrade hook, fetch, build via NewpkgCore, package, remove old via NewpkgRemove, deploy/install, post_upgrade hook)
- batch_upgrade(pkg_list, parallel=True): executa upgrades em paralelo usando ThreadPool
- rebuild(pkg_name): reconstrói a versão atual (ou a nova) em sandbox
- rollback(pkg_name, archive_path): restaura backup criado anteriormente (integra com NewpkgRemove.rollback)
- diff_versions(pkg_name, old_version, new_version): apresenta diffs entre pkginfo (metadados)
- verify_integrity(pkg_name): verifica checksums registrados
- clean_old_versions(pkg_name, keep=1): remove pacotes antigos pelo DB
- update_db(pkg_name, version, status): atualiza DB com nova versão/status

Este módulo assume a presença das seguintes abstrações criadas anteriormente:
 - NewpkgDownloader (downloader.download / clone_git)
 - NewpkgCore (prepare, build, install, package, deploy, record)
 - NewpkgRemove (remove/purge/rollback)
 - NewpkgHooks (run/execute_safe)
 - newpkg_db API (get_package, get_package_latest_source, add_package, update_package_status, list_package_versions, add_log)
 - newpkg_sandbox (used indiretamente via core and hooks)

O código tenta ser defensivo: registra logs, cria backups antes de mudanças destrutivas e realiza rollback em erro.

"""
from __future__ import annotations

import os
import shutil
import json
import tempfile
import subprocess
import concurrent.futures
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


class UpgradeError(Exception):
    pass


class NewpkgUpgrade:
    def __init__(self, cfg: Any, logger: Any = None, db: Any = None, downloader: Any = None, core: Any = None, remover: Any = None, hooks: Any = None, deps: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.logger = logger
        self.db = db
        self.downloader = downloader
        self.core = core
        self.remover = remover
        self.hooks = hooks
        self.deps = deps
        self.sandbox = sandbox

        # configuration defaults
        try:
            self.auto_backup = bool(self.cfg.get('upgrade.backup_before_upgrade'))
        except Exception:
            self.auto_backup = True
        try:
            self.parallel = bool(self.cfg.get('upgrade.parallel'))
        except Exception:
            self.parallel = True
        try:
            self.clean_old = bool(self.cfg.get('upgrade.clean_old'))
        except Exception:
            self.clean_old = True
        try:
            self.use_sandbox = bool(self.cfg.get('upgrade.sandbox'))
        except Exception:
            self.use_sandbox = True

    # ---------------- logging ----------------
    def _log(self, event: str, level: str = 'INFO', message: Optional[str] = None, meta: Optional[Dict[str, Any]] = None):
        if self.logger:
            self.logger.log_event(event, level=level, message=message or event, metadata=meta or {})

    # ---------------- utilities ----------------
    def _now(self) -> str:
        return datetime.utcnow().isoformat() + 'Z'

    def _pkginfo_path(self, pkg_name: str, version: Optional[str] = None) -> Optional[Path]:
        # try to find pkginfo in package_dir produced by NewpkgCore
        try:
            pkgdir = self.core._pkg_package_dir(pkg_name, version)
            p = Path(pkgdir) / 'pkginfo.json'
            if p.exists():
                return p
        except Exception:
            pass
        return None

    # ---------------- check updates ----------------
    def check_updates(self, pkg_name: str) -> Dict[str, Any]:
        """Verifica se há nova versão disponível para pkg_name.

        Estratégia:
          - consulta newpkg_db.get_package(pkg_name) para ver source_url/git/tag metadata
          - se houver source_url apontando para git, procura por tags ou HEAD commit diferentes
          - se houver source_url com um URL contendo versão, tenta inferir nova versão (heurística)

        Retorna dict: {'update': True/False, 'current_version': x, 'candidate_version': y, 'reason': str}
        """
        pkg = None
        try:
            pkg = self.db.get_package(pkg_name)
        except Exception:
            # fallback: try list_packages
            for p in getattr(self.db, 'list_packages', lambda: [])():
                if getattr(p, 'name', None) == pkg_name:
                    pkg = p
                    break
        if not pkg:
            raise UpgradeError(f'Package not found in DB: {pkg_name}')

        current_version = getattr(pkg, 'version', None)
        candidate_version = None
        reason = 'no-source'

        # try to get source metadata from DB
        source_meta = None
        try:
            source_meta = self.db.get_package_source(pkg_name)
        except Exception:
            # not available
            source_meta = None

        # if git URL provided, attempt to detect latest tag
        if source_meta and source_meta.get('type') == 'git' and source_meta.get('url'):
            git_url = source_meta.get('url')
            try:
                # shallow ls-remote --tags
                proc = subprocess.run(['git', 'ls-remote', '--tags', git_url], capture_output=True, text=True)
                if proc.returncode == 0 and proc.stdout:
                    # parse tags, pick highest semver-like tag (heuristic)
                    tags = [line.split('\t')[1] for line in proc.stdout.splitlines() if '\trefs/tags/' in line]
                    tags = [t.replace('refs/tags/', '').strip() for t in tags]
                    # prefer annotated tag names without ^{}
                    tags = [t.replace('^{}', '') for t in tags]
                    tags_sorted = sorted(tags, reverse=True)
                    if tags_sorted:
                        candidate_version = tags_sorted[0]
                        reason = 'git-tags'
            except Exception:
                pass

        # if http/ftp source with version in URL, attempt to find latest by checking mirrors metadata (best-effort)
        if not candidate_version and source_meta and source_meta.get('url') and (source_meta.get('type') in ('http', 'ftp', 'http(s)')):
            # heuristic: if url contains version number, try to bump and check existence (not implemented deeply)
            reason = 'no-heuristic'

        update = False
        if candidate_version and candidate_version != current_version:
            update = True

        res = {'update': update, 'current_version': current_version, 'candidate_version': candidate_version, 'reason': reason}
        self._log('upgrade.check', level='INFO', message='Checked updates', meta={'pkg': pkg_name, **res})
        return res

    # ---------------- fetch new source ----------------
    def fetch_new_source(self, pkg_name: str, dest: Optional[Path] = None) -> Dict[str, Any]:
        """Baixa novas fontes para pkg_name usando newpkg_downloader.

        Retorna metadata com caminho para sources (dir or archive) e status.
        """
        try:
            source_meta = self.db.get_package_source(pkg_name)
        except Exception:
            source_meta = None
        if not source_meta:
            raise UpgradeError('No source metadata available')

        dest = Path(dest) if dest else Path(tempfile.mkdtemp(prefix=f'newpkg-src-{pkg_name}-'))
        dest.mkdir(parents=True, exist_ok=True)

        if source_meta.get('type') == 'git':
            url = source_meta.get('url')
            branch = source_meta.get('branch')
            self._log('upgrade.fetch', level='INFO', message='Cloning git source', meta={'pkg': pkg_name, 'url': url})
            res = self.downloader.clone_git(url, dest, branch=branch, shallow=True)
            return {'status': res.get('status'), 'path': res.get('dest')}

        # otherwise assume URL or mirrors
        urls = [source_meta.get('url')] if source_meta.get('url') else []
        mirrors = source_meta.get('mirrors') or []
        if not urls:
            raise UpgradeError('No URL to download')
        filename = Path(urls[0]).name
        outpath = dest / filename
        coro = self.downloader.download(urls, outpath, mirrors=mirrors)
        # downloader is async; run loop if needed
        try:
            import asyncio
            res = asyncio.run(coro)
        except Exception as e:
            raise UpgradeError(f'Download failed: {e}')
        if res.get('status') != 'ok':
            raise UpgradeError(f'Download failed: {res}')
        # if archive, optionally extract to dest/sources
        if outpath.suffix in ('.xz', '.gz', '.bz2', '.zip', '.tar') or outpath.name.endswith('.tar.xz') or outpath.name.endswith('.tar.zst'):
            extract_dir = dest / 'sources'
            extract_dir.mkdir(parents=True, exist_ok=True)
            ex = self.downloader.extract_archive(Path(res['path']), extract_dir)
            if ex.get('status') != 'ok':
                return {'status': 'ok', 'path': res['path'], 'extracted': False}
            return {'status': 'ok', 'path': str(extract_dir)}
        return {'status': 'ok', 'path': res['path']}

    # ---------------- core upgrade flow ----------------
    def upgrade(self, pkg_name: str, force: bool = False, rebuild: bool = False, profile: str = 'default') -> Dict[str, Any]:
        """Fluxo completo de upgrade para um pacote.

        Passos:
         - check_updates (unless force)
         - fetch_new_source
         - run pre_upgrade hooks
         - build (core.build)
         - install/package
         - backup old version and remove it via NewpkgRemove
         - deploy new version (core.deploy or core.install)
         - run post_upgrade hooks
         - update DB
        """
        self._log('upgrade.start', level='INFO', message='Upgrade started', meta={'pkg': pkg_name})

        # get current package information
        try:
            pkg = self.db.get_package(pkg_name)
        except Exception:
            pkg = None
        current_version = getattr(pkg, 'version', None) if pkg else None

        # if not force, check updates
        if not force:
            chk = self.check_updates(pkg_name)
            if not chk.get('update'):
                return {'status': 'noop', 'reason': 'no-update', 'pkg': pkg_name}

        # fetch
        try:
            fetch_meta = self.fetch_new_source(pkg_name)
        except Exception as e:
            self._log('upgrade.fetch.fail', level='ERROR', message=str(e), meta={'pkg': pkg_name})
            raise UpgradeError(f'Fetch failed: {e}')

        src_path = Path(fetch_meta.get('path'))

        # run pre_upgrade hook
        try:
            if self.hooks:
                self.hooks.execute_safe('pre_upgrade', pkg_name=pkg_name, build_dir=src_path)
        except Exception:
            pass

        # prepare build dir via core.prepare
        try:
            build_dir = self.core.prepare(pkg_name, version=None, profile=profile, src_dir=src_path)
        except Exception as e:
            raise UpgradeError(f'Prepare failed: {e}')

        # resolve build deps
        try:
            if self.deps:
                bdeps = self.deps.resolve(pkg_name, dep_type='build')
                self._log('upgrade.deps', level='INFO', message='Resolved build deps', meta={'pkg': pkg_name, 'deps': bdeps})
        except Exception:
            pass

        # run build
        try:
            self.core.build(pkg_name, profile=profile, src_dir=src_path)
        except Exception as e:
            self._log('upgrade.build.fail', level='ERROR', message=str(e), meta={'pkg': pkg_name})
            # run on_error hooks
            if self.hooks:
                self.hooks.execute_safe('on_error', pkg_name=pkg_name, build_dir=build_dir)
            raise UpgradeError(f'Build failed: {e}')

        # install into destdir via core.install (fakeroot)
        try:
            self.core.install(pkg_name, fakeroot=True)
        except Exception as e:
            self._log('upgrade.install.fail', level='ERROR', message=str(e), meta={'pkg': pkg_name})
            if self.hooks:
                self.hooks.execute_safe('on_error', pkg_name=pkg_name, build_dir=build_dir)
            raise UpgradeError(f'Install failed: {e}')

        # package
        try:
            archive = self.core.package(pkg_name)
        except Exception as e:
            self._log('upgrade.package.fail', level='ERROR', message=str(e), meta={'pkg': pkg_name})
            raise UpgradeError(f'Package failed: {e}')

        # backup old version and remove (if present)
        backup_archive = None
        if current_version and self.remover:
            try:
                # create backup by archiving current installed files
                files = [f.get('path') for f in self.db.list_files(pkg_name)] if hasattr(self.db, 'list_files') else []
                if files:
                    backup_archive = self.remover._archive_before_remove(pkg_name, files)
                    self._log('upgrade.backup', level='INFO', message='Backup created', meta={'pkg': pkg_name, 'archive': str(backup_archive)})
                    # remove current version
                    self.remover.remove(pkg_name, purge=False, simulate=False)
            except Exception:
                # warn and continue
                self._log('upgrade.backup.fail', level='WARNING', message='Backup or removal of old version failed', meta={'pkg': pkg_name})

        # deploy new package
        try:
            target = self.cfg.get('NEWPKG_TARGET_ROOT') if self.cfg else '/'
            self.core.deploy(pkg_name, archive=archive, target=target, rollback=True)
        except Exception as e:
            self._log('upgrade.deploy.fail', level='ERROR', message=str(e), meta={'pkg': pkg_name})
            # attempt rollback from backup if possible
            if backup_archive and self.remover:
                try:
                    self.remover.rollback(str(backup_archive))
                except Exception:
                    pass
            raise UpgradeError(f'Deploy failed: {e}')

        # run post_upgrade hooks
        try:
            if self.hooks:
                self.hooks.execute_safe('post_upgrade', pkg_name=pkg_name, build_dir=build_dir)
        except Exception:
            pass

        # record in DB
        try:
            # com nome do pacote e versão extraída do pkginfo
            pkginfo_path = self._pkginfo_path(pkg_name)
            version = None
            if pkginfo_path:
                try:
                    data = json.loads(pkginfo_path.read_text(encoding='utf-8'))
                    version = data.get('version')
                except Exception:
                    version = None
            self.update_db(pkg_name, version or 'unknown', 'installed')
        except Exception:
            pass

        # clean old versions if configured
        if self.clean_old:
            try:
                self.clean_old_versions(pkg_name, keep=1)
            except Exception:
                pass

        self._log('upgrade.finish', level='INFO', message='Upgrade finished', meta={'pkg': pkg_name})
        return {'status': 'ok', 'pkg': pkg_name, 'archive': str(archive)}

    # ---------------- batch upgrade ----------------
    def _upgrade_worker(self, pkg_name: str) -> Dict[str, Any]:
        try:
            return {'pkg': pkg_name, 'result': self.upgrade(pkg_name)}
        except Exception as e:
            return {'pkg': pkg_name, 'error': str(e)}

    def batch_upgrade(self, pkg_list: Optional[List[str]] = None, parallel: Optional[bool] = None) -> List[Dict[str, Any]]:
        if parallel is None:
            parallel = self.parallel
        if pkg_list is None:
            # default: scan DB for packages with available updates
            pkg_list = []
            for p in self.db.list_packages():
                try:
                    chk = self.check_updates(p.name)
                    if chk.get('update'):
                        pkg_list.append(p.name)
                except Exception:
                    continue
        results = []
        if parallel:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(pkg_list)))) as ex:
                futs = {ex.submit(self._upgrade_worker, pkg): pkg for pkg in pkg_list}
                for fut in concurrent.futures.as_completed(futs):
                    try:
                        results.append(fut.result())
                    except Exception as e:
                        results.append({'pkg': futs[fut], 'error': str(e)})
        else:
            for pkg in pkg_list:
                results.append(self._upgrade_worker(pkg))
        return results

    # ---------------- rebuild ----------------
    def rebuild(self, pkg_name: str, profile: str = 'default') -> Dict[str, Any]:
        # rebuild the currently installed version
        try:
            # prepare using installed sources if available, otherwise fetch
            src = None
            try:
                src = self.db.get_package_source(pkg_name)
            except Exception:
                src = None
            if not src:
                # try to fetch
                fetched = self.fetch_new_source(pkg_name)
                src = fetched.get('path')
            # use core to build
            self.core.build(pkg_name, profile=profile, src_dir=Path(src))
            self.core.install(pkg_name, fakeroot=True)
            self._log('upgrade.rebuild', level='INFO', message='Rebuilt package', meta={'pkg': pkg_name})
            return {'status': 'ok', 'pkg': pkg_name}
        except Exception as e:
            self._log('upgrade.rebuild.fail', level='ERROR', message=str(e), meta={'pkg': pkg_name})
            raise UpgradeError(str(e))

    # ---------------- rollback ----------------
    def rollback(self, pkg_name: str, archive_path: str) -> Dict[str, Any]:
        # delegate to remover.rollback
        try:
            res = self.remover.rollback(archive_path)
            self._log('upgrade.rollback', level='INFO', message='Rollback applied', meta={'pkg': pkg_name})
            return res
        except Exception as e:
            self._log('upgrade.rollback.fail', level='ERROR', message=str(e), meta={'pkg': pkg_name})
            raise UpgradeError(str(e))

    # ---------------- diffs ----------------
    def diff_versions(self, pkg_name: str, old_version: str, new_version: str) -> Dict[str, Any]:
        # compare pkginfo.json between versions if available
        try:
            old_info = None
            new_info = None
            old_path = self._pkginfo_path(pkg_name, old_version)
            new_path = self._pkginfo_path(pkg_name, new_version)
            if old_path and old_path.exists():
                old_info = json.loads(old_path.read_text(encoding='utf-8'))
            if new_path and new_path.exists():
                new_info = json.loads(new_path.read_text(encoding='utf-8'))
            return {'old': old_info, 'new': new_info}
        except Exception as e:
            raise UpgradeError(str(e))

    # ---------------- verify integrity ----------------
    def verify_integrity(self, pkg_name: str) -> Dict[str, Any]:
        # walk files from DB and check hashes if available
        try:
            files = self.db.list_files(pkg_name)
        except Exception:
            return {'status': 'error', 'error': 'cannot list files'}
        mismatches = []
        missing = []
        for f in files:
            path = Path(f.get('path'))
            expected = f.get('hash')
            if not path.exists():
                missing.append(str(path))
                continue
            if expected:
                # compute sha256
                import hashlib
                h = hashlib.sha256()
                with path.open('rb') as fh:
                    for chunk in iter(lambda: fh.read(65536), b''):
                        h.update(chunk)
                if h.hexdigest() != expected:
                    mismatches.append({'path': str(path), 'expected': expected, 'got': h.hexdigest()})
        return {'missing': missing, 'mismatches': mismatches}

    # ---------------- clean old versions ----------------
    def clean_old_versions(self, pkg_name: str, keep: int = 1) -> Dict[str, Any]:
        # removes package versions from DB and disk, keeping `keep` most recent
        try:
            versions = []
            for v in self.db.list_package_versions(pkg_name):
                versions.append(v)
        except Exception:
            return {'status': 'error', 'error': 'cannot list versions'}
        # assume versions are dicts with version and created_at
        sorted_versions = sorted(versions, key=lambda x: x.get('created_at', ''), reverse=True)
        to_remove = sorted_versions[keep:]
        removed = []
        failed = []
        for v in to_remove:
            ver = v.get('version')
            try:
                # remove package files and DB entries
                if hasattr(self.remover, 'remove'):
                    self.remover.remove(f'{pkg_name}-{ver}', purge=True, simulate=False)
                # if db provides remove_package_version
                if hasattr(self.db, 'remove_package_version'):
                    self.db.remove_package_version(pkg_name, ver)
                removed.append(ver)
            except Exception as e:
                failed.append({'version': ver, 'error': str(e)})
        return {'removed': removed, 'failed': failed}

    # ---------------- update db ----------------
    def update_db(self, pkg_name: str, version: str, status: str) -> None:
        try:
            if hasattr(self.db, 'add_package'):
                # add or update package
                try:
                    self.db.add_package(pkg_name, version, 1, origin='upgrade', status=status)
                    return
                except Exception:
                    pass
            if hasattr(self.db, 'update_package_status'):
                self.db.update_package_status(pkg_name, status, version=version)
            # fallback: log
            try:
                self.db.add_log(pkg_name, 'upgrade', status, log_path=None)
            except Exception:
                pass
        except Exception:
            pass


# ---------------- CLI demo ----------------
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(prog='newpkg-upgrade')
    ap.add_argument('--pkg', '-p', required=True)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--upgrade', action='store_true')
    ap.add_argument('--batch', action='store_true')
    args = ap.parse_args()

    # minimal stubs if modules not present
    try:
        from newpkg_db import NewpkgDB
    except Exception:
        NewpkgDB = None
    try:
        from newpkg_download import NewpkgDownloader
    except Exception:
        NewpkgDownloader = None
    try:
        from newpkg_core import NewpkgCore
    except Exception:
        NewpkgCore = None
    try:
        from newpkg_remove import NewpkgRemove
    except Exception:
        NewpkgRemove = None
    try:
        from newpkg_hooks import NewpkgHooks
    except Exception:
        NewpkgHooks = None
    try:
        from newpkg_deps import NewpkgDeps
    except Exception:
        NewpkgDeps = None

    cfg = None
    class CfgShim:
        def get(self, k):
            return None
    cfg = CfgShim()

    db = None
    if NewpkgDB is not None:
        dbp = os.environ.get('NEWPKG_DB_PATH')
        if dbp:
            db = NewpkgDB(db_path=dbp)
            db.init_db()

    downloader = NewpkgDownloader() if NewpkgDownloader else None
    core = NewpkgCore(cfg, db, logger=None, sandbox=None, deps=None) if NewpkgCore else None
    remover = NewpkgRemove(cfg, logger=None, db=db, sandbox=None, hooks=None) if NewpkgRemove else None
    hooks = NewpkgHooks(cfg) if NewpkgHooks else None
    deps = NewpkgDeps(cfg, db) if NewpkgDeps else None

    upgr = NewpkgUpgrade(cfg, logger=None, db=db, downloader=downloader, core=core, remover=remover, hooks=hooks, deps=deps)
    if args.check:
        print(upgr.check_updates(args.pkg))
    if args.upgrade:
        print(upgr.upgrade(args.pkg))
    if args.batch:
        print(upgr.batch_upgrade())
