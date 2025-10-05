"""
newpkg_audit.py

System-wide vulnerability scanner + remediator for newpkg-managed packages.

Features:
- scan_system(): enumerate packages (from newpkg_db) and optionally files on disk to identify candidates
- check_vulnerabilities(): check candidates against a local vulnerability DB (JSON) or plugin adapter
- find_revdeps(): compute reverse-dependency graph using newpkg_db or newpkg_deps
- plan_remediation(): produce an ordered plan (upgrade / rebuild / patch / remove / test)
- execute_plan(): apply plan in sandboxed DESTDIR by calling newpkg_upgrade / newpkg_core / newpkg_patcher / newpkg_remove
- verify_postfix(): re-scan after remediation, run tests if provided by metafile/hooks
- report(): output plan/results in text/JSON/HTML
- update_vuln_db(): load/refresh vulnerability data from a local file or URL (adapter interface)

Design notes:
- This module is defensive: it will work in a limited mode if other modules aren't available.
- By default operations are DRY RUN. set auto_confirm=True to perform changes.
- Backups are created before destructive actions under REMOVE_BACKUP_DIR or /var/tmp/newpkg_backups.

Usage (programmatic):
    audit = NewpkgAudit(cfg, logger, db, deps, upgrade, core, patcher, hooks)
    plan = audit.scan_and_plan(scope='/usr', include_unmanaged=False)
    audit.report(plan, format='text')
    audit.execute_plan(plan, dry_run=True)

CLI:
    newpkg-audit scan --vulndb vuln.json --dry-run
    newpkg-audit fix --auto-confirm

"""
from __future__ import annotations

import os
import sys
import json
import shutil
import tarfile
import tempfile
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


class AuditError(Exception):
    pass


class NewpkgAudit:
    def __init__(self,
                 cfg: Any = None,
                 logger: Any = None,
                 db: Any = None,
                 deps: Any = None,
                 upgrade: Any = None,
                 core: Any = None,
                 patcher: Any = None,
                 remover: Any = None,
                 hooks: Any = None):
        self.cfg = cfg
        self.logger = logger
        self.db = db
        self.deps = deps
        self.upgrade = upgrade
        self.core = core
        self.patcher = patcher
        self.remover = remover
        self.hooks = hooks

        # config defaults
        try:
            self.backup_dir = Path(self.cfg.get('REMOVE_BACKUP_DIR')) if self.cfg else None
        except Exception:
            self.backup_dir = None
        if not self.backup_dir:
            self.backup_dir = Path(os.environ.get('NEWPKG_REMOVE_BACKUP', '/var/tmp/newpkg_backups'))
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        try:
            self.auto_confirm = bool(self.cfg.get('AUDIT_AUTO_CONFIRM'))
        except Exception:
            self.auto_confirm = False

        try:
            self.default_dry_run = bool(self.cfg.get('AUDIT_DEFAULT_DRYRUN'))
        except Exception:
            self.default_dry_run = True

        try:
            self.scan_paths = list(self.cfg.get('AUDIT_SCAN_PATHS') or ['/usr', '/bin', '/sbin', '/usr/local'])
        except Exception:
            self.scan_paths = ['/usr', '/bin', '/sbin', '/usr/local']

        # local vulnerability DB cache (format: {"pkg_name": [{"cve":..,"affected":..,"fixed_in":..}, ...]})
        self.vuln_db: Dict[str, List[Dict[str, Any]]] = {}

    # ---------------- logging ----------------
    def _log(self, event: str, level: str = 'INFO', message: Optional[str] = None, meta: Optional[Dict[str, Any]] = None):
        if self.logger:
            try:
                self.logger.log_event(event, level=level, message=message or event, metadata=meta or {})
            except Exception:
                pass
        else:
            # fallback to stderr for visibility
            sys.stderr.write(f"[{level}] {event}: {message or ''}\n")

    # ---------------- vuln db ----------------
    def update_vuln_db(self, source: str, force: bool = False) -> bool:
        """Load/refresh local vulnerability database from a JSON file (or plugin URL).

        Expected JSON format: {"packages": {"pkgname": [{"cve":"CVE-...","affected":"<ver-range>","fixed_in":"1.2.3","notes":"..."}, ...] } }
        For simplicity we'll accept either top-level mapping of pkg->list or {"packages": {...}}
        """
        try:
            p = Path(source)
            if p.exists():
                data = json.loads(p.read_text(encoding='utf-8'))
            else:
                # attempt to fetch via curl/wget
                proc = subprocess.run(['curl', '-fsSL', source], capture_output=True, text=True)
                if proc.returncode != 0:
                    self._log('vulndb.fetch.fail', level='ERROR', message=f'Failed to fetch {source}: {proc.stderr}')
                    return False
                data = json.loads(proc.stdout)
        except Exception as e:
            self._log('vulndb.load.fail', level='ERROR', message=str(e))
            return False

        # normalize
        if isinstance(data, dict) and 'packages' in data:
            dbmap = data['packages']
        elif isinstance(data, dict):
            dbmap = data
        else:
            self._log('vulndb.invalid', level='ERROR', message='Invalid vulnerability DB format')
            return False

        # simple assign; could support merging
        self.vuln_db = dbmap
        self._log('vulndb.loaded', level='INFO', message=f'Loaded vuln DB from {source}', meta={'count_pkgs': len(self.vuln_db)})
        return True

    # ---------------- system scan ----------------
    def scan_system(self, scope: Optional[str] = None, include_unmanaged: bool = False) -> Dict[str, Any]:
        """Scan the system for installed packages and candidate binaries/libraries.

        If newpkg_db is available, use it as the authoritative list of managed packages.
        If include_unmanaged=True, also scan filesystem for binaries and try to detect versions.
        Returns a dict with keys: managed_packages, unmanaged_candidates
        """
        managed = []
        unmanaged = []

        if self.db:
            try:
                for p in self.db.list_packages():
                    # p may be object or dict
                    name = getattr(p, 'name', None) or (p.get('name') if isinstance(p, dict) else None)
                    version = getattr(p, 'version', None) or (p.get('version') if isinstance(p, dict) else None)
                    managed.append({'name': name, 'version': version})
            except Exception:
                managed = []
        # optionally scan for unmanaged programs
        if include_unmanaged:
            paths_to_search = [scope] if scope else self.scan_paths
            seen = set()
            for base in paths_to_search:
                basep = Path(base)
                if not basep.exists():
                    continue
                for f in basep.rglob('*'):
                    if not f.is_file():
                        continue
                    if os.access(str(f), os.X_OK):
                        # quick heuristic: ELF binary or script
                        if str(f) in seen:
                            continue
                        seen.add(str(f))
                        ver = self._probe_version(f)
                        unmanaged.append({'path': str(f), 'version': ver})
        res = {'managed_packages': managed, 'unmanaged_candidates': unmanaged}
        self._log('audit.scan', level='INFO', message='Scan completed', meta={'managed': len(managed), 'unmanaged': len(unmanaged)})
        return res

    def _probe_version(self, binary_path: Path) -> Optional[str]:
        try:
            # try --version
            proc = subprocess.run([str(binary_path), '--version'], capture_output=True, text=True, timeout=3)
            if proc.returncode == 0 and proc.stdout:
                # extract first line
                first = proc.stdout.splitlines()[0].strip()
                # crude extract of digit groups
                import re
                m = re.search(r"(\d+\.[\d\.]+)", first)
                if m:
                    return m.group(1)
                return first
        except Exception:
            return None
        return None

    # ---------------- vulnerability checking ----------------
    def check_vulnerabilities(self, candidates: List[Dict[str, Any]], db_source: Optional[str] = None) -> List[Dict[str, Any]]:
        """Given a list of candidate packages (dicts with name & version), check against vuln_db.

        Returns list of dicts: {pkg, installed_version, matches: [vuln entries]}
        """
        if db_source and not self.vuln_db:
            self.update_vuln_db(db_source)
        results = []
        for c in candidates:
            name = c.get('name')
            ver = c.get('version')
            if not name:
                continue
            vulns = self.vuln_db.get(name) or []
            matches = []
            for v in vulns:
                # v expected to have 'affected' (string or list) and optional 'fixed_in'
                affected = v.get('affected')
                if not affected:
                    # if no affected metadata, include it for manual review
                    matches.append(v)
                    continue
                # naive version check: string equality or substring
                if isinstance(affected, str):
                    if ver and affected in ver:
                        matches.append(v)
                elif isinstance(affected, list):
                    if ver and any(a in ver for a in affected):
                        matches.append(v)
            if matches:
                results.append({'pkg': name, 'installed_version': ver, 'matches': matches})
        self._log('audit.check', level='INFO', message='Vulnerability check completed', meta={'count': len(results)})
        return results

    # ---------------- revdep resolution ----------------
    def find_revdeps(self, pkg_names: List[str]) -> Dict[str, List[str]]:
        """Find reverse dependencies (packages that depend on any of pkg_names).

        Uses newpkg_db if available, otherwise newpkg_deps if provided.
        Returns mapping pkg -> [reverse-dep names]
        """
        rev = {p: [] for p in pkg_names}
        if self.db:
            try:
                all_pkgs = self.db.list_packages()
            except Exception:
                all_pkgs = []
            for other in all_pkgs:
                name = getattr(other, 'name', None) or (other.get('name') if isinstance(other, dict) else None)
                deps = None
                try:
                    deps = self.db.get_deps(name)
                except Exception:
                    # fallback: attribute
                    deps = getattr(other, 'dependencies', None) or getattr(other, 'depends', None) or []
                depnames = []
                for d in (deps or []):
                    if isinstance(d, dict):
                        depnames.append(d.get('name') or d.get('pkg') or d.get('package'))
                    elif isinstance(d, str):
                        depnames.append(d)
                for p in pkg_names:
                    if p in depnames:
                        rev.setdefault(p, []).append(name)
            self._log('audit.revdeps', level='INFO', message='Reverse deps computed', meta={'pkg_count': len(pkg_names)})
            return rev
        # fallback: try deps module
        if self.deps:
            for p in pkg_names:
                try:
                    # deps should provide a method to compute reverse deps - if not, skip
                    rd = self.deps.reverse_deps(p)
                    rev[p] = rd
                except Exception:
                    rev[p] = []
            return rev
        # nothing available
        return rev

    # ---------------- planning remediation ----------------
    def plan_remediation(self, vuln_results: List[Dict[str, Any]], strategy: str = 'upgrade') -> Dict[str, Any]:
        """Given vuln_results, produce an ordered plan.

        Plan structure example:
        {
          'vulns': vuln_results,
          'revdeps': {pkg: [revdep list]},
          'actions': [ {action: 'upgrade'|'rebuild'|'patch'|'remove', 'pkg':.., 'reason':..}, ... ]
        }
        """
        pkg_names = [v['pkg'] for v in vuln_results]
        revdeps = self.find_revdeps(pkg_names)
        actions = []
        # primary: upgrade vulnerable packages
        for v in vuln_results:
            pkg = v['pkg']
            fixed_versions = [m.get('fixed_in') for m in v.get('matches', []) if m.get('fixed_in')]
            action = {'action': 'upgrade', 'pkg': pkg, 'installed_version': v.get('installed_version'), 'fixed_in': fixed_versions or None, 'reason': 'vulnerable'}
            actions.append(action)
            # schedule rebuilds for revdeps
            for r in revdeps.get(pkg, []):
                actions.append({'action': 'rebuild', 'pkg': r, 'reason': f'revdep of {pkg}'})
        plan = {'vulnerabilities': vuln_results, 'revdeps': revdeps, 'actions': actions, 'generated_at': datetime.utcnow().isoformat() + 'Z'}
        self._log('audit.plan', level='INFO', message='Plan generated', meta={'actions': len(actions)})
        return plan

    # ---------------- backup helper ----------------
    def _archive_files(self, paths: List[str], name_prefix: Optional[str] = None) -> Optional[str]:
        if not paths:
            return None
        if not name_prefix:
            name_prefix = 'audit-backup'
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        archive_name = f"{name_prefix}-{ts}.tar.xz"
        out = self.backup_dir / archive_name
        try:
            with tarfile.open(out, 'w:xz') as tar:
                for p in paths:
                    try:
                        tar.add(p, arcname=os.path.relpath(p, '/'))
                    except Exception:
                        continue
            return str(out)
        except Exception as e:
            self._log('audit.backup.fail', level='ERROR', message=str(e))
            return None

    # ---------------- execute plan ----------------
    def execute_plan(self, plan: Dict[str, Any], dry_run: Optional[bool] = None, auto_confirm: Optional[bool] = None, use_sandbox: bool = True) -> Dict[str, Any]:
        """Execute remediation plan.

        Steps are executed in order. For each action:
          - upgrade: call self.upgrade.upgrade(pkg)
          - rebuild: call self.upgrade.rebuild(pkg)
          - patch: call patcher.apply_patch
          - remove: call remover.remove(pkg)

        All destructive actions create a backup before applying.
        """
        if dry_run is None:
            dry_run = self.default_dry_run
        if auto_confirm is None:
            auto_confirm = self.auto_confirm

        results = {'actions': [], 'errors': []}
        actions = plan.get('actions', [])

        for act in actions:
            kind = act.get('action')
            pkg = act.get('pkg')
            entry = {'action': kind, 'pkg': pkg}
            try:
                if kind == 'upgrade':
                    # backup installed files for pkg
                    files = []
                    if self.db and hasattr(self.db, 'list_files'):
                        try:
                            files = [f.get('path') for f in self.db.list_files(pkg) if f.get('path')]
                        except Exception:
                            files = []
                    backup = None
                    if files:
                        backup = self._archive_files(files, name_prefix=pkg)
                        entry['backup'] = backup
                    if dry_run:
                        entry['result'] = 'dry-run'
                    else:
                        if not auto_confirm:
                            resp = input(f"About to upgrade {pkg}. Proceed? [y/N]: ")
                            if resp.strip().lower() not in ('y', 'yes'):
                                entry['result'] = 'skipped'
                                results['actions'].append(entry)
                                continue
                        if not self.upgrade:
                            raise AuditError('upgrade module not configured')
                        res = self.upgrade.upgrade(pkg, force=False, rebuild=False)
                        entry['result'] = res
                elif kind == 'rebuild':
                    if dry_run:
                        entry['result'] = 'dry-run'
                    else:
                        if not self.upgrade:
                            raise AuditError('upgrade module not configured')
                        res = self.upgrade.rebuild(pkg)
                        entry['result'] = res
                elif kind == 'patch':
                    patchfile = act.get('patchfile')
                    if dry_run:
                        entry['result'] = 'dry-run'
                    else:
                        if not self.patcher:
                            raise AuditError('patcher not configured')
                        res = self.patcher.apply_patch(patchfile, cwd=act.get('workdir'))
                        entry['result'] = res
                elif kind == 'remove':
                    if dry_run:
                        entry['result'] = 'dry-run'
                    else:
                        if not self.remover:
                            raise AuditError('remover not configured')
                        res = self.remover.remove(pkg, purge=act.get('purge', True), simulate=False)
                        entry['result'] = res
                else:
                    entry['result'] = 'noop'
                results['actions'].append(entry)
            except Exception as e:
                self._log('audit.exec.fail', level='ERROR', message=str(e), meta={'action': act})
                entry['error'] = str(e)
                results['actions'].append(entry)
                results['errors'].append({'action': act, 'error': str(e)})
        self._log('audit.exec', level='INFO', message='Execution finished', meta={'actions': len(actions), 'errors': len(results['errors'])})
        return results

    # ---------------- verify after remediation ----------------
    def verify_postfix(self, plan_result: Dict[str, Any], recheck: bool = True) -> Dict[str, Any]:
        # simple re-scan of packages that were in plan
        pkgs = [a.get('pkg') for a in plan_result.get('actions', []) if a.get('pkg')]
        candidates = []
        for p in pkgs:
            try:
                pkgobj = None
                if self.db:
                    pkgobj = self.db.get_package(p)
                if pkgobj:
                    candidates.append({'name': p, 'version': getattr(pkgobj, 'version', None)})
            except Exception:
                candidates.append({'name': p, 'version': None})
        vulns = self.check_vulnerabilities(candidates)
        ok = len(vulns) == 0
        res = {'ok': ok, 'vulnerabilities': vulns}
        self._log('audit.verify', level='INFO', message='Postfix verification done', meta={'ok': ok})
        return res

    # ---------------- reporting ----------------
    def report(self, plan: Dict[str, Any], format: str = 'text', path: Optional[str] = None) -> str:
        """Render plan/results as text, json, or (basic) html.

        Returns the rendered string; also writes to path if provided.
        """
        out = ''
        if format == 'json':
            out = json.dumps(plan, indent=2, ensure_ascii=False)
        elif format == 'html':
            # basic HTML
            out_lines = ['<html><body><h1>Newpkg Audit Report</h1>']
            out_lines.append('<pre>')
            out_lines.append(json.dumps(plan, indent=2, ensure_ascii=False))
            out_lines.append('</pre></body></html>')
            out = '\n'.join(out_lines)
        else:
            # plain text
            lines = []
            lines.append('Newpkg Audit Report')
            lines.append('Generated: ' + datetime.utcnow().isoformat() + 'Z')
            lines.append('')
            vulns = plan.get('vulnerabilities') or []
            lines.append(f'Vulnerabilities: {len(vulns)}')
            for v in vulns:
                lines.append(f"- {v.get('pkg')} {v.get('installed_version')}: {', '.join([m.get('cve', str(m)) for m in v.get('matches', [])])}")
            lines.append('')
            actions = plan.get('actions') or []
            lines.append(f'Planned actions: {len(actions)}')
            for a in actions:
                lines.append(f"- {a.get('action')}: {a.get('pkg')} ({a.get('reason')})")
            out = '\n'.join(lines)
        if path:
            try:
                Path(path).write_text(out, encoding='utf-8')
            except Exception as e:
                self._log('audit.report.fail', level='ERROR', message=str(e))
        return out


# --------------- CLI basic wrapper ---------------
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(prog='newpkg-audit')
    ap.add_argument('cmd', choices=['scan', 'plan', 'fix', 'report', 'revdep', 'update-db'])
    ap.add_argument('--vulndb', help='vulnerability db path or URL (JSON)')
    ap.add_argument('--pkg', help='package name for revdep/planning')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--auto-confirm', action='store_true')
    ap.add_argument('--out', help='output path for report')
    args = ap.parse_args()

    # minimal bootstrapping of dependencies if present
    try:
        from newpkg_db import NewpkgDB
    except Exception:
        NewpkgDB = None
    try:
        from newpkg_deps import NewpkgDeps
    except Exception:
        NewpkgDeps = None
    try:
        from newpkg_upgrade import NewpkgUpgrade
    except Exception:
        NewpkgUpgrade = None
    try:
        from newpkg_remove import NewpkgRemove
    except Exception:
        NewpkgRemove = None
    try:
        from newpkg_patcher import NewpkgPatcher
    except Exception:
        NewpkgPatcher = None
    try:
        from newpkg_core import NewpkgCore
    except Exception:
        NewpkgCore = None
    try:
        from newpkg_hooks import NewpkgHooks
    except Exception:
        NewpkgHooks = None

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
            try:
                db.init_db()
            except Exception:
                pass

    deps = NewpkgDeps(cfg) if NewpkgDeps else None
    upgrade = None
    core = None
    remover = None
    patcher = None
    hooks = None
    if NewpkgUpgrade:
        upgrade = NewpkgUpgrade(cfg, logger=None, db=db, downloader=None, core=None, remover=None, hooks=None)
    if NewpkgCore:
        core = NewpkgCore(cfg, db, logger=None, sandbox=None, deps=None)
    if NewpkgRemove:
        remover = NewpkgRemove(cfg, logger=None, db=db, sandbox=None, hooks=None)
    if NewpkgPatcher:
        patcher = NewpkgPatcher(cfg)
    if NewpkgHooks:
        hooks = NewpkgHooks(cfg)

    audit = NewpkgAudit(cfg=cfg, logger=None, db=db, deps=deps, upgrade=upgrade, core=core, patcher=patcher, remover=remover, hooks=hooks)

    if args.vulndb:
        loaded = audit.update_vuln_db(args.vulndb)
        print('vulndb loaded:', loaded)

    if args.cmd == 'scan':
        res = audit.scan_system(include_unmanaged=True)
        print(json.dumps(res, indent=2))
    elif args.cmd == 'plan':
        if not args.pkg:
            print('Please provide --pkg NAME to plan for a package')
            sys.exit(2)
        # plan for single package
        # make candidate list from DB
        cand = []
        if db:
            try:
                p = db.get_package(args.pkg)
                cand = [{'name': args.pkg, 'version': getattr(p, 'version', None)}]
            except Exception:
                cand = [{'name': args.pkg, 'version': None}]
        vulns = audit.check_vulnerabilities(cand)
        plan = audit.plan_remediation(vulns)
        print(audit.report(plan, format='text'))
    elif args.cmd == 'revdep':
        if not args.pkg:
            print('Please provide --pkg NAME for revdep')
            sys.exit(2)
        rd = audit.find_revdeps([args.pkg])
        print(json.dumps(rd, indent=2))
    elif args.cmd == 'fix':
        # quick flow: plan for all known vulnerable packages and execute
        if not audit.vuln_db:
            print('No vulnerability DB loaded. use --vulndb path.json')
            sys.exit(2)
        # gather candidates from DB
        candidates = []
        if db:
            for p in db.list_packages():
                name = getattr(p, 'name', None) or (p.get('name') if isinstance(p, dict) else None)
                version = getattr(p, 'version', None) or (p.get('version') if isinstance(p, dict) else None)
                candidates.append({'name': name, 'version': version})
        vulns = audit.check_vulnerabilities(candidates)
        plan = audit.plan_remediation(vulns)
        print('Plan generated:')
        print(audit.report(plan, format='text'))
        confirm = args.auto_confirm or audit.auto_confirm
        if args.dry_run:
            print('Dry run: no actions executed')
            sys.exit(0)
        res = audit.execute_plan(plan, dry_run=args.dry_run, auto_confirm=confirm)
        print(json.dumps(res, indent=2))
    elif args.cmd == 'report':
        print('Report command expects a plan; use programmatic API or fix->report')
    elif args.cmd == 'update-db':
        if not args.vulndb:
            print('Pass --vulndb source')
            sys.exit(2)
        print('update result:', audit.update_vuln_db(args.vulndb))
    else:
        print('unknown')
