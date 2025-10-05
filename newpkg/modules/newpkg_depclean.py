"""
newpkg_depclean.py

Módulo para identificar e limpar dependências órfãs, pacotes quebrados e oferecer
reconstruções reversas (revdep rebuild) no ecossistema newpkg.

Design goals:
- Integrar com NewpkgDB para leitura/escrita de pacotes e dependências
- Integrar com NewpkgLogger para eventos e métricas
- Integrar com NewpkgSandbox para rebuilds em ambiente seguro
- Suportar dry-run, confirmação interativa e geração de relatório JSON

API principal:
    depclean = NewpkgDepclean(cfg, db, logger, sandbox)
    report = depclean.scan()
    orphans = depclean.orphans()
    plan = depclean.plan(remove=True)
    depclean.execute(plan, interactive=True)

"""
from __future__ import annotations

import json
import sys
import shutil
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from pathlib import Path
from datetime import datetime


class DepcleanError(Exception):
    pass


@dataclass
class DepcleanPlanItem:
    package: str
    reason: str
    action: str  # 'remove' | 'rebuild'
    details: Dict[str, Any]


@dataclass
class DepcleanReport:
    timestamp: str
    summary: Dict[str, Any]
    items: List[DepcleanPlanItem]

    def to_json(self) -> str:
        return json.dumps({
            "timestamp": self.timestamp,
            "summary": self.summary,
            "items": [item.__dict__ for item in self.items],
        }, indent=2, ensure_ascii=False)


class NewpkgDepclean:
    def __init__(self, cfg: Any, db: Any, logger: Any = None, sandbox: Any = None):
        self.cfg = cfg
        self.db = db
        self.logger = logger
        self.sandbox = sandbox

        # config defaults
        self.keep_list = set()
        try:
            keep = self.cfg.get("DEPCLEAN_KEEP")
            if keep:
                # allow comma separated
                if isinstance(keep, str):
                    self.keep_list = set([p.strip() for p in keep.split(",") if p.strip()])
                elif isinstance(keep, (list, tuple, set)):
                    self.keep_list = set(keep)
        except Exception:
            self.keep_list = set()

        self.auto_run_after_build = False
        try:
            self.auto_run_after_build = bool(self.cfg.get("DEPCLEAN_AUTO"))
        except Exception:
            self.auto_run_after_build = False

        self.use_sandbox = False
        try:
            self.use_sandbox = bool(self.cfg.get("DEPCLEAN_SANDBOX"))
        except Exception:
            self.use_sandbox = False

        self.verbose = False
        try:
            self.verbose = bool(self.cfg.get("DEPCLEAN_LOG_VERBOSE"))
        except Exception:
            self.verbose = False

    # -------------------- helpers --------------------
    def _log(self, event: str, level: str = "INFO", message: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        if self.logger:
            self.logger.log_event(event, level=level, message=message or event, metadata=metadata or {})

    def _pkg_all(self) -> List[Dict[str, Any]]:
        # return list of packages as dicts (name, id, status...)
        pkgs = []
        for p in self.db.list_packages():
            pkgs.append({"name": p.name, "id": p.id, "status": p.status, "origin": p.origin, "version": p.version})
        return pkgs

    def _deps_all(self) -> List[Dict[str, Any]]:
        # returns list of deps rows from db: package_name -> depends_on
        out = []
        for p in self.db.list_packages():
            deps = self.db.get_deps(p.name)
            for d in deps:
                out.append({"package": p.name, "depends_on": d.get("depends_on"), "optional": bool(d.get("optional"))})
        return out

    # -------------------- scan / analysis --------------------
    def scan(self) -> DepcleanReport:
        """Analisa o estado atual e retorna um relatório com candidates para remoção e rebuild."""
        packages = self._pkg_all()
        deps = self._deps_all()

        pkg_names = {p["name"] for p in packages}

        # build adjacency: package -> set(depends_on)
        adj: Dict[str, Set[str]] = {name: set() for name in pkg_names}
        for d in deps:
            pkg = d["package"]
            dep = d["depends_on"]
            if pkg not in adj:
                adj[pkg] = set()
            adj[pkg].add(dep)

        # reverse graph: dep -> set(packages that depend on it)
        rev: Dict[str, Set[str]] = {name: set() for name in pkg_names}
        for pkg, depset in adj.items():
            for dep in depset:
                if dep not in rev:
                    rev[dep] = set()
                rev[dep].add(pkg)

        # identify orphans: packages with no dependents (rev[name] empty)
        orphans = [name for name in pkg_names if len(rev.get(name, set())) == 0]
        # filter keep list and core system packages heuristically
        filtered_orphans = [o for o in orphans if o not in self.keep_list and not self._is_core_package(o)]

        # identify broken: packages that depend on missing packages
        broken = []
        for pkg, depset in adj.items():
            for dep in depset:
                if dep not in pkg_names:
                    broken.append({"package": pkg, "missing_dep": dep})

        items: List[DepcleanPlanItem] = []
        for o in filtered_orphans:
            items.append(DepcleanPlanItem(package=o, reason="orphan", action="remove", details={}))
        for b in broken:
            items.append(DepcleanPlanItem(package=b["package"], reason=f"broken_dep:{b[\"missing_dep\"]}", action="rebuild", details={"missing_dep": b["missing_dep"]}))

        summary = {"total_packages": len(pkg_names), "orphans": len(filtered_orphans), "broken": len(broken)}
        report = DepcleanReport(timestamp=datetime.utcnow().isoformat() + "Z", summary=summary, items=items)

        self._log("depclean_scan", level="INFO", message="Completed depclean scan", metadata=summary)
        return report

    def orphans(self) -> List[str]:
        return [item.package for item in self.scan().items if item.reason == "orphan"]

    def broken(self) -> List[Dict[str, Any]]:
        return [item for item in self.scan().items if item.action == "rebuild"]

    # -------------------- plan generation --------------------
    def plan(self, remove: bool = True, rebuild: bool = True, prefer_rebuild_for_broken: bool = True) -> List[DepcleanPlanItem]:
        report = self.scan()
        plan: List[DepcleanPlanItem] = []
        for it in report.items:
            if it.action == "remove" and remove:
                plan.append(it)
            if it.action == "rebuild" and rebuild:
                # if prefer_rebuild_for_broken then schedule rebuild (or maybe remove)
                plan.append(it)
        self._log("depclean_plan", level="INFO", message="Generated depclean plan", metadata={"plan_items": len(plan)})
        return plan

    # -------------------- execute --------------------
    def _confirm_interactive(self, plan: List[DepcleanPlanItem]) -> bool:
        print("Depclean plan:")
        for i, it in enumerate(plan, 1):
            print(f"  {i}. {it.action.upper()}: {it.package} ({it.reason})")
        print(f"Total actions: {len(plan)}")
        resp = input("Proceed? [y/N]: ")
        return resp.strip().lower() in ("y", "yes")

    def execute(self, plan: List[DepcleanPlanItem], interactive: bool = True, dry_run: bool = True, report_path: Optional[Path] = None) -> DepcleanReport:
        """Executa o plano passado.

        - interactive: se True, pergunta confirmação ao usuário antes de executar.
        - dry_run: se True, não altera o DB; apenas simula.
        - report_path: se fornecido, salva o relatório JSON em disco.
        """
        if not plan:
            raise DepcleanError("Empty plan")

        if interactive:
            ok = self._confirm_interactive(plan)
            if not ok:
                raise DepcleanError("User aborted")

        executed: List[DepcleanPlanItem] = []
        for it in plan:
            if it.action == "remove":
                # remove package from DB (and optionally files via installer)
                self._log("depclean_remove", level="INFO", message=f"Removing {it.package}", metadata={"package": it.package})
                if not dry_run:
                    try:
                        self.db.remove_package(it.package)
                        executed.append(it)
                        # record
                        try:
                            self.db.add_log(it.package, "depclean", "ok", log_path=None)
                        except Exception:
                            pass
                    except Exception as e:
                        self._log("depclean_remove", level="ERROR", message=f"Failed to remove {it.package}: {e}", metadata={"package": it.package, "error": str(e)})
                else:
                    executed.append(it)
            elif it.action == "rebuild":
                self._log("depclean_rebuild", level="INFO", message=f"Rebuilding {it.package}", metadata={"package": it.package})
                if not dry_run:
                    try:
                        if self.use_sandbox and self.sandbox:
                            # create sandbox for package and run placeholder rebuild steps
                            build_dir = self.sandbox.sandbox_for_package(it.package)
                            # In real usage, you would fetch sources and execute build commands here
                            res = self.sandbox.run(["/bin/true"], cwd=build_dir)
                            if res.returncode == 0:
                                executed.append(it)
                                try:
                                    self.db.add_log(it.package, "depclean_rebuild", "ok", log_path=None)
                                except Exception:
                                    pass
                            else:
                                self._log("depclean_rebuild", level="ERROR", message=f"Rebuild failed for {it.package}", metadata={"package": it.package, "rc": res.returncode})
                                raise DepcleanError(f"Rebuild failed for {it.package}")
                        else:
                            # Non-sandboxed placeholder rebuild (user should integrate real builder)
                            # For now, mark as rebuilt in DB by updating status
                            try:
                                self.db.update_package_status(it.package, "rebuilt")
                                executed.append(it)
                                try:
                                    self.db.add_log(it.package, "depclean_rebuild", "ok", log_path=None)
                                except Exception:
                                    pass
                            except Exception as e:
                                self._log("depclean_rebuild", level="ERROR", message=f"Failed to rebuild {it.package}: {e}", metadata={"package": it.package, "error": str(e)})
                                raise
                    except Exception as e:
                        raise DepcleanError(f"Failed to rebuild {it.package}: {e}")
                else:
                    executed.append(it)
            else:
                # unknown action
                self._log("depclean_unknown", level="WARNING", message=f"Unknown action {it.action} for {it.package}", metadata={"package": it.package})

        summary = {"requested": len(plan), "executed": len(executed), "dry_run": dry_run}
        report = DepcleanReport(timestamp=datetime.utcnow().isoformat() + "Z", summary=summary, items=executed)

        if report_path:
            try:
                report_path = Path(report_path)
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(report.to_json(), encoding="utf-8")
            except Exception:
                self._log("depclean_report", level="ERROR", message="Failed to write report", metadata={})

        self._log("depclean_execute", level="INFO", message="Depclean execute finished", metadata=summary)
        return report

    # -------------------- convenience --------------------
    def clean(self, interactive: bool = True, dry_run: bool = True, report_path: Optional[Path] = None) -> DepcleanReport:
        plan = self.plan()
        return self.execute(plan, interactive=interactive, dry_run=dry_run, report_path=report_path)

    def rebuild_reverse(self, pkg_name: str, interactive: bool = False, dry_run: bool = True) -> DepcleanReport:
        # find reverse deps
        rev = self._reverse_deps_map()
        dependents = rev.get(pkg_name, set())
        plan = [DepcleanPlanItem(package=p, reason=f"revdep_of:{pkg_name}", action="rebuild", details={}) for p in dependents]
        if not plan:
            raise DepcleanError(f"No reverse dependencies found for {pkg_name}")
        return self.execute(plan, interactive=interactive, dry_run=dry_run)

    # -------------------- utility: reverse deps map --------------------
    def _reverse_deps_map(self) -> Dict[str, Set[str]]:
        # construct reverse map quickly
        packages = self._pkg_all()
        pkg_names = {p["name"] for p in packages}
        rev: Dict[str, Set[str]] = {name: set() for name in pkg_names}
        for p in packages:
            deps = self.db.get_deps(p["name"])
            for d in deps:
                dep = d.get("depends_on")
                if dep not in rev:
                    rev[dep] = set()
                rev[dep].add(p["name"])
        return rev

    # -------------------- heuristics --------------------
    def _is_core_package(self, name: str) -> bool:
        # basic heuristics: consider packages in keep_list or common core names as core
        core_candidates = {"glibc", "coreutils", "bash", "linux", "gcc"}
        if name in self.keep_list:
            return True
        if name in core_candidates:
            return True
        return False


# -------------------- CLI quick tool --------------------
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(prog="newpkg-depclean")
    ap.add_argument("--report", help="path to write JSON report", default=None)
    ap.add_argument("--execute", action="store_true", help="actually execute the plan (not dry-run)")
    ap.add_argument("--yes", action="store_true", help="assume yes to interactive prompts")
    args = ap.parse_args()

    # try to load cfg/db/logger from environment or defaults if present in project workspace
    # In standalone mode we'll require a DB file path via environment NEWPKG_DB_PATH
    from pathlib import Path
    db_path = os.environ.get("NEWPKG_DB_PATH")
    if not db_path:
        print("Please set NEWPKG_DB_PATH to the sqlite file for newpkg_db")
        sys.exit(2)
    # lazy import of NewpkgDB if available in same workspace
    try:
        from newpkg_db import NewpkgDB
    except Exception:
        # try relative
        try:
            from .newpkg_db import NewpkgDB  # type: ignore
        except Exception:
            print("newpkg_db not available in PYTHONPATH. Aborting.")
            sys.exit(2)

    cfg = None
    try:
        # minimal cfg shim
        class CfgShim:
            def __init__(self, dbp):
                self._dbp = dbp
            def get(self, k):
                if k == "DEPCLEAN_KEEP":
                    return None
                return None
        cfg = CfgShim(db_path)
    except Exception:
        cfg = None

    db = NewpkgDB(db_path=db_path)
    db.init_db()
    depclean = NewpkgDepclean(cfg, db)
    report = depclean.scan()
    if args.execute:
        dr = depclean.execute(depclean.plan(), interactive=not args.yes, dry_run=not args.execute, report_path=Path(args.report) if args.report else None)
        print(dr.to_json())
    else:
        if args.report:
            Path(args.report).write_text(report.to_json(), encoding="utf-8")
        print(report.to_json())
