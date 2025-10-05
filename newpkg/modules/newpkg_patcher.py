"""
newpkg_patcher.py

Gerencia patches para fontes de pacotes no projeto `newpkg`.
- Localiza patches em diretórios configuráveis
- Verifica integridade (sha256) quando solicitado
- Aplica e reverte patches usando `patch` ou `git apply`
- Pode executar os comandos dentro de um sandbox (bubblewrap) quando configurado
- Registra eventos via NewpkgLogger e, opcionalmente, grava registros no NewpkgDB
- Marca patches aplicados em um arquivo `.applied_patches.json` dentro do target_dir

Dependências: stdlib only (subprocess, hashlib, json, pathlib, shutil)

"""
from __future__ import annotations

import subprocess
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
from contextlib import contextmanager


class PatchError(Exception):
    pass


def _sha256_of_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class NewpkgPatcher:
    def __init__(self, cfg: Any = None, logger: Any = None, db: Any = None):
        """Inicializa o patcher.

        cfg: objeto compatível com ConfigStore (cfg.get(key))
        logger: instancia de NewpkgLogger (opcional)
        db: instancia de NewpkgDB (opcional)
        """
        self.cfg = cfg
        self.logger = logger
        self.db = db

        # defaults
        self.patch_dirs = [
            Path("patches"),
            Path(self._cfg_get("PATCH_DIR") or "/usr/src/patches"),
        ]
        self.patch_tool = self._cfg_get("PATCH_TOOL") or "patch"
        self.patch_flags = self._cfg_get("PATCH_FLAGS") or "-p1 -N"
        self.verify_hash = self._to_bool(self._cfg_get("PATCH_VERIFY_HASH") or True)
        self.use_sandbox = self._to_bool(self._cfg_get("PATCH_SANDBOX") or True)
        # marker file to record applied patches
        self._marker = ".applied_patches.json"

    # --------------- config helpers ----------------
    def _cfg_get(self, key: str) -> Optional[Any]:
        if not self.cfg:
            return None
        try:
            # support dotted keys
            return self.cfg.get(key) if "." in key else self.cfg.get(key)
        except Exception:
            # fallback to lower-case dotted variants
            try:
                return self.cfg.get(key.lower())
            except Exception:
                return None

    def _to_bool(self, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if v is None:
            return False
        return str(v).lower() in ("1", "true", "yes", "on")

    # --------------- patch discovery ----------------
    def auto_detect_patch_dir(self, pkg_name: Optional[str] = None) -> List[Path]:
        """Retorna uma lista ordenada de diretórios onde procurar patches.

        Ordem tentativa:
          - ${SRC_DIR}/patches
          - ${PATCH_DIR}
          - ./patches
          - ./pkg_name/patches
        """
        out: List[Path] = []
        # src dir
        src = self._cfg_get("SRC_DIR") or self._cfg_get("general.SRC_DIR")
        if src:
            p = Path(src) / "patches"
            out.append(p)
        # global
        pd = self._cfg_get("PATCH_DIR")
        if pd:
            out.append(Path(pd))
        # project-local
        out.append(Path("patches"))
        if pkg_name:
            out.append(Path(pkg_name) / "patches")
        # dedupe and return existing only
        seen = set()
        res = []
        for p in out:
            norm = str(p)
            if norm in seen:
                continue
            seen.add(norm)
            if p.exists() and p.is_dir():
                res.append(p)
        return res

    def find_patches(self, pkg_name: Optional[str] = None) -> List[Path]:
        """Procura arquivos .patch/.diff em diretórios detectados para o pacote."""
        dirs = self.auto_detect_patch_dir(pkg_name)
        found: List[Path] = []
        for d in dirs:
            for p in sorted(d.iterdir()):
                if p.is_file() and p.suffix in (".patch", ".diff"):
                    found.append(p)
        return found

    # --------------- marker file handling ----------------
    def _marker_path(self, target_dir: Path) -> Path:
        return target_dir.resolve() / self._marker

    def _read_marker(self, target_dir: Path) -> Dict[str, Any]:
        m = self._marker_path(target_dir)
        if not m.exists():
            return {"applied": []}
        try:
            return json.loads(m.read_text(encoding="utf-8"))
        except Exception:
            return {"applied": []}

    def _write_marker(self, target_dir: Path, data: Dict[str, Any]) -> None:
        m = self._marker_path(target_dir)
        m.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    # --------------- verification ----------------
    def verify_patch(self, patch_file: Path, expected_hash: Optional[str] = None) -> bool:
        """Verifica hash do patch se expected_hash fornecido, ou apenas calcula e retorna True."""
        if not patch_file.exists():
            raise PatchError(f"Patch file not found: {patch_file}")
        actual = _sha256_of_file(patch_file)
        if expected_hash:
            ok = actual == expected_hash
            if not ok:
                raise PatchError(f"Hash mismatch for {patch_file}: expected {expected_hash}, got {actual}")
            return True
        return True

    # --------------- command execution (sandbox aware) ----------------
    def _build_command(self, cmd: List[str], target_dir: Path) -> List[str]:
        """Se sandbox ativado, retorna comando prefixado por bubblewrap."""
        if not self.use_sandbox:
            return cmd
        # basic bubblewrap wrapper: bind target_dir to itself, chdir into it
        b = ["bwrap", "--unshare-all", "--dev", "/dev", "--proc", "/proc", "--ro-bind", str(target_dir), str(target_dir), "--chdir", str(target_dir), "--"]
        return b + cmd

    def _run_cmd(self, cmd: List[str], cwd: Optional[Path] = None, capture: bool = True) -> subprocess.CompletedProcess:
        try:
            cp = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=capture, text=True, check=False)
            return cp
        except FileNotFoundError as e:
            raise PatchError(f"Command not found: {cmd[0]}") from e

    # --------------- apply / revert logic ----------------
    def _apply_single_patch(self, patch_file: Path, target_dir: Path, tool: Optional[str] = None, flags: Optional[str] = None) -> Dict[str, Any]:
        tool = tool or ("git" if (target_dir / ".git").exists() else self.patch_tool)
        flags = flags or self.patch_flags
        start = datetime.utcnow()
        res: Dict[str, Any] = {"patch": str(patch_file), "tool": tool, "status": "unknown", "stdout": None, "stderr": None}
        if tool == "git":
            # git apply <patch>
            cmd = ["git", "apply", "--check", str(patch_file)]
            cmd = self._build_command(cmd, target_dir)
            cp = self._run_cmd(cmd, cwd=target_dir)
            if cp.returncode != 0:
                res.update({"status": "check-failed", "stderr": cp.stderr})
                return res
            # apply
            cmd = ["git", "apply", str(patch_file)]
            cmd = self._build_command(cmd, target_dir)
            cp = self._run_cmd(cmd, cwd=target_dir)
            res.update({"stdout": cp.stdout, "stderr": cp.stderr})
            res["status"] = "ok" if cp.returncode == 0 else "failed"
        else:
            # classic patch
            args = flags.split() if flags else []
            cmd = ["patch"] + args + ["-i", str(patch_file)]
            cmd = self._build_command(cmd, target_dir)
            cp = self._run_cmd(cmd, cwd=target_dir)
            res.update({"stdout": cp.stdout, "stderr": cp.stderr})
            res["status"] = "ok" if cp.returncode == 0 else "failed"
        # record duration
        dur = (datetime.utcnow() - start).total_seconds()
        res["duration"] = dur
        return res

    def _revert_single_patch(self, patch_file: Path, target_dir: Path, tool: Optional[str] = None, flags: Optional[str] = None) -> Dict[str, Any]:
        tool = tool or ("git" if (target_dir / ".git").exists() else self.patch_tool)
        flags = flags or self.patch_flags
        res: Dict[str, Any] = {"patch": str(patch_file), "tool": tool, "status": "unknown", "stdout": None, "stderr": None}
        if tool == "git":
            cmd = ["git", "apply", "-R", str(patch_file)]
            cmd = self._build_command(cmd, target_dir)
            cp = self._run_cmd(cmd, cwd=target_dir)
            res.update({"stdout": cp.stdout, "stderr": cp.stderr})
            res["status"] = "ok" if cp.returncode == 0 else "failed"
        else:
            args = flags.split() if flags else []
            cmd = ["patch"] + args + ["-R", "-i", str(patch_file)]
            cmd = self._build_command(cmd, target_dir)
            cp = self._run_cmd(cmd, cwd=target_dir)
            res.update({"stdout": cp.stdout, "stderr": cp.stderr})
            res["status"] = "ok" if cp.returncode == 0 else "failed"
        return res

    def apply_patch(self, patch_file: Path, target_dir: Path, expected_hash: Optional[str] = None, register_in_db: bool = True) -> Dict[str, Any]:
        """Aplica um único patch no target_dir.

        Retorna um dict com resultado e lança PatchError em falhas críticas.
        """
        patch_file = patch_file.resolve()
        target_dir = target_dir.resolve()
        if not patch_file.exists():
            raise PatchError(f"Patch not found: {patch_file}")
        if not target_dir.exists() or not target_dir.is_dir():
            raise PatchError(f"Target dir not found: {target_dir}")

        if self.verify_hash and expected_hash:
            self.verify_patch(patch_file, expected_hash=expected_hash)

        # safety: ensure target_dir is ancestor of any file modified? Hard to know; rely on patch tool
        result = self._apply_single_patch(patch_file, target_dir)

        # record marker on success
        if result.get("status") == "ok":
            marker = self._read_marker(target_dir)
            marker.setdefault("applied", []).append({
                "patch": str(patch_file),
                "applied_at": datetime.utcnow().isoformat() + "Z",
                "tool": result.get("tool"),
            })
            self._write_marker(target_dir, marker)
            # logger
            if self.logger:
                self.logger.log_event("patch_apply", level="INFO", message=f"Applied {patch_file.name}", metadata={"package": target_dir.name, "patch": str(patch_file), "status": "ok"})
            # db
            if register_in_db and self.db:
                try:
                    # add as build_log with phase 'patch'
                    self.db.add_log(target_dir.name, "patch", "ok", log_path=None)
                except Exception:
                    pass
        else:
            if self.logger:
                self.logger.log_event("patch_apply", level="ERROR", message=f"Failed to apply {patch_file.name}", metadata={"package": target_dir.name, "patch": str(patch_file), "status": result.get("status"), "stderr": result.get("stderr")})
            raise PatchError(f"Failed to apply patch {patch_file}: {result.get('stderr')}")

        return result

    def revert_patch(self, patch_file: Path, target_dir: Path, register_in_db: bool = True) -> Dict[str, Any]:
        patch_file = patch_file.resolve()
        target_dir = target_dir.resolve()
        if not patch_file.exists():
            raise PatchError(f"Patch not found: {patch_file}")
        result = self._revert_single_patch(patch_file, target_dir)
        if result.get("status") == "ok":
            marker = self._read_marker(target_dir)
            applied = marker.get("applied", [])
            applied = [a for a in applied if a.get("patch") != str(patch_file)]
            marker["applied"] = applied
            self._write_marker(target_dir, marker)
            if self.logger:
                self.logger.log_event("patch_revert", level="INFO", message=f"Reverted {patch_file.name}", metadata={"package": target_dir.name, "patch": str(patch_file), "status": "ok"})
            if register_in_db and self.db:
                try:
                    self.db.add_log(target_dir.name, "patch_revert", "ok", log_path=None)
                except Exception:
                    pass
        else:
            if self.logger:
                self.logger.log_event("patch_revert", level="ERROR", message=f"Failed to revert {patch_file.name}", metadata={"package": target_dir.name, "patch": str(patch_file), "status": result.get("status"), "stderr": result.get("stderr")})
            raise PatchError(f"Failed to revert patch {patch_file}: {result.get('stderr')}")
        return result

    def status(self, target_dir: Path) -> Dict[str, Any]:
        target_dir = target_dir.resolve()
        marker = self._read_marker(target_dir)
        return marker

    def apply_all(self, pkg_name: Optional[str], target_dir: Path) -> List[Dict[str, Any]]:
        patches = self.find_patches(pkg_name)
        results: List[Dict[str, Any]] = []
        for p in patches:
            try:
                r = self.apply_patch(p, target_dir)
                results.append(r)
            except Exception as e:
                # log and continue? We choose to stop and raise to avoid inconsistent state
                if self.logger:
                    self.logger.log_event("patch_apply_all", level="ERROR", message=f"Stopped applying patches due to {e}", metadata={"package": target_dir.name, "error": str(e)})
                raise
        return results

    def revert_all(self, pkg_name: Optional[str], target_dir: Path) -> List[Dict[str, Any]]:
        marker = self._read_marker(target_dir)
        applied = marker.get("applied", [])
        results: List[Dict[str, Any]] = []
        # revert in reverse order
        for entry in reversed(applied):
            pth = Path(entry.get("patch"))
            try:
                r = self.revert_patch(pth, target_dir)
                results.append(r)
            except Exception as e:
                if self.logger:
                    self.logger.log_event("patch_revert_all", level="ERROR", message=f"Stopped reverting patches due to {e}", metadata={"package": target_dir.name, "error": str(e)})
                raise
        return results


# ----------------- small demo CLI -----------------
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(prog="newpkg-patcher")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--apply", help="patch file to apply")
    ap.add_argument("--revert", help="patch file to revert")
    ap.add_argument("--target", help="target dir (source tree)", required=True)
    ap.add_argument("--pkg", help="package name (for autodetect)", default=None)
    args = ap.parse_args()

    p = NewpkgPatcher()
    t = Path(args.target)
    if args.list:
        for x in p.find_patches(args.pkg):
            print(x)
    if args.apply:
        p.apply_patch(Path(args.apply), t)
        print("Applied")
    if args.revert:
        p.revert_patch(Path(args.revert), t)
        print("Reverted")
