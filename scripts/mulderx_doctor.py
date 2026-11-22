#!/usr/bin/env python3
"""Read-only diagnostics for Mulderx code, providers, dependencies, and tools."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = (
    "orchestrator.py", "AGENTS.md", "scripts/bb_pipeline.py",
    "scripts/recon_fingerprint_v3.6_handoff_slim.py", "scripts/mulderx_metrics.py",
    "scripts/scope_policy.py", "scripts/file_lock.py", "scripts/evidence_store.py",
    "scripts/research_memory.py", "scripts/benchmark_taint_tracker.py",
    "requirements.txt", "docs/evidence-store.md", "docs/schemas/finding.schema.json",
    "docs/schemas/triage.schema.json",
)
REQUIRED_MODULES = {"requests": "requests", "bs4": "beautifulsoup4", "lxml": "lxml"}
OPTIONAL_MODULES = {
    "networkx": "Webpack graph analysis",
    "tree_sitter": "Webpack AST analysis",
    "tree_sitter_javascript": "JavaScript AST grammar",
}
OPTIONAL_TOOLS = (
    "git", "bash", "node", "npm", "npx", "claude", "codex", "opencode",
    "hermes", "subfinder", "assetfinder", "findomain", "dnsx", "httpx",
    "katana", "subzy", "ffuf", "nuclei", "arjun", "x8",
    "github-subdomains", "chaos",
)
WSL_FALLBACK_TOOLS = frozenset({
    "git", "bash", "subfinder", "assetfinder", "findomain", "dnsx", "httpx",
    "katana", "subzy", "ffuf", "nuclei", "arjun", "x8",
    "github-subdomains", "chaos",
})


def _check(name: str, status: str, detail: str, *, required: bool = False) -> dict[str, Any]:
    return {"name": name, "status": status, "required": required, "detail": detail}


def _run_read_only_check(script: Path) -> dict[str, Any]:
    if not script.is_file():
        return _check(script.name, "ERROR", "script inexistente", required=True)
    try:
        result = subprocess.run(
            [sys.executable, str(script), "--check"], cwd=ROOT,
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _check(script.name, "ERROR", f"no se pudo ejecutar: {exc}", required=True)
    detail = (result.stdout or result.stderr).strip().splitlines()
    return _check(
        script.name,
        "OK" if result.returncode == 0 else "ERROR",
        detail[-1][:240] if detail else f"exit={result.returncode}",
        required=True,
    )


def _find_wsl_tool(command: str) -> str | None:
    """Find a Linux CLI in WSL when Mulderx is running from Windows."""
    wsl = shutil.which("wsl.exe")
    if os.name != "nt" or not wsl or command not in WSL_FALLBACK_TOOLS:
        return None
    try:
        result = subprocess.run(
            [wsl, "-e", "bash", "-lc", f"command -v {shlex.quote(command)}"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0:
        return result.stdout.strip().splitlines()[0] if result.stdout.strip() else None
    return None


def _find_wsl_seclists() -> str | None:
    """Check for the small SecLists files used by parameter/path discovery."""
    wsl = shutil.which("wsl.exe")
    if os.name != "nt" or not wsl:
        return None
    probe = (
        'base="${SECLISTS_PATH:-}"; '
        '[ -n "$base" ] && '
        '[ -f "$base/Discovery/Web-Content/burp-parameter-names.txt" ] && '
        '[ -f "$base/Discovery/Web-Content/common.txt" ] && printf "%s" "$base"'
    )
    try:
        result = subprocess.run(
            [wsl, "-e", "bash", "-lc", probe],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def _find_wsl_mulderx_python() -> str | None:
    """Check the WSL virtualenv used by the Windows-to-WSL recon workflow."""
    wsl = shutil.which("wsl.exe")
    if os.name != "nt" or not wsl:
        return None
    probe = (
        'python="$HOME/.local/share/mulderx/venvs/mulderx/bin/python"; '
        '[ -x "$python" ] && '
        '"$python" -c "import requests, bs4, lxml, networkx, tree_sitter, tree_sitter_javascript" '
        '&& printf "%s" "$python"'
    )
    try:
        result = subprocess.run(
            [wsl, "-e", "bash", "-lc", probe],
            capture_output=True, text=True, timeout=12, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def collect_report(root: Path = ROOT) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    py_ok = sys.version_info >= (3, 10)
    checks.append(_check(
        "python", "OK" if py_ok else "ERROR",
        f"{sys.version.split()[0]} (se requiere >=3.10)", required=True,
    ))

    for relative in REQUIRED_FILES:
        path = root / relative
        checks.append(_check(
            relative, "OK" if path.is_file() else "ERROR",
            "presente" if path.is_file() else "falta archivo requerido", required=True,
        ))

    for module, package in REQUIRED_MODULES.items():
        try:
            found = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            found = False
        checks.append(_check(
            f"python:{package}", "OK" if found else "ERROR",
            "instalado" if found else f"falta; instala con `python -m pip install {package}`",
            required=True,
        ))

    for module, purpose in OPTIONAL_MODULES.items():
        try:
            found = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            found = False
        checks.append(_check(
            f"python:{module}", "OK" if found else "WARN",
            "instalado" if found else f"no instalado; función opcional: {purpose}",
        ))

    for relative in (".claude/agents", ".claude/skills", ".codex/agents", ".agents/skills", "agents"):
        path = root / relative
        checks.append(_check(
            relative, "OK" if path.is_dir() else "ERROR",
            f"{sum(1 for item in path.iterdir())} entradas" if path.is_dir() else "directorio requerido faltante",
            required=True,
        ))

    mcp_path = root / ".mcp.json"
    try:
        mcp = json.loads(mcp_path.read_text(encoding="utf-8"))
        server_count = len(mcp.get("mcpServers", {}))
        checks.append(_check(".mcp.json", "OK", f"JSON válido; {server_count} MCP configurados", required=True))
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        checks.append(_check(".mcp.json", "ERROR", f"configuración inválida: {exc}", required=True))

    for relative in ("scripts/sync_codex_agents.py", "scripts/sync_codex_skills.py"):
        checks.append(_run_read_only_check(root / relative))

    for command in OPTIONAL_TOOLS:
        executable = shutil.which(command)
        wsl_executable = None if executable else _find_wsl_tool(command)
        status = "OK" if executable or wsl_executable else "WARN"
        detail = executable or (
            f"WSL: {wsl_executable} (usar WSL para scripts Bash)" if wsl_executable
            else "no está en PATH de Windows ni WSL (puede ser opcional)"
        )
        checks.append(_check(f"tool:{command}", status, detail))

    seclists_path = os.environ.get("SECLISTS_PATH")
    if seclists_path:
        seclists_ready = all(
            (Path(seclists_path) / "Discovery" / "Web-Content" / name).is_file()
            for name in ("burp-parameter-names.txt", "common.txt")
        )
    else:
        seclists_path = _find_wsl_seclists()
        seclists_ready = bool(seclists_path)
    checks.append(_check(
        "wordlists:SecLists-Web-Content",
        "OK" if seclists_ready else "WARN",
        str(seclists_path) if seclists_ready else "no configuradas; las skills de parámetros/rutas necesitan listas para x8/ffuf",
    ))
    wsl_python = _find_wsl_mulderx_python()
    checks.append(_check(
        "python:Mulderx-WSL",
        "OK" if wsl_python else "WARN",
        wsl_python or "faltan el venv y sus dependencias; instala con scripts/install_recon_tools_wsl.sh",
    ))

    if os.name == "nt" and shutil.which("wsl.exe") and not shutil.which("hermes"):
        checks.append(_check("tool:hermes-wsl", "WARN", "WSL existe; no se inspeccionó ni ejecutó el perfil Hermes externo."))
    checks.append(_check(
        "env:OPENAI_API_KEY", "OK" if os.environ.get("OPENAI_API_KEY") else "INFO",
        "configurada (valor oculto)" if os.environ.get("OPENAI_API_KEY") else "no configurada; no se necesita para Claude/Codex",
    ))

    errors = sum(item["status"] == "ERROR" for item in checks)
    warnings = sum(item["status"] == "WARN" for item in checks)
    return {"root": str(root), "checks": checks, "summary": {"errors": errors, "warnings": warnings}}


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Imprimir diagnóstico como JSON")
    parser.add_argument("--root", type=Path, default=ROOT, help="Raíz del repositorio (default: ubicación del script)")
    args = parser.parse_args()
    report = collect_report(args.root.resolve())
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        print(f"Mulderx doctor — {report['root']}")
        for check in report["checks"]:
            print(f"[{check['status']:<5}] {check['name']}: {check['detail']}")
        print(f"Resumen: {report['summary']['errors']} errores, {report['summary']['warnings']} avisos")
    return 1 if report["summary"]["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
