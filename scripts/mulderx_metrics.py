#!/usr/bin/env python3
"""Gating and low-cost artifact metrics for the Mulderx Hermes pipeline."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from file_lock import locked_file
except ModuleNotFoundError:
    from scripts.file_lock import locked_file

METRICS_DIR = ".mulderx_metrics"
LEAD_STATES = ("CONFIRMADO", "CANDIDATO", "SETUP-PENDIENTE")
DISCARDED_STATES = ("MUERTO", "BLOQUEADO-EXTERNO")


def evidence_store_module():
    module_path = Path(__file__).with_name("evidence_store.py")
    spec = importlib.util.spec_from_file_location("mulderx_evidence_store", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"No se pudo cargar {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def structured_findings_snapshot(workspace: Path) -> dict[str, Any]:
    try:
        store = evidence_store_module()
        data = store.load_store(workspace)
        errors = store.validate_store(data, workspace)
        counts = {state: 0 for state in store.STATES}
        if not errors:
            for finding in data["findings"]:
                counts[finding["status"]] += 1
        return {
            "available": True,
            "valid": not errors,
            "counts": counts,
            "errors": errors,
        }
    except (OSError, ValueError, KeyError, json.JSONDecodeError, ImportError) as exc:
        return {
            "available": False,
            "valid": False,
            "counts": {},
            "errors": [str(exc)],
        }


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def count_triage_candidates(workspace: Path) -> int:
    """Count data rows in Triage's two prioritized-vector tables."""
    text = read_text(workspace / "triage.md")
    in_vector_section = False
    count = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            in_vector_section = line in {
                "## Vectores client-side priorizados",
                "## Vectores server-side (para después de client-side)",
            }
            continue
        if not in_vector_section or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells or cells[0] in {"Vector", "---"}:
            continue
        if all(not cell or set(cell) <= {"-", ":"} for cell in cells):
            continue
        count += 1
    return count


def count_lead_states(text: str) -> dict[str, int]:
    counts = {state: 0 for state in LEAD_STATES}
    for state in re.findall(r"^\*\*Estado:\*\*\s*(CONFIRMADO|CANDIDATO|SETUP-PENDIENTE)\b", text, re.MULTILINE):
        counts[state] += 1
    return counts


def count_discarded_states(text: str) -> dict[str, int]:
    counts = {state: 0 for state in DISCARDED_STATES}
    for state in DISCARDED_STATES:
        counts[state] = len(re.findall(rf"\|[^\n]*\|\s*{re.escape(state)}\s*\|", text))
    return counts


def collect_snapshot(workspace: Path) -> dict[str, Any]:
    leads_text = read_text(workspace / "leads.md")
    discarded_text = read_text(workspace / "discarded.md")
    judged_text = read_text(workspace / "judged.md")
    reports_dir = workspace / "reports"
    reports = 0
    if reports_dir.is_dir():
        reports = sum(path.name != "index.md" for path in reports_dir.glob("*.md"))

    artifacts = {}
    for name in ("recon.md", "recon_summary.md", "js_leads.md", "secrets.md", "triage.md", "leads.md", "discarded.md", "coverage.md", "posthunt-triage.md", "judged.md"):
        path = workspace / name
        artifacts[name] = path.stat().st_size if path.is_file() else 0

    return {
        "recorded_at": now(),
        "triage_candidates": count_triage_candidates(workspace),
        "leads": count_lead_states(leads_text),
        "discarded": count_discarded_states(discarded_text),
        "judged": {
            "APROBADO": len(re.findall(r"^\*\*Veredicto:\*\*\s*APROBADO\b", judged_text, re.MULTILINE)),
            "REFUTADO_O_REBAJADO": len(re.findall(r"^\*\*Killer:\*\*", judged_text, re.MULTILINE)),
            "INCOMPLETO": len(re.findall(r"^\|\s*`?leads\.md`?\s*\|", judged_text, re.MULTILINE)),
        },
        "structured_findings": structured_findings_snapshot(workspace),
        "reports": reports,
        "artifact_bytes": artifacts,
    }


def metrics_path(workspace: Path, run_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id):
        raise ValueError("run-id inválido; usa 1–128 letras, números, punto, guion o underscore.")
    root = workspace.resolve()
    directory = root / METRICS_DIR
    if directory.is_symlink():
        raise ValueError(f"El directorio de métricas no puede ser un symlink: {directory}")
    resolved_directory = directory.resolve()
    try:
        resolved_directory.relative_to(root)
    except ValueError as exc:
        raise ValueError("El directorio de métricas debe permanecer dentro del workspace.") from exc
    path = directory / f"{run_id}.json"
    if path.is_symlink():
        raise ValueError("El archivo de métricas no puede ser un symlink.")
    return path


def _run_lock(workspace: Path, run_id: str):
    path = metrics_path(workspace, run_id)
    return locked_file(path.with_suffix(".lock"))


def _atomic_save_run(workspace: Path, run_id: str, data: dict[str, Any]) -> Path:
    path = metrics_path(workspace, run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{run_id}.", suffix=".tmp", delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()
    return path


def load_run(workspace: Path, run_id: str) -> dict[str, Any]:
    path = metrics_path(workspace, run_id)
    if not path.is_file():
        raise FileNotFoundError(f"Métricas inexistentes para run-id '{run_id}': {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_run(workspace: Path, run_id: str, data: dict[str, Any]) -> Path:
    with _run_lock(workspace, run_id):
        return _atomic_save_run(workspace, run_id, data)


def start_run(workspace: Path, run_id: str, board: str | None) -> Path:
    data = {
        "run_id": run_id,
        "board": board,
        "started_at": now(),
        "snapshots": [{"stage": "start", **collect_snapshot(workspace)}],
    }
    with _run_lock(workspace, run_id):
        path = metrics_path(workspace, run_id)
        if path.exists():
            raise FileExistsError(f"El run-id ya existe; no se sobrescriben métricas: {run_id}")
        return _atomic_save_run(workspace, run_id, data)


def append_snapshot(workspace: Path, run_id: str, stage: str) -> Path:
    with _run_lock(workspace, run_id):
        data = load_run(workspace, run_id)
        data.setdefault("snapshots", []).append({"stage": stage, **collect_snapshot(workspace)})
        return _atomic_save_run(workspace, run_id, data)


def stage_gate(workspace: Path, stage: str) -> tuple[bool, dict[str, Any]]:
    """Decide whether the next expensive pipeline stage has usable input."""
    snapshot = collect_snapshot(workspace)
    if stage == "hunters":
        triage_exists = (workspace / "triage.md").is_file()
        allowed = triage_exists and snapshot["triage_candidates"] > 0
        return allowed, {
            "stage": stage,
            "triage_exists": triage_exists,
            "triage_candidates": snapshot["triage_candidates"],
            "run_hunters": allowed,
        }
    if stage == "judge":
        structured = snapshot["structured_findings"]
        confirmed = structured["counts"].get("CONFIRMED", 0) if structured["valid"] else 0
        return confirmed > 0, {
            "stage": stage,
            "confirmed_leads": confirmed,
            "evidence_store_valid": structured["valid"],
            "evidence_store_errors": structured["errors"],
            "run_judge": confirmed > 0,
        }
    if stage == "reporter":
        structured = snapshot["structured_findings"]
        approved = structured["counts"].get("APPROVED", 0) if structured["valid"] else 0
        return approved > 0, {
            "stage": stage,
            "approved_findings": approved,
            "evidence_store_valid": structured["valid"],
            "evidence_store_errors": structured["errors"],
            "run_reporter": approved > 0,
        }
    if stage == "closeout":
        triage_exists = (workspace / "triage.md").is_file()
        allowed = triage_exists
        return allowed, {
            "stage": stage,
            "triage_exists": triage_exists,
            "run_closeout": allowed,
        }
    if stage == "posthunt-triage":
        coverage_exists = (workspace / "coverage.md").is_file()
        allowed = coverage_exists
        return allowed, {
            "stage": stage,
            "coverage_exists": coverage_exists,
            "run_posthunt_triage": allowed,
        }
    raise ValueError(f"Etapa de gating desconocida: {stage}")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="Create a per-run metrics file.")
    start.add_argument("--workspace", type=Path, required=True)
    start.add_argument("--run-id", required=True)
    start.add_argument("--board")

    snapshot = subparsers.add_parser("snapshot", help="Append an artifact snapshot to an existing run.")
    snapshot.add_argument("--workspace", type=Path, required=True)
    snapshot.add_argument("--run-id", required=True)
    snapshot.add_argument("--stage", required=True, choices=("triage", "hunters", "closeout", "posthunt-triage", "judge", "reporter", "final"))

    gate = subparsers.add_parser("gate", help="Return whether the next pipeline stage has actionable input.")
    gate.add_argument("--workspace", type=Path, required=True)
    gate.add_argument("--stage", required=True, choices=("hunters", "closeout", "posthunt-triage", "judge", "reporter"))

    args = parser.parse_args()
    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        parser.error(f"workspace inexistente: {workspace}")

    try:
        if args.command == "start":
            print(start_run(workspace, args.run_id, args.board))
            return 0
        if args.command == "snapshot":
            print(append_snapshot(workspace, args.run_id, args.stage))
            return 0

        allowed, result = stage_gate(workspace, args.stage)
        print(json.dumps(result, ensure_ascii=True))
        return 0 if allowed else 10
    except (OSError, ValueError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
