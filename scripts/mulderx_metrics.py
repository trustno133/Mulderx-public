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
TRIAGE_STATUSES = {"CANDIDATE", "NEEDS_OPERATOR"}
TRIAGE_VECTOR_FIELDS = ("vulnerability_class", "endpoint_or_signal", "source", "priority", "reason", "next_step")


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


def triage_candidate_snapshot(workspace: Path) -> dict[str, Any]:
    """Read structured triage output, with a tolerant legacy Markdown fallback."""
    json_path = workspace / "triage.json"
    if json_path.is_file():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"present": True, "source": "triage.json", "count": 0,
                    "needs_operator": 0, "business_logic_candidates": 0,
                    "blockers": 0, "discarded": 0,
                    "errors": [f"no se pudo leer triage.json: {exc}"]}

        errors: list[str] = []
        if not isinstance(data, dict):
            return {"present": True, "source": "triage.json", "count": 0,
                    "needs_operator": 0, "business_logic_candidates": 0,
                    "blockers": 0, "discarded": 0,
                    "errors": ["triage.json debe contener un objeto JSON."]}
        allowed_root = {
            "schema_version", "vectors", "business_logic_candidates", "discarded", "blockers",
        }
        extra_root = sorted(set(data) - allowed_root)
        if extra_root:
            errors.append(f"campos no reconocidos en triage.json: {', '.join(extra_root)}.")
        if type(data.get("schema_version")) is not int or data.get("schema_version") != 1:
            errors.append("schema_version debe ser 1.")
        for collection in ("business_logic_candidates", "discarded", "blockers"):
            if not isinstance(data.get(collection), list):
                errors.append(f"{collection} debe ser una lista.")
        vectors = data.get("vectors")
        if not isinstance(vectors, list):
            errors.append("vectors debe ser una lista.")
            vectors = []

        count = 0
        needs_operator = 0
        business_logic_count = 0
        seen_ids: set[str] = set()
        vector_collections = (("vectors", vectors),)
        business_vectors = data.get("business_logic_candidates")
        if isinstance(business_vectors, list):
            vector_collections += (("business_logic_candidates", business_vectors),)
        for collection_name, items in vector_collections:
            for index, vector in enumerate(items):
                prefix = f"{collection_name}[{index}]"
                if not isinstance(vector, dict):
                    errors.append(f"{prefix} debe ser un objeto.")
                    continue
                allowed_vector = {"id", "status", *TRIAGE_VECTOR_FIELDS}
                extra_vector = sorted(set(vector) - allowed_vector)
                if extra_vector:
                    errors.append(f"{prefix}: campos no reconocidos: {', '.join(extra_vector)}.")
                status = vector.get("status")
                if not isinstance(status, str) or status not in TRIAGE_STATUSES:
                    errors.append(f"{prefix}.status inválido.")
                    continue
                missing = [
                    field for field in ("id", *TRIAGE_VECTOR_FIELDS)
                    if not isinstance(vector.get(field), str) or not vector[field].strip()
                ]
                if missing:
                    errors.append(f"{prefix}: faltan campos requeridos: {', '.join(missing)}.")
                    continue
                vector_id = vector["id"]
                if not re.fullmatch(r"T[0-9]{1,4}", vector_id):
                    errors.append(f"{prefix}.id debe tener formato T01.")
                    continue
                if vector_id in seen_ids:
                    errors.append(f"{prefix}.id duplicado: {vector_id}.")
                    continue
                seen_ids.add(vector_id)
                if vector["priority"] not in {"P1", "P2", "P3"}:
                    errors.append(f"{prefix}.priority debe ser P1, P2 o P3.")
                    continue
                if collection_name == "vectors" and status == "CANDIDATE":
                    count += 1
                elif collection_name == "vectors" and status == "NEEDS_OPERATOR":
                    needs_operator += 1
                elif collection_name == "business_logic_candidates" and status == "CANDIDATE":
                    business_logic_count += 1

        for collection_name, fields in (
            ("discarded", ("source", "signal", "counterevidence", "reason")),
            ("blockers", ("source", "signal", "reason", "next_action")),
        ):
            items = data.get(collection_name)
            if not isinstance(items, list):
                continue
            for index, item in enumerate(items):
                prefix = f"{collection_name}[{index}]"
                if not isinstance(item, dict):
                    errors.append(f"{prefix} debe ser un objeto.")
                    continue
                allowed_fields = set(fields)
                extra_fields = sorted(set(item) - allowed_fields)
                if extra_fields:
                    errors.append(f"{prefix}: campos no reconocidos: {', '.join(extra_fields)}.")
                missing = [
                    field for field in fields
                    if not isinstance(item.get(field), str) or not item[field].strip()
                ]
                if missing:
                    errors.append(f"{prefix}: faltan campos requeridos: {', '.join(missing)}.")

        blockers = data.get("blockers")
        discarded = data.get("discarded")
        return {
            "present": True,
            "source": "triage.json",
            "count": count,
            "needs_operator": needs_operator,
            "business_logic_candidates": business_logic_count,
            "blockers": len(blockers) if isinstance(blockers, list) else 0,
            "discarded": len(discarded) if isinstance(discarded, list) else 0,
            "errors": errors,
        }

    markdown_path = workspace / "triage.md"
    if not markdown_path.is_file():
        return {"present": False, "source": None, "count": 0,
                "needs_operator": 0, "business_logic_candidates": 0,
                "blockers": 0, "discarded": 0,
                "errors": ["faltan triage.json y triage.md."]}

    text = read_text(markdown_path)
    in_vector_section = False
    recognized_section = False
    count = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            heading = line[3:].casefold()
            in_vector_section = "vector" in heading and (
                "client-side" in heading or "server-side" in heading
            )
            recognized_section = recognized_section or in_vector_section
            continue
        if not in_vector_section or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells or cells[0].casefold() == "vector" or cells[0] == "---":
            continue
        if all(not cell or set(cell) <= {"-", ":"} for cell in cells):
            continue
        count += 1
    errors = [] if recognized_section else [
        "triage.md no contiene secciones de vectores priorizados reconocibles."
    ]
    return {"present": True, "source": "triage.md (legacy)", "count": count,
            "needs_operator": 0, "business_logic_candidates": 0,
            "blockers": 0, "discarded": 0, "errors": errors}


def count_triage_candidates(workspace: Path) -> int:
    """Count candidate vectors in current or legacy Triage output."""
    return triage_candidate_snapshot(workspace)["count"]


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
    for name in ("recon.md", "recon_summary.md", "js_leads.md", "secrets.md", "triage.md", "triage.json", "leads.md", "discarded.md", "coverage.md", "posthunt-triage.md", "judged.md"):
        path = workspace / name
        artifacts[name] = path.stat().st_size if path.is_file() else 0

    triage = triage_candidate_snapshot(workspace)
    return {
        "recorded_at": now(),
        "triage_candidates": triage["count"],
        "triage_input": triage,
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
        triage = snapshot["triage_input"]
        triage_exists = triage["present"]
        allowed = triage_exists and not triage["errors"] and snapshot["triage_candidates"] > 0
        return allowed, {
            "stage": stage,
            "triage_exists": triage_exists,
            "triage_candidates": snapshot["triage_candidates"],
            "triage_needs_operator": triage["needs_operator"],
            "triage_business_logic_candidates": triage["business_logic_candidates"],
            "triage_blockers": triage["blockers"],
            "triage_discarded": triage["discarded"],
            "triage_source": triage["source"],
            "triage_errors": triage["errors"],
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
