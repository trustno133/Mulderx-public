#!/usr/bin/env python3
"""Validate and transition per-program Mulderx finding receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from file_lock import locked_file
except ModuleNotFoundError:
    from scripts.file_lock import locked_file


STORE_NAME = "findings.json"
STATES = {
    "CANDIDATE", "TESTING", "CONFIRMED", "REVIEWED", "APPROVED",
    "DISCARDED", "BLOCKED", "INSUFFICIENT",
}
EVIDENCE_KINDS = {
    "baseline", "execution", "verification", "impact", "disproof", "judge", "source", "other",
}
REQUIRED_FIELDS = {
    "target", "scope", "lead_id", "vulnerability_class", "affected_asset",
    "actor", "resource", "operation", "hypothesis", "observations", "evidence",
    "confidence", "impact", "reproduction_status", "severity_proposal",
    "disproof_attempts", "status", "next_action",
}
ACTORS = {"liquid", "solid", "mulderx", "operator"}
UPDATE_FIELDS = {
    "affected_asset", "actor", "resource", "operation", "hypothesis",
    "observations", "confidence", "impact", "reproduction_status",
    "severity_proposal", "disproof_attempts", "severity_gate", "next_action",
}
TRANSITIONS = {
    "CANDIDATE": {"TESTING", "DISCARDED", "BLOCKED", "INSUFFICIENT"},
    "TESTING": {"CANDIDATE", "CONFIRMED", "DISCARDED", "BLOCKED", "INSUFFICIENT"},
    "CONFIRMED": {"TESTING", "REVIEWED", "DISCARDED", "INSUFFICIENT"},
    "REVIEWED": {"CONFIRMED", "APPROVED", "DISCARDED", "INSUFFICIENT"},
    "APPROVED": {"REVIEWED"},
    "DISCARDED": set(),
    "BLOCKED": {"CANDIDATE", "TESTING", "DISCARDED", "INSUFFICIENT"},
    "INSUFFICIENT": {"CANDIDATE", "TESTING", "DISCARDED", "BLOCKED"},
}


def _workspace_root(workspace: Path) -> Path:
    root = workspace.resolve()
    if not root.is_dir():
        raise ValueError(f"workspace inexistente: {root}")
    return root


def _store_path(workspace: Path) -> Path:
    root = _workspace_root(workspace)
    path = root / STORE_NAME
    if path.is_symlink():
        raise ValueError(f"{STORE_NAME} no puede ser un symlink.")
    return path


def _artifact_path(workspace: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
        raise ValueError("La ruta de evidencia debe ser relativa y usar separadores '/'.")
    posix = PurePosixPath(relative)
    if posix.is_absolute() or any(part in {"", ".", ".."} for part in posix.parts):
        raise ValueError("La ruta de evidencia debe permanecer dentro del workspace.")
    root = _workspace_root(workspace)
    candidate = (root / Path(*posix.parts)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("La evidencia resuelve fuera del workspace.") from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"No existe el artefacto de evidencia: {relative}")
    return candidate


def _validate_evidence(workspace: Path, evidence: Any, lead_id: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(evidence, list):
        return [f"{lead_id}: evidence debe ser una lista."]
    for index, item in enumerate(evidence):
        prefix = f"{lead_id}: evidence[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} debe ser un objeto.")
            continue
        if item.get("kind") not in EVIDENCE_KINDS:
            errors.append(f"{prefix}.kind no es válido.")
        if not isinstance(item.get("description"), str) or not item["description"].strip():
            errors.append(f"{prefix}.description es obligatorio.")
        if item.get("source") not in {"tool_capture", "operator_capture"}:
            errors.append(f"{prefix}.source debe ser tool_capture u operator_capture.")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            errors.append(f"{prefix}.sha256 debe ser un SHA-256 hexadecimal.")
            continue
        try:
            artifact = _artifact_path(workspace, item.get("path"))
            actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if actual != digest:
                errors.append(f"{prefix}: hash no coincide con {item.get('path')}.")
        except (ValueError, FileNotFoundError, OSError) as exc:
            errors.append(f"{prefix}: {exc}")
    return errors


def validate_finding(finding: Any, workspace: Path) -> list[str]:
    if not isinstance(finding, dict):
        return ["finding debe ser un objeto JSON."]
    lead_id = str(finding.get("lead_id", "<sin-id>"))
    errors = [f"{lead_id}: falta {field}." for field in sorted(REQUIRED_FIELDS - finding.keys())]
    for field in sorted(REQUIRED_FIELDS & finding.keys()):
        value = finding[field]
        if field in {"target", "lead_id", "vulnerability_class", "affected_asset", "actor", "resource", "operation", "hypothesis", "severity_proposal", "next_action"}:
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{lead_id}: {field} debe ser texto no vacío.")
    if not re.fullmatch(r"L[0-9]{1,6}", lead_id):
        errors.append(f"{lead_id}: lead_id debe tener formato L01.")
    if not isinstance(finding.get("scope"), list) or not finding["scope"] or not all(isinstance(x, str) and x.strip() for x in finding["scope"]):
        errors.append(f"{lead_id}: scope debe ser una lista de entradas no vacías.")
    if finding.get("confidence") not in {"low", "medium", "high"}:
        errors.append(f"{lead_id}: confidence debe ser low, medium o high.")
    if not isinstance(finding.get("observations"), list) or not isinstance(finding.get("disproof_attempts"), list):
        errors.append(f"{lead_id}: observations y disproof_attempts deben ser listas.")
    impact = finding.get("impact")
    if not isinstance(impact, dict) or not isinstance(impact.get("demonstrated"), bool) or not isinstance(impact.get("description"), str):
        errors.append(f"{lead_id}: impact requiere demonstrated (boolean) y description (texto).")
    status = finding.get("status")
    if status not in STATES:
        errors.append(f"{lead_id}: status inválido.")
    reproduction = finding.get("reproduction_status")
    if reproduction not in {"NOT_TESTED", "PARTIAL", "REPRODUCED", "NOT_REPRODUCIBLE"}:
        errors.append(f"{lead_id}: reproduction_status inválido.")
    history = finding.get("status_history")
    if not isinstance(history, list):
        errors.append(f"{lead_id}: status_history debe ser una lista de transiciones.")
    else:
        cursor = "CANDIDATE"
        for index, event in enumerate(history):
            prefix = f"{lead_id}: status_history[{index}]"
            if not isinstance(event, dict):
                errors.append(f"{prefix} debe ser un objeto.")
                continue
            previous, following = event.get("from"), event.get("to")
            if previous != cursor:
                errors.append(f"{prefix}: cadena de estados discontinua.")
            if previous not in TRANSITIONS or following not in TRANSITIONS.get(previous, set()):
                errors.append(f"{prefix}: transición no permitida.")
            actor = event.get("actor")
            if actor not in ACTORS:
                errors.append(f"{prefix}: actor no reconocido.")
            elif actor in {"liquid", "solid"} and following in {"REVIEWED", "APPROVED"}:
                errors.append(f"{prefix}: un hunter no puede registrar una revisión de Ocelot.")
            elif actor == "mulderx" and following == "CONFIRMED":
                errors.append(f"{prefix}: Mulderx no puede confirmar el lead en nombre del hunter.")
            if not isinstance(event.get("reason"), str) or not event["reason"].strip():
                errors.append(f"{prefix}: reason es obligatorio.")
            if not isinstance(event.get("at"), str) or not event["at"].strip():
                errors.append(f"{prefix}: at es obligatorio.")
            if following in TRANSITIONS:
                cursor = following
        if cursor != status:
            errors.append(f"{lead_id}: status no coincide con el final de status_history.")
    evidence_errors = _validate_evidence(workspace, finding.get("evidence"), lead_id)
    errors.extend(evidence_errors)

    if status in {"CONFIRMED", "REVIEWED", "APPROVED"}:
        kinds = {
            item.get("kind") for item in finding.get("evidence", [])
            if isinstance(item, dict) and item.get("source") in {"tool_capture", "operator_capture"}
        }
        required_kinds = {"baseline", "execution", "verification", "impact"}
        if reproduction != "REPRODUCED":
            errors.append(f"{lead_id}: {status} requiere reproduction_status=REPRODUCED.")
        if not isinstance(impact, dict) or impact.get("demonstrated") is not True or not impact.get("description", "").strip():
            errors.append(f"{lead_id}: {status} requiere impacto demostrado con descripción.")
        missing = required_kinds - kinds
        if missing:
            errors.append(f"{lead_id}: {status} requiere evidencia: {', '.join(sorted(missing))}.")
        gate = finding.get("severity_gate")
        if not isinstance(gate, dict) or any(not isinstance(gate.get(q), str) or not gate[q].strip() for q in ("Q1", "Q2", "Q3")):
            errors.append(f"{lead_id}: {status} requiere respuestas documentadas Q1, Q2 y Q3.")
    if status in {"REVIEWED", "APPROVED"}:
        review = finding.get("review")
        if not isinstance(review, dict) or review.get("verdict") not in {"APPROVED", "REJECTED", "INCOMPLETE"}:
            errors.append(f"{lead_id}: {status} requiere un review estructurado de Ocelot.")
        elif status == "APPROVED" and review.get("verdict") != "APPROVED":
            errors.append(f"{lead_id}: APPROVED requiere veredicto APPROVED de Ocelot.")
        if "judge" not in {item.get("kind") for item in finding.get("evidence", []) if isinstance(item, dict)}:
            errors.append(f"{lead_id}: {status} requiere un artefacto de evidencia judge.")
    if status in {"DISCARDED", "BLOCKED", "INSUFFICIENT"}:
        if not isinstance(finding.get("status_reason"), str) or not finding["status_reason"].strip():
            errors.append(f"{lead_id}: {status} requiere status_reason verificable.")
    return errors


def validate_store(data: Any, workspace: Path) -> list[str]:
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("findings"), list):
        return ["findings.json requiere schema_version=1 y findings como lista."]
    errors: list[str] = []
    seen: set[str] = set()
    for finding in data["findings"]:
        errors.extend(validate_finding(finding, workspace))
        if isinstance(finding, dict):
            lead_id = finding.get("lead_id")
            if isinstance(lead_id, str):
                if lead_id in seen:
                    errors.append(f"lead_id duplicado: {lead_id}.")
                seen.add(lead_id)
    return errors


def load_store(workspace: Path) -> dict[str, Any]:
    path = _store_path(workspace)
    if not path.is_file():
        raise FileNotFoundError(f"No existe {STORE_NAME}; inicializa findings.json antes del gate.")
    return json.loads(path.read_text(encoding="utf-8"))


def _store_lock(workspace: Path):
    root = _workspace_root(workspace)
    lock_path = root / ".findings.lock"
    return locked_file(lock_path)


def _write_store(workspace: Path, data: dict[str, Any]) -> Path:
    path = _store_path(workspace)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=".findings.", suffix=".tmp", delete=False,
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


def init_store(workspace: Path) -> Path:
    with _store_lock(workspace):
        path = _store_path(workspace)
        if path.exists():
            raise FileExistsError(f"No se sobrescribe un store existente: {path}")
        return _write_store(workspace, {"schema_version": 1, "findings": []})


def create_finding(workspace: Path, finding: dict[str, Any]) -> Path:
    with _store_lock(workspace):
        data = load_store(workspace)
        if validate_store(data, workspace):
            raise ValueError("findings.json actual no valida; corrige sus errores antes de agregar leads.")
        if any(item.get("lead_id") == finding.get("lead_id") for item in data["findings"]):
            raise ValueError(f"lead_id ya existe: {finding.get('lead_id')}")
        finding = {**finding, "status": "CANDIDATE", "status_history": []}
        errors = validate_finding(finding, workspace)
        if errors:
            raise ValueError("\n".join(errors))
        data["findings"].append(finding)
        return _write_store(workspace, data)


def set_review(workspace: Path, lead_id: str, verdict: str, summary: str, reviewer: str) -> Path:
    if verdict not in {"APPROVED", "REJECTED", "INCOMPLETE"}:
        raise ValueError("verdict debe ser APPROVED, REJECTED o INCOMPLETE.")
    if reviewer not in {"mulderx", "operator"} or not summary.strip():
        raise ValueError("reviewer debe ser mulderx/operator y summary no puede estar vacío.")
    with _store_lock(workspace):
        data = load_store(workspace)
        errors = validate_store(data, workspace)
        if errors:
            raise ValueError("findings.json contiene errores: " + "; ".join(errors))
        finding = next((item for item in data["findings"] if item.get("lead_id") == lead_id), None)
        if finding is None:
            raise KeyError(f"Lead inexistente: {lead_id}")
        if finding.get("status") != "CONFIRMED":
            raise ValueError("La revisión se registra solamente sobre un lead CONFIRMED.")
        if "judge" not in {item.get("kind") for item in finding.get("evidence", [])}:
            raise ValueError("Registra primero judged.md como evidencia kind=judge.")
        finding["review"] = {
            "verdict": verdict,
            "summary": summary.strip(),
            "reviewed_by": reviewer,
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        errors = validate_finding(finding, workspace)
        if errors:
            finding.pop("review", None)
            raise ValueError("\n".join(errors))
        return _write_store(workspace, data)


def update_finding(workspace: Path, lead_id: str, updates: dict[str, Any]) -> Path:
    if not isinstance(updates, dict) or not updates:
        raise ValueError("El patch debe ser un objeto JSON no vacío.")
    forbidden = set(updates) - UPDATE_FIELDS
    if forbidden:
        raise ValueError(f"Campos no editables por update: {', '.join(sorted(forbidden))}.")
    with _store_lock(workspace):
        data = load_store(workspace)
        errors = validate_store(data, workspace)
        if errors:
            raise ValueError("findings.json contiene errores: " + "; ".join(errors))
        finding = next((item for item in data["findings"] if item.get("lead_id") == lead_id), None)
        if finding is None:
            raise KeyError(f"Lead inexistente: {lead_id}")
        finding.update(updates)
        errors = validate_finding(finding, workspace)
        if errors:
            raise ValueError("\n".join(errors))
        return _write_store(workspace, data)


def record_evidence(workspace: Path, lead_id: str, kind: str, relative_path: str, description: str, source: str) -> Path:
    if kind not in EVIDENCE_KINDS:
        raise ValueError(f"kind inválido: {kind}")
    if source not in {"tool_capture", "operator_capture"}:
        raise ValueError(f"source inválido: {source}")
    artifact = _artifact_path(workspace, relative_path)
    receipt = {
        "kind": kind,
        "path": PurePosixPath(relative_path).as_posix(),
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "description": description.strip(),
        "source": source,
    }
    with _store_lock(workspace):
        data = load_store(workspace)
        errors = validate_store(data, workspace)
        if errors:
            raise ValueError("findings.json contiene errores: " + "; ".join(errors))
        finding = next((item for item in data["findings"] if item.get("lead_id") == lead_id), None)
        if finding is None:
            raise KeyError(f"Lead inexistente: {lead_id}")
        finding.setdefault("evidence", []).append(receipt)
        errors = validate_finding(finding, workspace)
        if errors:
            finding["evidence"].pop()
            raise ValueError("\n".join(errors))
        return _write_store(workspace, data)


def transition_finding(workspace: Path, lead_id: str, to_status: str, actor: str, reason: str) -> Path:
    if to_status not in STATES:
        raise ValueError(f"Estado inválido: {to_status}")
    if not actor.strip() or not reason.strip():
        raise ValueError("actor y reason son obligatorios para cada transición.")
    with _store_lock(workspace):
        data = load_store(workspace)
        errors = validate_store(data, workspace)
        if errors:
            raise ValueError("findings.json contiene errores: " + "; ".join(errors))
        finding = next((item for item in data["findings"] if item.get("lead_id") == lead_id), None)
        if finding is None:
            raise KeyError(f"Lead inexistente: {lead_id}")
        old_status = finding["status"]
        if to_status not in TRANSITIONS[old_status]:
            raise ValueError(f"Transición no permitida: {old_status} → {to_status}")
        if to_status == "DISCARDED":
            attempts = finding.get("disproof_attempts")
            documented_attempts = isinstance(attempts, list) and any(
                isinstance(item, dict)
                and isinstance(item.get("action"), str) and item["action"].strip()
                and isinstance(item.get("result"), str) and item["result"].strip()
                for item in attempts
            )
            has_disproof_receipt = isinstance(finding.get("evidence"), list) and any(
                isinstance(item, dict) and item.get("kind") == "disproof"
                for item in finding["evidence"]
            )
            if finding.get("reproduction_status") != "NOT_REPRODUCIBLE":
                raise ValueError("DISCARDED requiere reproduction_status=NOT_REPRODUCIBLE.")
            if not documented_attempts:
                raise ValueError("DISCARDED requiere un intento de refutación con action y result.")
            if not has_disproof_receipt:
                raise ValueError("DISCARDED requiere evidencia registrada de tipo disproof.")
        finding["status"] = to_status
        previous_reason = finding.get("status_reason")
        if to_status in {"DISCARDED", "BLOCKED", "INSUFFICIENT"}:
            finding["status_reason"] = reason.strip()
        elif "status_reason" in finding:
            finding.pop("status_reason")
        finding.setdefault("status_history", []).append({
            "from": old_status,
            "to": to_status,
            "actor": actor.strip(),
            "reason": reason.strip(),
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
        })
        errors = validate_finding(finding, workspace)
        if errors:
            finding["status"] = old_status
            if previous_reason is not None:
                finding["status_reason"] = previous_reason
            else:
                finding.pop("status_reason", None)
            finding["status_history"].pop()
            raise ValueError("\n".join(errors))
        return _write_store(workspace, data)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Crear findings.json sin sobrescribirlo.")
    init.add_argument("--workspace", type=Path, required=True)
    validate = sub.add_parser("validate", help="Validar esquema, transiciones y hashes de evidencia.")
    validate.add_argument("--workspace", type=Path, required=True)
    record = sub.add_parser("record", help="Registrar un artefacto local y calcular su hash.")
    record.add_argument("--workspace", type=Path, required=True)
    record.add_argument("--lead-id", required=True)
    record.add_argument("--kind", choices=sorted(EVIDENCE_KINDS), required=True)
    record.add_argument("--path", required=True)
    record.add_argument("--description", required=True)
    record.add_argument("--source", choices=("tool_capture", "operator_capture"), default="operator_capture")
    create = sub.add_parser("create", help="Crear un lead CANDIDATE desde un JSON local o stdin.")
    create.add_argument("--workspace", type=Path, required=True)
    create.add_argument("--json", dest="json_path", required=True, help="Archivo JSON relativo al workspace o '-' para stdin.")
    review = sub.add_parser("review", help="Registrar el resultado de Ocelot sobre un lead confirmado.")
    review.add_argument("--workspace", type=Path, required=True)
    review.add_argument("--lead-id", required=True)
    review.add_argument("--verdict", choices=("APPROVED", "REJECTED", "INCOMPLETE"), required=True)
    review.add_argument("--summary", required=True)
    review.add_argument("--reviewer", choices=("mulderx", "operator"), default="mulderx")
    update = sub.add_parser("update", help="Actualizar campos de investigación sin alterar estado/evidencia.")
    update.add_argument("--workspace", type=Path, required=True)
    update.add_argument("--lead-id", required=True)
    update.add_argument("--json", dest="json_path", required=True, help="Archivo JSON patch relativo al workspace o '-' para stdin.")
    transition = sub.add_parser("transition", help="Aplicar una transición validada del ciclo de vida.")
    transition.add_argument("--workspace", type=Path, required=True)
    transition.add_argument("--lead-id", required=True)
    transition.add_argument("--to", choices=sorted(STATES), required=True)
    transition.add_argument("--actor", required=True)
    transition.add_argument("--reason", required=True)
    args = parser.parse_args()

    try:
        workspace = _workspace_root(args.workspace)
        if args.command == "init":
            print(init_store(workspace))
            return 0
        if args.command == "validate":
            errors = validate_store(load_store(workspace), workspace)
            if errors:
                print("\n".join(errors), file=sys.stderr)
                return 1
            print("findings.json válido; los hashes de evidencia coinciden.")
            return 0
        if args.command == "record":
            print(record_evidence(workspace, args.lead_id, args.kind, args.path, args.description, args.source))
            return 0
        if args.command == "create":
            if args.json_path == "-":
                raw = sys.stdin.read()
            else:
                source = _artifact_path(workspace, args.json_path)
                raw = source.read_text(encoding="utf-8")
            finding = json.loads(raw)
            if not isinstance(finding, dict):
                raise ValueError("El lead JSON debe ser un objeto.")
            print(create_finding(workspace, finding))
            return 0
        if args.command == "review":
            print(set_review(workspace, args.lead_id, args.verdict, args.summary, args.reviewer))
            return 0
        if args.command == "update":
            raw = sys.stdin.read() if args.json_path == "-" else _artifact_path(workspace, args.json_path).read_text(encoding="utf-8")
            updates = json.loads(raw)
            print(update_finding(workspace, args.lead_id, updates))
            return 0
        print(transition_finding(workspace, args.lead_id, args.to, args.actor, args.reason))
        return 0
    except (OSError, ValueError, KeyError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
