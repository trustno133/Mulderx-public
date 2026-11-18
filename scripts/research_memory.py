#!/usr/bin/env python3
"""Per-program structured local research memory backed by SQLite/FTS5."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any


DB_NAME = "research_memory.sqlite3"
KINDS = {"asset", "technology", "hypothesis", "test", "false_positive", "scope", "relationship", "finding"}


def workspace_root(path: Path) -> Path:
    root = path.resolve()
    if not root.is_dir():
        raise ValueError(f"Workspace inexistente: {root}")
    return root


def db_path(workspace: Path) -> Path:
    root = workspace_root(workspace)
    path = root / DB_NAME
    if path.is_symlink():
        raise ValueError(f"La base de memoria no puede ser un symlink: {path}")
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise ValueError("La base de memoria debe permanecer dentro del workspace.") from exc
    return path


def _connect(workspace: Path, program_id: str) -> sqlite3.Connection:
    if not program_id.strip() or len(program_id) > 128:
        raise ValueError("program-id debe tener entre 1 y 128 caracteres.")
    connection = sqlite3.connect(db_path(workspace), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA journal_mode=WAL")
    row = connection.execute("SELECT value FROM metadata WHERE key='program_id'").fetchone()
    if row is None:
        connection.close()
        raise ValueError("Memoria no inicializada; ejecuta el comando init.")
    if row["value"] != program_id:
        connection.close()
        raise ValueError("El program-id no coincide con esta base; se bloqueó el acceso cruzado.")
    return connection


def init_memory(workspace: Path, program_id: str) -> Path:
    path = db_path(workspace)
    connection = sqlite3.connect(path, timeout=10)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                endpoint TEXT NOT NULL DEFAULT '',
                technology TEXT NOT NULL DEFAULT '',
                vulnerability_class TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                related_to TEXT NOT NULL DEFAULT '',
                evidence_path TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS records_kind_idx ON records(kind);
            CREATE INDEX IF NOT EXISTS records_endpoint_idx ON records(endpoint);
            CREATE INDEX IF NOT EXISTS records_technology_idx ON records(technology);
            CREATE INDEX IF NOT EXISTS records_vuln_idx ON records(vulnerability_class);
            """
        )
        try:
            connection.executescript(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
                    title, endpoint, technology, vulnerability_class, details,
                    content='records', content_rowid='id'
                );
                CREATE TRIGGER IF NOT EXISTS records_ai AFTER INSERT ON records BEGIN
                    INSERT INTO records_fts(rowid,title,endpoint,technology,vulnerability_class,details)
                    VALUES (new.id,new.title,new.endpoint,new.technology,new.vulnerability_class,new.details);
                END;
                CREATE TRIGGER IF NOT EXISTS records_ad AFTER DELETE ON records BEGIN
                    INSERT INTO records_fts(records_fts,rowid,title,endpoint,technology,vulnerability_class,details)
                    VALUES ('delete',old.id,old.title,old.endpoint,old.technology,old.vulnerability_class,old.details);
                END;
                """
            )
            fts_enabled = "1"
        except sqlite3.OperationalError:
            fts_enabled = "0"
        row = connection.execute("SELECT value FROM metadata WHERE key='program_id'").fetchone()
        if row and row[0] != program_id:
            raise ValueError("La base ya pertenece a otro program-id; no se mezcló la memoria.")
        connection.execute(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES ('program_id',?)",
            (program_id,),
        )
        connection.execute(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES ('fts5',?)",
            (fts_enabled,),
        )
        connection.commit()
    finally:
        connection.close()
    return path


def _evidence_path(workspace: Path, relative: str) -> str:
    if not relative:
        return ""
    if "\\" in relative or ":" in relative:
        raise ValueError("evidence-path debe ser relativa y usar '/'.")
    posix = PurePosixPath(relative)
    if posix.is_absolute() or any(part in {"", ".", ".."} for part in posix.parts):
        raise ValueError("evidence-path debe permanecer dentro del workspace.")
    root = workspace_root(workspace)
    resolved = (root / Path(*posix.parts)).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("evidence-path resuelve fuera del workspace.") from exc
    if not resolved.is_file():
        raise FileNotFoundError(f"No existe evidence-path: {relative}")
    return PurePosixPath(relative).as_posix()


def add_record(workspace: Path, program_id: str, record: dict[str, Any]) -> int:
    kind = record.get("kind")
    title = record.get("title")
    details = record.get("details")
    if kind not in KINDS:
        raise ValueError(f"kind debe ser uno de: {', '.join(sorted(KINDS))}")
    if not isinstance(title, str) or not title.strip() or not isinstance(details, str) or not details.strip():
        raise ValueError("title y details son obligatorios.")
    evidence = _evidence_path(workspace, record.get("evidence_path", ""))
    values = (
        kind, str(record.get("endpoint", "")), str(record.get("technology", "")),
        str(record.get("vulnerability_class", "")), str(record.get("status", "")),
        title.strip(), details.strip(), str(record.get("related_to", "")), evidence,
        datetime.now(UTC).isoformat(timespec="seconds"),
    )
    connection = _connect(workspace, program_id)
    try:
        with connection:
            cursor = connection.execute(
                """INSERT INTO records(kind,endpoint,technology,vulnerability_class,status,title,details,related_to,evidence_path,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                values,
            )
            return int(cursor.lastrowid)
    finally:
        connection.close()


def search_records(
    workspace: Path,
    program_id: str,
    query: str = "",
    *,
    endpoint: str = "",
    technology: str = "",
    vulnerability_class: str = "",
    kind: str = "",
    limit: int = 50,
) -> list[dict[str, Any]]:
    if not 1 <= limit <= 500:
        raise ValueError("limit debe estar entre 1 y 500.")
    if kind and kind not in KINDS:
        raise ValueError(f"kind debe ser uno de: {', '.join(sorted(KINDS))}")
    connection = _connect(workspace, program_id)
    try:
        filters: list[str] = []
        params: list[Any] = []
        join = ""
        if query.strip():
            # FTS5 MATCH is parameterized. For user-friendly plain text, quote
            # tokens instead of exposing FTS operators as part of the API.
            terms = re.findall(r"[\w.-]+", query)
            if not terms:
                return []
            match = " AND ".join('"' + term.replace('"', '""') + '"' for term in terms)
            join = " JOIN records_fts f ON f.rowid=r.id"
            filters.append("records_fts MATCH ?")
            params.append(match)
        for column, value in (
            ("endpoint", endpoint), ("technology", technology),
            ("vulnerability_class", vulnerability_class), ("kind", kind),
        ):
            if value:
                filters.append(f"r.{column} = ?")
                params.append(value)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        sql = f"SELECT r.* FROM records r{join}{where} ORDER BY r.id DESC LIMIT ?"
        params.append(limit)
        try:
            rows = connection.execute(sql, params).fetchall()
        except sqlite3.OperationalError as exc:
            if "fts" not in str(exc).lower() and "match" not in str(exc).lower():
                raise
            # FTS5 can be unavailable in some Python builds; retain a bounded
            # structured LIKE fallback with the same filters.
            fallback_filters = [f"r.{column} = ?" for column, value in (
                ("endpoint", endpoint), ("technology", technology),
                ("vulnerability_class", vulnerability_class), ("kind", kind),
            ) if value]
            fallback_params = [value for value in (endpoint, technology, vulnerability_class, kind) if value]
            if query.strip():
                fallback_filters.append("(r.title LIKE ? OR r.details LIKE ? OR r.endpoint LIKE ? OR r.technology LIKE ? OR r.vulnerability_class LIKE ?)")
                wildcard = f"%{query.strip()}%"
                fallback_params.extend([wildcard] * 5)
            fallback_where = " WHERE " + " AND ".join(fallback_filters) if fallback_filters else ""
            rows = connection.execute(
                f"SELECT r.* FROM records r{fallback_where} ORDER BY r.id DESC LIMIT ?",
                [*fallback_params, limit],
            ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("init", "add", "search"):
        item = sub.add_parser(command)
        item.add_argument("--workspace", type=Path, required=True)
        item.add_argument("--program-id", required=True)
        if command == "add":
            item.add_argument("--json", dest="json_path", required=True, help="JSON de registro local o '-' para stdin.")
        elif command == "search":
            item.add_argument("--query", default="")
            item.add_argument("--endpoint", default="")
            item.add_argument("--technology", default="")
            item.add_argument("--vulnerability-class", default="")
            item.add_argument("--kind", default="", choices=("", *sorted(KINDS)))
            item.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    try:
        root = workspace_root(args.workspace)
        if args.command == "init":
            print(init_memory(root, args.program_id))
            return 0
        if args.command == "add":
            raw = sys.stdin.read() if args.json_path == "-" else Path(_evidence_path(root, args.json_path)).read_text(encoding="utf-8")
            record = json.loads(raw)
            print(json.dumps({"id": add_record(root, args.program_id, record)}, ensure_ascii=True))
            return 0
        results = search_records(
            root, args.program_id, args.query, endpoint=args.endpoint,
            technology=args.technology, vulnerability_class=args.vulnerability_class,
            kind=args.kind, limit=args.limit,
        )
        print(json.dumps(results, ensure_ascii=True, indent=2))
        return 0
    except (OSError, ValueError, sqlite3.Error, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
