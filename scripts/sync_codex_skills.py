#!/usr/bin/env python3
"""Validate Codex skill inventory, minimum content, and direct references."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".claude" / "skills"
DESTINATION = ROOT / ".agents" / "skills"
REFERENCE_ONLY = {"xss"}
ROUTER = "mulderx-workflows"
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
FENCED_CODE = re.compile(r"(?s)```.*?```|~~~.*?~~~")


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def link_target(destination: str) -> str:
    destination = destination.strip()
    if destination.startswith("<") and ">" in destination:
        return destination[1:destination.index(">")]
    return destination.split(maxsplit=1)[0].strip()


def check_skill_references(path: Path) -> tuple[list[str], int]:
    """Check explicit references/ links in a skill entrypoint."""
    problems: list[str] = []
    checked = 0
    text = FENCED_CODE.sub("", path.read_text(encoding="utf-8-sig"))
    for raw in MARKDOWN_LINK.findall(text):
        target = link_target(raw)
        if not target or target.startswith("#") or SCHEME.match(target):
            continue
        if target.startswith(("/", "\\")) or "<" in target or ">" in target:
            continue
        path_part = target.split("#", 1)[0].split("?", 1)[0]
        path_part = path_part.removeprefix("./")
        if path_part.startswith(("targets/", "../targets/")):
            problems.append(
                f"Shared skill links into a program workspace are not allowed: "
                f"{path.relative_to(ROOT)} -> {target}"
            )
            continue
        if not path_part.startswith("references/"):
            continue
        checked += 1
        candidate = path.parent / path_part
        if not candidate.exists():
            problems.append(f"Broken skill reference in {path.relative_to(ROOT)}: {target}")
    return problems, checked


def validate() -> int:
    if not SOURCE.is_dir() or not DESTINATION.is_dir():
        print("Missing .claude/skills or .agents/skills directory.", file=sys.stderr)
        return 2

    expected = {
        slug(path.name)
        for path in SOURCE.iterdir()
        if path.is_dir() and path.name not in REFERENCE_ONLY and (path / "SKILL.md").is_file()
    }
    actual = {
        slug(path.name)
        for path in DESTINATION.iterdir()
        if path.is_dir() and (path / "SKILL.md").is_file()
    }
    expected_with_router = expected | {ROUTER}
    problems: list[str] = []
    if expected_with_router != actual:
        missing = sorted(expected_with_router - actual)
        extra = sorted(actual - expected_with_router)
        if missing:
            problems.append("Missing Codex skills: " + ", ".join(missing))
        if extra:
            problems.append("Codex-only skills without Claude source: " + ", ".join(extra))

    checked_references = 0
    for name in sorted(expected_with_router & actual):
        path = DESTINATION / name / "SKILL.md"
        text = path.read_text(encoding="utf-8-sig")
        body = re.sub(r"\A---\s*\n.*?\n---\s*\n", "", text, count=1, flags=re.DOTALL)
        if len(body.strip()) < 300:
            problems.append(f"Skill is too short to be a full playbook: {name}")
        if "Codex entrypoint" in body or "regenerate this entrypoint" in body:
            problems.append(f"Generated redirect stub found: {name}")
        reference_problems, reference_count = check_skill_references(path)
        problems.extend(reference_problems)
        checked_references += reference_count

    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(
        f"Validated {len(expected)} Codex playbooks for inventory, minimum content, "
        f"and explicit references ({checked_references} links inspected). "
        "This check does not prove semantic parity with Claude skills."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Codex skill inventory, completeness, and direct references."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run validation without modifying skill files (the default behavior).",
    )
    parser.parse_args()
    # Validation-only by design: this script never replaces authored skills.
    return validate()


if __name__ == "__main__":
    raise SystemExit(main())
