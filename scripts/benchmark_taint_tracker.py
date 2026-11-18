#!/usr/bin/env python3
"""Run a small, deterministic local benchmark for the regex JS taint tracker."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "js"
TRACKER_PATH = ROOT / "scripts" / "taint_tracker.py"


def load_tracker():
    spec = importlib.util.spec_from_file_location("mulderx_taint_tracker", TRACKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {TRACKER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def evaluate() -> dict:
    tracker = load_tracker()
    labels = {
        path.name: path.name.endswith(".vuln.js")
        for path in sorted(FIXTURES.glob("*.js"))
    }
    predictions = {}
    for name in labels:
        code = (FIXTURES / name).read_text(encoding="utf-8")
        predictions[name] = bool(tracker.scan(code, tracker.SINK_DEFS, 5, "low"))

    tp = sum(labels[name] and predictions[name] for name in labels)
    fp = sum(not labels[name] and predictions[name] for name in labels)
    fn = sum(labels[name] and not predictions[name] for name in labels)
    tn = sum(not labels[name] and not predictions[name] for name in labels)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "dataset": "Mulderx synthetic local XSS taint fixtures v1",
        "samples": len(labels),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "false_positives": [name for name in labels if not labels[name] and predictions[name]],
        "false_negatives": [name for name in labels if labels[name] and not predictions[name]],
    }


def main() -> int:
    print(json.dumps(evaluate(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
