import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name)
        self.store = load_module(ROOT / "scripts" / "evidence_store.py", "evidence_store_test")
        self.metrics = load_module(ROOT / "scripts" / "mulderx_metrics.py", "metrics_test")
        self.store.init_store(self.workspace)
        self.store.create_finding(self.workspace, {
            "target": "https://app.example.test",
            "scope": ["app.example.test"],
            "lead_id": "L01",
            "vulnerability_class": "XSS",
            "affected_asset": "https://app.example.test/search",
            "actor": "unauthenticated user",
            "resource": "search response",
            "operation": "render query parameter",
            "hypothesis": "A query value reaches an executable HTML context.",
            "observations": ["Locally authored test fixture."],
            "evidence": [],
            "confidence": "medium",
            "impact": {"demonstrated": False, "description": "Not yet demonstrated."},
            "reproduction_status": "NOT_TESTED",
            "severity_proposal": "P4",
            "disproof_attempts": [],
            "next_action": "Capture baseline and controlled reproduction.",
        })

    def tearDown(self):
        self.tmp.cleanup()

    def add_artifact(self, kind: str):
        path = self.workspace / f"{kind}.txt"
        path.write_text(f"local test evidence: {kind}\n", encoding="utf-8")
        self.store.record_evidence(
            self.workspace, "L01", kind, path.name,
            f"Local {kind} evidence fixture.", "tool_capture",
        )

    def promote_to_confirmed(self):
        for kind in ("baseline", "execution", "verification", "impact"):
            self.add_artifact(kind)
        path = self.workspace / "findings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        finding = data["findings"][0]
        finding["reproduction_status"] = "REPRODUCED"
        finding["impact"] = {"demonstrated": True, "description": "Controlled impact reproduced in local test."}
        finding["severity_gate"] = {"Q1": "Yes", "Q2": "Yes", "Q3": "Yes"}
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.store.transition_finding(self.workspace, "L01", "TESTING", "liquid", "Start bounded validation.")
        self.store.transition_finding(self.workspace, "L01", "CONFIRMED", "liquid", "Required evidence validated.")

    def test_candidate_cannot_be_confirmed_without_evidence(self):
        self.store.transition_finding(self.workspace, "L01", "TESTING", "liquid", "Start bounded testing.")
        with self.assertRaises(ValueError):
            self.store.transition_finding(self.workspace, "L01", "CONFIRMED", "liquid", "Insufficient evidence.")

    def test_direct_markdown_or_status_claim_does_not_open_judge_gate(self):
        (self.workspace / "leads.md").write_text("**Estado:** CONFIRMADO\n", encoding="utf-8")
        path = self.workspace / "findings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["findings"][0]["status"] = "CONFIRMED"
        path.write_text(json.dumps(data), encoding="utf-8")
        allowed, details = self.metrics.stage_gate(self.workspace, "judge")
        self.assertFalse(allowed)
        self.assertEqual(details["confirmed_leads"], 0)
        self.assertFalse(details["evidence_store_valid"])

    def test_valid_evidence_and_lifecycle_gate_judge_then_reporter(self):
        self.promote_to_confirmed()
        allowed, details = self.metrics.stage_gate(self.workspace, "judge")
        self.assertTrue(allowed)
        self.assertEqual(details["confirmed_leads"], 1)

        (self.workspace / "judged.md").write_text("**Veredicto:** APROBADO\n", encoding="utf-8")
        self.add_artifact("judge")
        self.store.set_review(self.workspace, "L01", "APPROVED", "No contradiction found; evidence gates passed.", "mulderx")
        self.store.transition_finding(self.workspace, "L01", "REVIEWED", "mulderx", "Ocelot review recorded.")
        self.store.transition_finding(self.workspace, "L01", "APPROVED", "mulderx", "Ocelot verdict approved.")
        allowed, details = self.metrics.stage_gate(self.workspace, "reporter")
        self.assertTrue(allowed)
        self.assertEqual(details["approved_findings"], 1)

    def test_tampered_artifact_invalidates_structured_gate(self):
        self.promote_to_confirmed()
        (self.workspace / "impact.txt").write_text("changed after receipt", encoding="utf-8")
        allowed, details = self.metrics.stage_gate(self.workspace, "judge")
        self.assertFalse(allowed)
        self.assertFalse(details["evidence_store_valid"])
        self.assertTrue(any("hash no coincide" in error for error in details["evidence_store_errors"]))

    def test_hunter_cannot_record_ocelot_approval(self):
        self.promote_to_confirmed()
        self.add_artifact("judge")
        self.store.set_review(self.workspace, "L01", "APPROVED", "Review approved.", "mulderx")
        with self.assertRaises(ValueError):
            self.store.transition_finding(self.workspace, "L01", "REVIEWED", "liquid", "Try to self-review.")


if __name__ == "__main__":
    unittest.main()
