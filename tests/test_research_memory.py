import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "research_memory.py"


def load_module():
    spec = importlib.util.spec_from_file_location("research_memory_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ResearchMemoryTests(unittest.TestCase):
    def test_program_identity_prevents_cross_program_reuse(self):
        memory = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            memory.init_memory(workspace, "program-a")
            with self.assertRaises(ValueError):
                memory.add_record(workspace, "program-b", {
                    "kind": "asset", "title": "host", "details": "app.example.test",
                })

    def test_full_text_and_structured_filters_find_only_local_records(self):
        memory = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            memory.init_memory(workspace, "sample-program")
            memory.add_record(workspace, "sample-program", {
                "kind": "technology", "title": "Frontend framework",
                "details": "React application bundle seen on local recon evidence.",
                "endpoint": "app.example.test/search", "technology": "React",
                "vulnerability_class": "XSS", "status": "observed",
            })
            memory.add_record(workspace, "sample-program", {
                "kind": "false_positive", "title": "Encoded query reflection",
                "details": "Input was HTML-escaped in text context; discarded.",
                "endpoint": "app.example.test/help", "technology": "React",
                "vulnerability_class": "XSS", "status": "discarded",
            })
            results = memory.search_records(
                workspace, "sample-program", "React bundle",
                endpoint="app.example.test/search", technology="React", kind="technology",
            )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["title"], "Frontend framework")
            self.assertEqual(memory.search_records(workspace, "sample-program", "React", kind="finding"), [])

    def test_evidence_references_must_stay_inside_program_workspace(self):
        memory = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            memory.init_memory(workspace, "program-a")
            with self.assertRaises(ValueError):
                memory.add_record(workspace, "program-a", {
                    "kind": "test", "title": "Bad path", "details": "must reject traversal",
                    "evidence_path": "../secret.txt",
                })


if __name__ == "__main__":
    unittest.main()
