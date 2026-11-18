import importlib.util
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mulderx_metrics.py"


def load_module():
    spec = importlib.util.spec_from_file_location("mulderx_metrics", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class MulderxMetricsTests(unittest.TestCase):
    def test_run_id_rejects_path_traversal_and_start_does_not_overwrite(self):
        metrics = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            outside = workspace / "outside.json"
            for value in ("../outside", r"..\outside", ".", "", "a/b"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    metrics.metrics_path(workspace, value)
            run_file = metrics.start_run(workspace, "run-001", None)
            original = run_file.read_bytes()
            with self.assertRaises(FileExistsError):
                metrics.start_run(workspace, "run-001", None)
            self.assertEqual(run_file.read_bytes(), original)
            self.assertFalse(outside.exists())

    def test_parallel_snapshots_do_not_overwrite_each_other(self):
        metrics = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            metrics.start_run(workspace, "parallel-run", None)
            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(
                    lambda index: metrics.append_snapshot(workspace, "parallel-run", f"stage-{index}"),
                    range(24),
                ))
            snapshots = metrics.load_run(workspace, "parallel-run")["snapshots"]
            self.assertEqual(len(snapshots), 25)
            self.assertEqual({item["stage"] for item in snapshots[1:]}, {f"stage-{i}" for i in range(24)})

    def test_triage_candidates_ignore_headers_and_empty_sections(self):
        metrics = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "triage.md").write_text(
                """## Vectores client-side priorizados
| Vector | Endpoint/señal | Fuente | Por qué se prioriza | Conexión a server-side (si hay) |
|---|---|---|---|---|
| XSS | https://app.example/search?q | recon.md | reflexión cruda | |

## Vectores server-side (para después de client-side)
Sin candidatos en esta categoría
""",
                encoding="utf-8",
            )
            self.assertEqual(metrics.count_triage_candidates(workspace), 1)

    def test_snapshot_counts_lead_lifecycle_and_reports(self):
        metrics = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "leads.md").write_text(
                """### [L01] Confirmado
**Estado:** CONFIRMADO
### [L02] Pendiente
**Estado:** CANDIDATO
""",
                encoding="utf-8",
            )
            (workspace / "discarded.md").write_text(
                """| Lead | Tipo | Owner | Estado | Killer |
|---|---|---|---|---|
| Foo | XSS | liquid | MUERTO | encoded |
""",
                encoding="utf-8",
            )
            (workspace / "judged.md").write_text(
                """## Aprobados
### [J01] Confirmado
**Veredicto:** APROBADO — listo para Scully
## Refutados / rebajados
### [J02] No
**Killer:** sin impacto
""",
                encoding="utf-8",
            )
            reports = workspace / "reports"
            reports.mkdir()
            (reports / "finding.md").write_text("# finding\n", encoding="utf-8")
            (reports / "index.md").write_text("# index\n", encoding="utf-8")

            snapshot = metrics.collect_snapshot(workspace)

            self.assertEqual(snapshot["leads"], {"CONFIRMADO": 1, "CANDIDATO": 1, "SETUP-PENDIENTE": 0})
            self.assertEqual(snapshot["discarded"], {"MUERTO": 1, "BLOQUEADO-EXTERNO": 0})
            self.assertEqual(snapshot["judged"], {"APROBADO": 1, "REFUTADO_O_REBAJADO": 1, "INCOMPLETO": 0})
            self.assertFalse(snapshot["structured_findings"]["valid"])
            self.assertEqual(snapshot["reports"], 1)

    def test_markdown_claims_alone_never_open_judge_or_reporter_gates(self):
        metrics = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "leads.md").write_text(
                "### [L01] Confirmado\n**Estado:** CONFIRMADO\n",
                encoding="utf-8",
            )
            allowed, result = metrics.stage_gate(workspace, "judge")
            self.assertFalse(allowed)
            self.assertEqual(result["confirmed_leads"], 0)
            self.assertFalse(result["evidence_store_valid"])

            (workspace / "judged.md").write_text(
                "**Veredicto:** APROBADO — listo para Scully\n",
                encoding="utf-8",
            )
            allowed, result = metrics.stage_gate(workspace, "reporter")
            self.assertFalse(allowed)
            self.assertEqual(result["approved_findings"], 0)




if __name__ == "__main__":
    unittest.main()
