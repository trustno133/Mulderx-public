import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import scripts.bb_pipeline as pipeline


class BBPipelineTests(unittest.TestCase):
    def test_missing_bash_marks_discovery_degraded_and_falls_back_to_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            script = work_dir / "reconv2.5.sh"
            script.write_text("#!/bin/sh\n", encoding="utf-8")
            args = SimpleNamespace(only_new=False)
            with patch.object(pipeline, "SUBDOMAIN_SCRIPT", script), \
                 patch.object(pipeline, "BASH_BIN", str(work_dir / "missing-bash")), \
                 patch.object(pipeline, "log"):
                result = pipeline.stage_subdomains("example.test", work_dir, args)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["subdomains"], ["example.test"])
        self.assertIn("No se pudo iniciar", result["detail"])

    def test_corrupt_state_is_not_silently_reinitialized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pipeline_state.json"
            path.write_text("not-json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "No se pudo leer el estado"):
                pipeline.load_state(path)


if __name__ == "__main__":
    unittest.main()
