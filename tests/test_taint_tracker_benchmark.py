import unittest

from scripts.benchmark_taint_tracker import evaluate


class TaintTrackerBenchmarkTests(unittest.TestCase):
    def test_known_local_xss_samples_have_a_reproducible_confusion_matrix(self):
        result = evaluate()
        self.assertEqual(result["samples"], 9)
        self.assertEqual(result["tp"], 4)
        self.assertEqual(result["fp"], 3)
        self.assertEqual(result["fn"], 0)
        self.assertEqual(result["tn"], 2)
        self.assertAlmostEqual(result["precision"], 4 / 7)
        self.assertAlmostEqual(result["recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
