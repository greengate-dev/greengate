"""Verify that benchmark errors and skips cannot inflate detection scores."""

import unittest

import run


class ScoringTests(unittest.TestCase):
    def test_unrelated_failure_is_not_detection(self):
        self.assertEqual(run.classify(1, "compiler failed", True, False, {}), "error")
        self.assertEqual(run.classify(-11, "[PHANTOM]", True, False, {}), "error")

    def test_preflight_and_after_execution_are_distinct(self):
        message = "pre-existing package(s) with suspicious lifecycle scripts"
        self.assertEqual(run.classify(1, message, False, False, {}), "preflight")
        self.assertEqual(run.classify(1, "[PHANTOM]", True, False, {}), "after execution")

    def test_native_build_must_complete_if_installer_runs(self):
        case = {"compiler": True}
        self.assertEqual(run.classify(0, "", True, False, case), "error")
        self.assertEqual(run.classify(1, "[PHANTOM]", True, False, case), "error")
        self.assertEqual(run.classify(0, "", True, True, case), "permitted")

    def test_allowlisted_warnings_are_not_blocking_false_positives(self):
        self.assertEqual(run.classify(0, "[PHANTOM] [allowlisted]", True, True,
                                      {"compiler": True}), "permitted")

    def test_incomplete_installer_is_an_error_even_if_wrapper_succeeds(self):
        self.assertEqual(run.classify(0, "", True, False, {}, completed=False), "error")

    def test_totals_exclude_errors_and_skips(self):
        results = [
            {"label": "malicious", "trials": [{"outcome": value} for value in
             ("preflight", "after execution", "permitted", "error", "skipped")]},
            {"label": "benign", "trials": [{"outcome": value} for value in
             ("preflight", "after execution", "permitted")]},
        ]
        counts = run.totals(results)
        self.assertEqual(dict(counts), {
            "tp": 2, "preflight": 1, "fn": 1, "error": 1, "skipped": 1, "fp": 2, "tn": 1,
        })


if __name__ == "__main__":
    unittest.main()
