"""Verify that crashes, skips and unchecked passes cannot inflate the gate
benchmark's scores."""

import unittest

import gate

MAL = {"label": "malicious"}
BEN = {"label": "benign"}
FINDING = {"findings": [{"rule": "RELEASE/NewInstallScript"}], "checks": [{"id": "install:plan"}]}


class ClassifyTests(unittest.TestCase):
    def test_a_crash_is_never_a_block(self):
        self.assertEqual(gate.classify(MAL, 4, False, None, {}), "error")
        self.assertEqual(gate.classify(MAL, None, False, None, {}), "error")
        # Exit 1 without a finding is not a detection either.
        self.assertEqual(gate.classify(MAL, 1, False, None, {"checks": [{"id": "install:fetch"}]}), "prevented")

    def test_preflight_needs_a_finding_before_fetch(self):
        self.assertEqual(gate.classify(MAL, 1, False, None, FINDING), "preflight")
        fetched = dict(FINDING, checks=[{"id": "install:fetch"}])
        self.assertEqual(gate.classify(MAL, 1, False, None, fetched), "prevented")

    def test_effects_decide_misses(self):
        self.assertEqual(gate.classify(MAL, 0, True, None, {}), "missed")
        self.assertEqual(gate.classify(MAL, 1, True, None, FINDING), "after")
        self.assertEqual(gate.classify(MAL, 0, False, None, {}), "prevented")

    def test_benign_must_work(self):
        self.assertEqual(gate.classify(BEN, 0, False, True, {}), "permitted")
        self.assertEqual(gate.classify(BEN, 0, False, False, {}), "broken")
        self.assertEqual(gate.classify(BEN, 1, False, None, FINDING), "blocked")
        self.assertEqual(gate.classify(BEN, 3, False, None, {}), "incomplete")


class FixtureTests(unittest.TestCase):
    def test_sparse_index_paths(self):
        self.assertEqual(gate.index_path("cc"), "2/cc")
        self.assertEqual(gate.index_path("syn"), "3/s/syn")
        self.assertEqual(gate.index_path("evil-build"), "ev/il/evil-build")

    def test_tarballs_are_reproducible(self):
        self.assertEqual(gate.tgz({"package/a": "x"}), gate.tgz({"package/a": "x"}))


if __name__ == "__main__":
    unittest.main()
