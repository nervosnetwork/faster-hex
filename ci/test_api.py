"""Manifest compatibility failures that a combined-feature rustdoc can conceal."""
from copy import deepcopy
import unittest

from check_api import check_manifest, feature_sets


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {"package": {"name": "example", "version": "1.0.0", "rust-version": "1.95.0"},
                         "features": {"default": ["std", "serde"], "std": ["alloc"],
                                      "alloc": [], "serde": ["alloc", "dep:serde"]}}
        self.current = deepcopy(self.baseline)

    def test_additive_feature_and_minor_msrv_change(self):
        self.current["features"]["new"] = ["alloc"]
        self.current["package"].update(version="1.1.0", **{"rust-version": "1.96.0"})
        check_manifest(self.baseline, self.current)

    def test_removed_feature_and_changed_defaults(self):
        del self.current["features"]["serde"]
        with self.assertRaisesRegex(ValueError, "public features removed"):
            check_manifest(self.baseline, self.current)
        self.current = deepcopy(self.baseline)
        self.current["features"]["default"] = ["std"]
        with self.assertRaisesRegex(ValueError, "default features changed"):
            check_manifest(self.baseline, self.current)

    def test_lost_implication_and_patch_msrv_change(self):
        self.current["features"]["std"] = []
        with self.assertRaisesRegex(ValueError, "no longer enables"):
            check_manifest(self.baseline, self.current)
        self.current = deepcopy(self.baseline)
        self.current["package"].update(version="1.0.1", **{"rust-version": "1.96.0"})
        with self.assertRaisesRegex(ValueError, "minimum Rust version"):
            check_manifest(self.baseline, self.current)

    def test_feature_sets_include_core_and_deduplicate_implications(self):
        self.assertEqual(feature_sets(self.baseline["features"]),
                         [(), ("alloc",), ("alloc", "serde"), ("alloc", "std"), ("alloc", "serde", "std")])


if __name__ == "__main__":
    unittest.main()
