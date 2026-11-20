"""Regression checks for feature contracts and fuzz corpus/coverage failures."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_api import check_manifest, feature_sets
from check_fuzz_coverage import KERNELS, kernel_counts
from corpus import contents, merge, replace


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


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def corpus(self, name, values):
        directory = self.root / name
        directory.mkdir()
        for index, value in enumerate(values):
            (directory / str(index)).write_bytes(value)
        return directory

    def test_restore_new_seeds_and_minimize_across_runs(self):
        saved = self.corpus("saved", [b"old", b"same"])
        seeds = self.corpus("seeds", [b"new", b"same"])
        working = self.root / "working"
        self.assertEqual(merge([saved, seeds], working)["files"], 3)
        minimized = self.corpus("minimized", [b"old", b"new"])
        replace(minimized, saved)
        self.assertCountEqual(contents(saved).values(), [b"old", b"new"])
        restored = self.root / "restored"
        merge([saved, seeds], restored)
        self.assertCountEqual(contents(restored).values(), [b"old", b"new", b"same"])

    def test_empty_minimization_does_not_erase_saved_seeds(self):
        saved = self.corpus("saved", [b"keep"])
        empty = self.corpus("empty", [])
        with self.assertRaisesRegex(ValueError, "empty minimization"):
            replace(empty, saved)
        self.assertEqual(list(contents(saved).values()), [b"keep"])

    def test_symlink_is_not_imported_as_fuzz_data(self):
        saved = self.corpus("saved", [b"keep"])
        source = self.corpus("source", [])
        (source / "link").symlink_to(saved / "0")
        with self.assertRaisesRegex(ValueError, "unexpected corpus entry"):
            replace(source, saved)
        self.assertEqual(list(contents(saved).values()), [b"keep"])


class AflReportTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "the AFL stub uses a POSIX shebang")
    def test_successful_but_empty_minimization_preserves_saved_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cargo = root / "cargo"
            cargo.write_text('''#!/usr/bin/env python3
from pathlib import Path
import sys
command = sys.argv[2]
if command in ("fuzz", "cmin"):
    output = Path(sys.argv[sys.argv.index("-o") + 1])
    output.mkdir(parents=True)
    if command == "fuzz":
        queue = output / "default/queue"
        queue.mkdir(parents=True)
        (queue / "id:000000").write_bytes(b"ff")
        (queue.parent / "fuzzer_stats").write_text(
            "execs_done : 10\\nsaved_crashes : 0\\nsaved_hangs : 0\\n")
    else:
        print("narrowed down to 0 files")
''')
            cargo.chmod(0o755)
            saved = root / "saved"
            saved.mkdir()
            (saved / "keep").write_bytes(b"old corpus")
            output = root / "output"
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("check_afl.py")),
                                     "--seconds", "1", "--out", str(output), "--corpus", str(saved)],
                                    capture_output=True, text=True,
                                    env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"]})
            self.assertNotEqual(result.returncode, 0)
            report = json.loads((output / "results.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertIn("empty corpus", report["error"])
            self.assertEqual(report["commands"][-1]["name"], "minimize")
            self.assertEqual(report["commands"][-1]["exit_code"], 0)
            self.assertFalse((output / "coverage").exists())
            self.assertEqual(list(contents(saved).values()), [b"old corpus"])
            self.assertIn("narrowed down to 0 files", (output / "minimize.log").read_text())


class CoverageTests(unittest.TestCase):
    def profile(self, backends):
        return {"data": [{"functions": [
            {"name": f"_RNvNtC_source{len(name)}{name}", "count": 1,
             "regions": [[1, 1, 2, 1, 1, 0, 0, 0]]}
            for backend in backends for name in KERNELS[backend]
        ]}]}

    def test_requires_raw_conversion_even_when_checked_entry_executes(self):
        for backend in ["avx2", "avx512"]:
            with self.subTest(backend=backend):
                coverage = self.profile(["scalar", backend])
                functions = coverage["data"][0]["functions"]
                name = f"hex_decode_{backend}"
                functions[:] = [f for f in functions if not f["name"].endswith(f"{len(name)}{name}")]
                with self.assertRaisesRegex(ValueError, name):
                    kernel_counts(coverage, ["scalar", backend])

    def test_rejects_unexecuted_kernel_and_does_not_count_its_closure(self):
        coverage = self.profile(["scalar"])
        functions = coverage["data"][0]["functions"]
        functions[0]["count"] = 0
        functions.append({**functions[0], "name": functions[0]["name"] + "0B5_", "count": 10})
        with self.assertRaisesRegex(ValueError, "hex_encode_custom_case_fallback"):
            kernel_counts(coverage, ["scalar"])

    def test_accepts_executed_kernels_for_each_architecture(self):
        for backends in [["scalar", "neon"], ["scalar", "sse41", "avx2"],
                         ["scalar", "sse41", "avx2", "avx512"]]:
            counts = kernel_counts(self.profile(backends), backends)
            self.assertEqual(len(counts), sum(len(KERNELS[name]) for name in backends))


if __name__ == "__main__":
    unittest.main()
