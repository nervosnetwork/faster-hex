"""Regression checks for API contracts, fuzz corpora/coverage and release artifacts."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from check_api import check_manifest, feature_sets
from check_fuzz_coverage import KERNELS, kernel_counts
from check_package import inspect_package
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


class FeatureReportTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "the compiler stub uses a POSIX shebang")
    def test_failed_consumer_preserves_diagnostics_and_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cargo = root / "cargo"
            cargo.write_text('''#!/usr/bin/env python3
from pathlib import Path
import sys
manifest = Path(sys.argv[sys.argv.index("--manifest-path") + 1])
(manifest.parent / "Cargo.lock").write_text("# failed consumer lockfile\\n")
print("intentional consumer compiler failure", file=sys.stderr)
raise SystemExit(23)
''')
            cargo.chmod(0o755)
            report = root / "report"
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("check_features.py")),
                                     "--report-dir", str(report)], capture_output=True, text=True,
                                    env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"]})
            self.assertEqual(result.returncode, 23)
            self.assertIn("intentional consumer compiler failure", result.stdout)
            records = json.loads((report / "results.json").read_text())
            self.assertEqual(records, [{"target": "host", "kind": "combination", "features": [], "exit_code": 23}])
            self.assertIn("default-features = false", (report / "core/Cargo.toml").read_text())
            self.assertIn("#![no_std]", (report / "core/src/lib.rs").read_text())
            self.assertTrue((report / "core/Cargo.lock").is_file())
            self.assertIn("intentional consumer compiler failure", (report / "core/check.log").read_text())


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
        coverage = self.profile(["scalar", "avx2"])
        functions = coverage["data"][0]["functions"]
        functions[:] = [f for f in functions if not f["name"].endswith("15hex_decode_avx2")]
        with self.assertRaisesRegex(ValueError, "hex_decode_avx2"):
            kernel_counts(coverage, ["scalar", "avx2"])

    def test_rejects_unexecuted_kernel_and_does_not_count_its_closure(self):
        coverage = self.profile(["scalar"])
        functions = coverage["data"][0]["functions"]
        functions[0]["count"] = 0
        functions.append({**functions[0], "name": functions[0]["name"] + "0B5_", "count": 10})
        with self.assertRaisesRegex(ValueError, "hex_encode_custom_case_fallback"):
            kernel_counts(coverage, ["scalar"])

    def test_accepts_executed_kernels_for_each_architecture(self):
        for backends in [["scalar", "neon"], ["scalar", "sse41", "avx2"]]:
            counts = kernel_counts(self.profile(backends), backends)
            self.assertEqual(len(counts), sum(len(KERNELS[name]) for name in backends))


class NativeValidationTests(unittest.TestCase):
    class BackendChecksReached(Exception):
        pass

    def validate(self, required, probe, *, machine="x86_64", translated=False):
        def read(command, **kwargs):
            if command[:2] == ["git", "status"]:
                return ""
            return "{}" if command[0] == "lscpu" else "fixture"

        def run(command, **kwargs):
            if command[0] == "sysctl":
                return subprocess.CompletedProcess(command, 0, stdout="1", stderr="")
            if Path(command[0]).name == "cpu-probe":
                kwargs["stdout"].write("".join(f"{key}={value}\n" for key, value in probe.items()))
            elif command[0] == "rustc" and command[1].startswith("+"):
                # Stop after qualification; mocked commands are not native evidence.
                raise self.BackendChecksReached()
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as directory:
            script = Path(__file__).with_name("native_validation.py")
            with patch.object(sys, "argv", [str(script), "--vendor", required, "--out", directory]), \
                 patch("platform.machine", return_value=machine), \
                 patch("platform.system", return_value="Darwin" if translated else "Linux"), \
                 patch("platform.platform", return_value="fixture"), \
                 patch("subprocess.check_output", side_effect=read), \
                 patch("subprocess.run", side_effect=run), \
                 patch("sys.stdout", new_callable=io.StringIO):
                runpy.run_path(str(script), run_name="__main__")

    def test_auto_accepts_each_vendor_and_explicit_vendor_stays_strict(self):
        for vendor, cpu_id in [("intel", "GenuineIntel"), ("amd", "AuthenticAMD")]:
            probe = dict(arch="x86_64", vendor=cpu_id, sse41="true", avx2="true")
            for required in ["auto", vendor]:
                with self.subTest(cpu=vendor, required=required), self.assertRaises(self.BackendChecksReached):
                    self.validate(required, probe)
            required = "amd" if vendor == "intel" else "intel"
            with self.subTest(cpu=vendor, required=required), self.assertRaisesRegex(SystemExit, "vendor=" + required):
                self.validate(required, probe)

    def test_auto_rejects_missing_isa_unknown_vendor_and_wrong_architecture(self):
        for field, value in [("sse41", "false"), ("avx2", "false"), ("avx2", None),
                             ("vendor", "unknown"), ("arch", "aarch64")]:
            probe = dict(arch="x86_64", vendor="GenuineIntel", sse41="true", avx2="true")
            probe[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(SystemExit, "SSE4.1/AVX2"):
                self.validate("auto", probe)

    def test_auto_rejects_non_x86_hosts_and_translated_execution(self):
        probe = dict(arch="x86_64", vendor="GenuineIntel", sse41="true", avx2="true")
        with self.assertRaisesRegex(SystemExit, "non-x86 host"):
            self.validate("auto", probe, machine="arm64")
        with self.assertRaisesRegex(SystemExit, "translated execution"):
            self.validate("auto", probe, translated=True)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.archive = Path(self.temporary.name) / "example.crate"
        self.files = {path: b"" for path in ["src/lib.rs", "LICENSE", "CHANGELOG.md", "MIGRATION.md",
                      "LICENSE-THIRD-PARTY/Rust Project Developers", "LICENSE-THIRD-PARTY/fast-hex"]}
        root = Path(__file__).resolve().parents[1]
        for path in ["LICENSE", "LICENSE-THIRD-PARTY/Rust Project Developers", "LICENSE-THIRD-PARTY/fast-hex"]:
            self.files[path] = (root / path).read_bytes()
        self.files.update({"Cargo.toml": b'[package]\nname = "example"\nversion = "1.0.0"\nlicense = "MIT"\n',
                           "README.md": b'[Guide](MIGRATION.md#changes) [Web](https://example.com)\n'
                                        b'[License]: <LICENSE-THIRD-PARTY/Rust%20Project%20Developers>\n',
                           ".cargo_vcs_info.json": json.dumps({"git": {"sha1": "abc123"}}).encode()})

    def inspect(self):
        with tarfile.open(self.archive, "w:gz") as archive:
            for path, data in self.files.items():
                member = tarfile.TarInfo("example-1.0.0/" + path)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return inspect_package(self.archive, "example", "1.0.0", "abc123")

    def test_complete_package(self):
        report = self.inspect()
        self.assertEqual(len(report["relative_links"]), 2)
        self.assertEqual(report["commit"], "abc123")

    def test_excluded_link_target(self):
        self.files["README.md"] += b"[Benchmarks](benches/hex.rs)"
        with self.assertRaisesRegex(ValueError, "broken packaged Markdown link"):
            self.inspect()

    def test_missing_license(self):
        del self.files["LICENSE"]
        with self.assertRaisesRegex(ValueError, "missing release files"):
            self.inspect()

    def test_empty_truncated_or_unattributed_license(self):
        path = "LICENSE-THIRD-PARTY/fast-hex"
        original = self.files[path]
        for data in [b"", original[:100], original.replace(b"Copyright (c) 2017 Zach Bjornson", b"")]:
            with self.subTest(data=data[:50]):
                self.files[path] = data
                with self.assertRaisesRegex(ValueError, "copyright or complete MIT terms"):
                    self.inspect()

    def test_manifest_license_mismatch(self):
        self.files["Cargo.toml"] = self.files["Cargo.toml"].replace(b'license = "MIT"', b'license = "Apache-2.0"')
        with self.assertRaisesRegex(ValueError, "declare the MIT license"):
            self.inspect()

    def test_dirty_or_stale_commit(self):
        for git in [{"sha1": "abc123", "dirty": True}, {"sha1": "older"}]:
            with self.subTest(git=git):
                self.files[".cargo_vcs_info.json"] = json.dumps({"git": git}).encode()
                with self.assertRaisesRegex(ValueError, "clean checked-out commit"):
                    self.inspect()


if __name__ == "__main__":
    unittest.main()
