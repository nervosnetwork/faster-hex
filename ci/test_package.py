"""Regression cases for real release-artifact failures, using tiny in-memory crates."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from check_package import inspect_package


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
