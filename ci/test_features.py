"""Check that a consumer compiler failure remains actionable in CI artifacts."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main()
