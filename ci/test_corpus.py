"""Keep accumulated seeds across runs and preserve the old corpus on failed minimization."""
from pathlib import Path
import tempfile
import unittest

from corpus import contents, merge, replace


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


if __name__ == "__main__":
    unittest.main()
