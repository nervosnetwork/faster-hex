import unittest

from check_fuzz_coverage import KERNELS, kernel_counts


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


if __name__ == "__main__":
    unittest.main()
