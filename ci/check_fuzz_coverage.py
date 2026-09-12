#!/usr/bin/env python3
"""Replay minimized corpora and require measured execution inside every available kernel."""
import argparse
import json
import os
from pathlib import Path
import subprocess


KERNELS = {
    "scalar": ["hex_encode_custom_case_fallback", "hex_encode_pairs",
               "hex_check_fallback_with_case", "hex_decode_fallback"],
    "sse41": ["hex_encode_sse41", "encode_sse41_16", "hex_check_sse_with_case",
              "hex_decode_sse41_checked", "hex_decode_sse41", "decode_sse41_block",
              "decode_sse41_nibbles", "pack_sse41"],
    "avx2": ["hex_encode_avx2", "encode_avx2_32", "hex_check_avx2_with_case",
             "hex_decode_avx2_checked", "hex_decode_avx2", "decode_avx2_block",
             "decode_avx2_nibbles", "pack_avx2"],
    "neon": ["hex_encode_neon", "encode_neon_8", "encode_neon_16",
             "hex_check_neon_with_case", "hex_check_neon_short",
             "hex_decode_short_neon", "hex_decode_bounded_neon", "hex_decode_neon",
             "decode_neon_block", "decode_neon_nibbles"],
}


def kernel_counts(coverage, backends):
    if not backends or "scalar" not in backends or set(backends) - KERNELS.keys():
        raise ValueError(f"invalid measured backend list: {backends}")
    functions = [function for unit in coverage["data"] for function in unit["functions"]]
    measured = {}
    for name in [kernel for backend in backends for kernel in KERNELS[backend]]:
        # All kernels are non-generic; v0 symbols end in their identifier. Exclude
        # closures and `*_checked` so they cannot stand in for the raw conversion.
        matches = [f for f in functions if f["name"].endswith(f"{len(name)}{name}")]
        regions = [region for f in matches for region in f["regions"] if region[7] == 0]
        measured[name] = {"executions": sum(f["count"] for f in matches),
                          "regions_hit": sum(region[4] > 0 for region in regions),
                          "regions_total": len(regions)}
    missing = [name for name, counts in measured.items() if counts["executions"] == 0]
    if missing:
        raise ValueError(f"corpus did not execute required core functions: {', '.join(missing)}")
    return measured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, default=Path("target/fuzz-coverage"))
    parser.add_argument("--require-backends", default=os.environ.get("FUZZ_REQUIRED_BACKENDS", ""),
                        help="comma-separated backends that this runner must execute")
    args = parser.parse_args()
    required = [name.strip() for name in args.require_backends.split(",") if name.strip()]
    if set(required) - KERNELS.keys():
        parser.error("unknown required backend")
    root = Path(__file__).resolve().parents[1]
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error("use a new, empty output directory for each coverage replay")
    out.mkdir(parents=True, exist_ok=True)
    report = {"status": "running", "corpora": [str(path.resolve()) for path in args.corpus],
              "required_backends": required, "commands": []}
    env = {**os.environ, "LLVM_PROFILE_FILE": str(out / "replay-%p.profraw")}

    def save():
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(name, command):
        with (out / f"{name}.log").open("w") as log:
            result = subprocess.run([str(arg) for arg in command], cwd=root, env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
        report["commands"].append({"name": name, "command": [str(arg) for arg in command],
                                   "exit_code": result.returncode})
        save()
        if result.returncode:
            raise ValueError(f"{name} failed: {(out / f'{name}.log').read_text()[-8000:]}")
        return (out / f"{name}.log").read_text()

    try:
        version = run("rustc", ["rustc", "-vV"])
        report["rustc"] = version
        host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
        sysroot = Path(run("sysroot", ["rustc", "--print", "sysroot"]).strip())
        llvm = sysroot / "lib/rustlib" / host / "bin"
        for name in ["llvm-cov", "llvm-profdata"]:
            if not (llvm / name).is_file():
                raise ValueError("install llvm-tools-preview for the active Rust toolchain")
        # No dependency download or optional feature is needed to measure these
        # kernels. Instrument the real library sources, not a copy of the codec.
        flags = ["--cfg", "fuzzing", "-C", "instrument-coverage", "-C", "opt-level=1",
                 "-C", "codegen-units=1", "-C", "symbol-mangling-version=v0", "-D", "warnings"]
        library = out / "libfaster_hex.rlib"
        binary = out / "replay"
        run("library", ["rustc", "--edition=2018", "--crate-type=rlib", "--crate-name=faster_hex",
                        *flags, "src/lib.rs", "-o", library])
        run("driver", ["rustc", "--edition=2021", *flags, "ci/fuzz_coverage.rs",
                       "--extern", f"faster_hex={library}", "-o", binary])
        output = run("replay", [binary, *report["corpora"]])
        report["backends"] = [line.split("=", 1)[1] for line in output.splitlines() if line.startswith("backend=")]
        if missing := set(required) - set(report["backends"]):
            raise ValueError(f"runner did not execute required backends: {sorted(missing)}")
        report["inputs"] = int(next(line.split("=", 1)[1] for line in output.splitlines() if line.startswith("inputs=")))
        profile = out / "replay.profdata"
        run("merge", [llvm / "llvm-profdata", "merge", "-sparse", *out.glob("*.profraw"), "-o", profile])
        exported = run("export", [llvm / "llvm-cov", "export", binary, f"-instr-profile={profile}"])
        coverage = json.loads(exported)
        report["kernels"] = kernel_counts(coverage, report["backends"])
        run("summary", [llvm / "llvm-cov", "report", binary, f"-instr-profile={profile}",
                        str(root / "src/encode.rs"), str(root / "src/decode.rs")])
        run("html", [llvm / "llvm-cov", "show", binary, f"-instr-profile={profile}",
                     "-format=html", f"-output-dir={out / 'html'}"])
        report["status"] = "passed"
    except (OSError, ValueError, KeyError, StopIteration) as error:
        report.update(status="failed", error=str(error))
        save()
        raise SystemExit(str(error)) from error
    save()
    print(f"Core coverage passed: {report['inputs']} corpus inputs, {', '.join(report['backends'])}", flush=True)


if __name__ == "__main__":
    main()
