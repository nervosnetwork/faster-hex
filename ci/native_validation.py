#!/usr/bin/env python3
"""Verify native Intel/AMD backends; require both ISAs and reject translated execution."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--vendor", choices=["auto", "intel", "amd"], required=True,
                    help="auto accepts either Intel or AMD; explicit vendors must match")
parser.add_argument("--nightly", default=os.environ.get("NIGHTLY_TOOLCHAIN", "nightly-2026-08-21"))
parser.add_argument("--out", type=Path, default=root / "target/native-validation")
args = parser.parse_args()
out = args.out.resolve()
if out.exists() and any(out.iterdir()):
    parser.error("use a new, empty output directory for each validation run")
out.mkdir(parents=True, exist_ok=True)
records = []
base = {**os.environ, "RUSTUP_TOOLCHAIN": "1.95.0", "CARGO_TERM_COLOR": "never",
        "CARGO_TARGET_DIR": str(root / "target/native-cargo")}


def read(command):
    return subprocess.check_output(command, cwd=root, env=base, text=True).strip()


def save(name, data):
    (out / name).write_text(json.dumps(data, indent=2) + "\n")


def run(name, command, extra=None):
    extra = extra or {}
    print(f"Running {name}", flush=True)
    start = time.monotonic()
    with (out / f"{name}.log").open("w") as log:
        result = subprocess.run(command, cwd=root, env={**base, **extra}, stdout=log, stderr=subprocess.STDOUT)
    locks = {}
    for source, saved in [(root / "Cargo.lock", "root-Cargo.lock"), (root / "fuzz/Cargo.lock", "fuzz-Cargo.lock")]:
        if source.exists():
            (out / "locks").mkdir(exist_ok=True)
            shutil.copyfile(source, out / "locks" / saved)
            locks[saved] = hashlib.sha256(source.read_bytes()).hexdigest()
    records.append(dict(name=name, command=command, environment=extra, lock_sha256=locks,
                        seconds=round(time.monotonic() - start, 2), exit_code=result.returncode))
    save("commands.json", records)
    if result.returncode:
        print((out / f"{name}.log").read_text()[-12000:], flush=True)
        raise SystemExit(result.returncode)
    return (out / f"{name}.log").read_text()


def test_completed(log, name):
    # With --test-threads=1, capture one test record up to the next test or
    # summary. An ignored test or a name mentioned in diagnostics is insufficient.
    record = re.search(r"^test [^\n ]*::" + re.escape(name) + r" \.\.\.(.*?)(?=^test |\Z)", log, re.M | re.S)
    return record is not None and record.group(1).strip().splitlines()[-1:] == ["ok"]


metadata = dict(commit=read(["git", "rev-parse", "HEAD"]),
                git_status=read(["git", "status", "--porcelain"]),
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                rustc=read(["rustc", "-Vv"]), platform=platform.platform(), machine=platform.machine(),
                expected_vendor=args.vendor,
                nightly_toolchain=args.nightly,
                runner={key: os.environ.get(key) for key in ["RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion",
                        "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]},
                limitations="Native instruction execution on hosted runners; these checks do not measure performance.")
save("environment.json", metadata)
if metadata["git_status"]:
    raise SystemExit("Commit source changes before recording native evidence for HEAD")
if platform.machine().lower() not in ["x86_64", "amd64"]:
    raise SystemExit("Refusing native x86 evidence on a non-x86 host")
if platform.system() == "Darwin":
    translated = subprocess.run(["sysctl", "-n", "sysctl.proc_translated"], capture_output=True, text=True)
    metadata["translation_probe"] = dict(exit_code=translated.returncode, stdout=translated.stdout, stderr=translated.stderr)
    metadata["cpu"] = read(["sysctl", "-n", "machdep.cpu.brand_string"])
    save("environment.json", metadata)
    if translated.returncode == 0 and translated.stdout.strip() != "0":
        raise SystemExit("Refusing translated execution as native evidence")
else:
    metadata["cpu"] = json.loads(read(["lscpu", "--json"]))
    save("environment.json", metadata)
run("build-cpu-probe", ["rustc", "--edition=2021", "ci/cpu_probe.rs", "-o", str(out / "cpu-probe")])
probe = dict(line.split("=", 1) for line in run("cpu-probe", [str(out / "cpu-probe")]).splitlines())
metadata["cpu_probe"] = probe
save("environment.json", metadata)
vendors = {"intel": "GenuineIntel", "amd": "AuthenticAMD"}
expected = probe.get("vendor") if args.vendor == "auto" else vendors[args.vendor]
if (expected not in vendors.values()
        or probe != dict(arch="x86_64", vendor=expected, sse41="true", avx2="true")):
    raise SystemExit(f"This runner does not satisfy vendor={args.vendor} and SSE4.1/AVX2 requirements: {probe}")
metadata["nightly_rustc"] = run("nightly-rustc", ["rustc", f"+{args.nightly}", "-Vv"]).strip()
metadata["cargo_fuzz"] = run("cargo-fuzz-version", ["cargo", f"+{args.nightly}", "fuzz", "--version"]).strip()
save("environment.json", metadata)

required_tests = ["forced_backends_preserve_order_at_independent_alignments",
                  "forced_backends_check_every_byte_in_every_lane_before_writing",
                  "conversions_and_checks_stop_at_guard_pages"]
for name, flags, extra in [("test-debug", [], {}), ("test-release", ["--release"], {}),
                           ("test-static-avx2", ["--release"], {"RUSTFLAGS": "-Ctarget-feature=+avx2"})]:
    # The main workflow covers public integration tests and packaging. This job
    # proves the forced kernels and guard-page tests ran on the recorded CPU.
    log = run(name, ["cargo", "test", "--lib", "--all-features", *flags,
                     "--", "--nocapture", "--test-threads=1"], extra)
    coverage = {test: test_completed(log, test) for test in required_tests}
    coverage["sse41_and_avx2_executed"] = "forced x86 backends: SSE4.1=true, AVX2=true" in log
    save(f"{name}-coverage.json", coverage)
    if not all(coverage.values()):
        raise SystemExit(f"{name} did not execute the required backend and guard-page tests")
run("fuzz", [sys.executable, "ci/check_fuzz.py", "--out", str(out / "fuzz"),
             "--corpus", str(out / "corpus")],
    {"RUSTUP_TOOLCHAIN": args.nightly, "CARGO_TARGET_DIR": str(root / "target/native-fuzz"),
     "FUZZ_REQUIRED_BACKENDS": "scalar,sse41,avx2"})

save("complete.json", dict(commit=metadata["commit"], vendor=probe["vendor"], status="passed",
                            timestamp_utc=datetime.now(timezone.utc).isoformat()))
print("Native validation passed", flush=True)
