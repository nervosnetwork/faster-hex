#!/usr/bin/env python3
"""Build with AFL instrumentation, run the engine, and reject crashes or hangs."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from corpus import merge, replace

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, default=root / "target/afl-results")
parser.add_argument("--corpus", type=Path, default=root / "target/fuzz-corpus/afl")
parser.add_argument("--seconds", type=int, default=30)
parser.add_argument("--no-cmplog", action="store_true", help="disable comparison tracing on hosts with limited shared memory")
args = parser.parse_args()
if not 1 <= args.seconds <= 900:
    parser.error("--seconds must be between 1 and 900")
out = args.out.resolve()
if out.exists() and any(out.iterdir()):
    parser.error("use a new, empty output directory for each AFL run")
out.mkdir(parents=True, exist_ok=True)
target = root / "target/afl-runtime"
env = {**os.environ, "CARGO_TARGET_DIR": str(target), "AFL_NO_UI": "1", "AFL_SKIP_CPUFREQ": "1"}
report = {"status": "running", "commands": []}


def save():
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")


def run(name, command, *, env_extra=None):
    print(f"Running AFL {name}", flush=True)
    with (out / f"{name}.log").open("w") as log:
        result = subprocess.run(command, cwd=root, env={**env, **(env_extra or {})}, stdout=log, stderr=subprocess.STDOUT)
    report["commands"].append({"name": name, "command": command, "exit_code": result.returncode,
                               "env_overrides": env_extra or {}})
    save()
    if result.returncode:
        report["status"] = "failed"
        save()
        print((out / f"{name}.log").read_text()[-8000:], flush=True)
        raise SystemExit(result.returncode)


run("version", ["cargo", "afl", "--version"])
run("build", ["cargo", "afl", "build", "--manifest-path", "afl/Cargo.toml"])
seeds = out / "seeds"
corpus = args.corpus.resolve()
report["restored_and_seeded"] = merge([corpus, root / "afl/in"], seeds)
tracing = ["-c", "-"] if args.no_cmplog else []
run("fuzz", ["cargo", "afl", "fuzz", *tracing, "-i", str(seeds), "-o", str(out / "findings"),
             "-V", str(args.seconds), "-G", "8192", str(target / "debug/faster-hex-afl")])
# AFL can exit successfully after finding a crash. Its exit status alone is not
# a passing test: require actual execution and inspect the engine's statistics.
files = list((out / "findings").glob("*/fuzzer_stats"))
if len(files) != 1:
    report.update(status="failed", error="expected exactly one AFL statistics file")
else:
    statistics = dict(line.split(":", 1) for line in files[0].read_text().splitlines() if ":" in line)
    statistics = {key.strip(): value.strip() for key, value in statistics.items()}
    report["statistics"] = statistics
    try:
        passed = (int(statistics["execs_done"]) > 0 and int(statistics["saved_crashes"]) == 0
                  and int(statistics["saved_hangs"]) == 0)
    except (KeyError, ValueError):
        passed = False
    report["status"] = "passed" if passed else "failed"
save()
if report["status"] != "passed":
    raise SystemExit("AFL did not complete cleanly; inspect results.json and findings")
report["status"] = "minimizing"
save()
# Each showmap invocation must finish after one input. afl.rs otherwise defaults
# to an effectively unbounded persistent loop; batch cmin can then time out and
# silently discard every input on macOS. Fuzzing itself keeps persistent mode.
run("minimize", ["cargo", "afl", "cmin", "-i", str(files[0].parent / "queue"),
                 "-o", str(out / "minimized"), "-t", "10000", "-m", "none", "--",
                 str(target / "debug/faster-hex-afl")], env_extra={"AFL_FUZZER_LOOPCOUNT": "1"})
try:
    report["saved"] = replace(out / "minimized", corpus)
except (OSError, ValueError) as error:
    report.update(status="failed", error=str(error))
    save()
    raise SystemExit(str(error)) from error
report["status"] = "passed"
save()
print(f"AFL passed: {report['statistics']['execs_done']} executions, no crashes or hangs", flush=True)
