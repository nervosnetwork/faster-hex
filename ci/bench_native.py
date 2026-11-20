"""Compare two checkouts on one host with the baseline's timers and dependency lock."""

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def main():
    baseline, candidate, results = (Path(arg).resolve() for arg in sys.argv[1:])
    results.mkdir(parents=True, exist_ok=True)
    # The workflow supplies disposable checkouts. New APIs may need newer timers,
    # but comparisons of existing operations must run the identical harness.
    shutil.copytree(baseline / "benches", candidate / "benches", dirs_exist_ok=True)
    if not (baseline / "Cargo.lock").exists():
        subprocess.run(["cargo", "generate-lockfile"], cwd=baseline, check=True)
    shutil.copy(baseline / "Cargo.lock", candidate / "Cargo.lock")
    shutil.copy(baseline / "Cargo.lock", results / "Cargo.lock")

    linux = platform.system() == "Linux"
    cpu = ["lscpu"] if linux else ["sysctl", "-n", "machdep.cpu.brand_string"]
    metadata = [subprocess.check_output(cpu, text=True), subprocess.check_output(["rustc", "-vV"], text=True)]
    for checkout in (baseline, candidate):
        metadata.append(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True))
    (results / "host.txt").write_text("\n".join(metadata))
    print("".join(metadata), flush=True)

    # Pin both binaries to the same available logical CPU on Linux.
    pin = ["taskset", "-c", str(min(os.sched_getaffinity(0)))] if linux else []
    cases = (
        r"^((encode/faster_hex|rotating_encode/faster_hex)/(4|8|32|64|65|256|4096)"
        r"|decode/faster_hex_mixed/32|rotating_decode/faster_hex/32|decode_array/faster_hex/32"
        r"|invalid/decode/(first|last)/(32|4096)|format/borrowed/32)$"
    )
    command = ["cargo", "bench", "--locked", "--bench", "hex", "--bench", "check", "--bench", "format"]
    # Cargo resolves this relative to each checkout, including when the caller
    # normally points CARGO_TARGET_DIR at a shared build cache.
    env = dict(os.environ, CRITERION_HOME=str(results), CARGO_TARGET_DIR="target")
    # Build both before timing. Reversing order helps reveal drift on hosted runners.
    with (results / "binary-sizes.txt").open("w") as sizes:
        for checkout in (baseline, candidate):
            built = subprocess.check_output(command + ["--no-run", "--message-format=json"],
                                            cwd=checkout, env=env, text=True)
            for line in built.splitlines():
                artifact = json.loads(line)
                if artifact.get("executable") and "bench" in artifact["target"]["kind"]:
                    print(f"{checkout.name}/{artifact['target']['name']}", file=sizes, flush=True)
                    subprocess.run(["size", artifact["executable"]], stdout=sizes, check=True)
    for checkout, label in ((baseline, "base1"), (candidate, "head1"),
                            (candidate, "head2"), (baseline, "base2")):
        args = ["--", cases, "--warm-up-time", "0.2", "--measurement-time", "1",
                "--sample-size", "30", "--noplot", "--save-baseline", label]
        subprocess.run(pin + command + args, cwd=checkout, env=env, check=True)

    rows = ["| Case | Base 1 (ns) | Head 1 | Base 2 | Head 2 |", "|---|---:|---:|---:|---:|"]
    for first in sorted(results.rglob("base1/estimates.json")):
        case = first.parent.parent
        values = []
        for label in ("base1", "head1", "base2", "head2"):
            estimates = json.loads((case / label / "estimates.json").read_text())
            values.append((estimates["slope"] or estimates["mean"])["point_estimate"])
        rows.append(f"| {case.relative_to(results)} | " + " | ".join(f"{v:.3f}" for v in values) + " |")
    if len(rows) == 2:
        raise RuntimeError("no comparison cases ran")
    report = f"### Bench LTO {os.environ.get('CARGO_PROFILE_BENCH_LTO', 'default')}\n\n" + "\n".join(rows) + "\n"
    (results / "comparison.md").write_text(report)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as out:
            out.write(report)


if __name__ == "__main__":
    main()
