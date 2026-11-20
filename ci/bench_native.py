"""Compare public codec and downstream workloads on one host with paired builds."""

import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile


CASES = {
    *(f"encode/faster_hex/{n}" for n in (2, 4, 8, 20, 32, 64, 65, 256, 4096)),
    *(f"decode/faster_hex_mixed/{n}" for n in (2, 20, 32, 4096)),
    *(f"rotating_encode/faster_hex/{n}" for n in (8, 32, 64)),
    "rotating_decode/faster_hex/32", "decode_array/faster_hex/32", "format/borrowed/32",
    *(f"invalid/decode/{position}/{n}" for position in ("first", "last") for n in (32, 4096)),
    *(f"serde_json/serialize_reuse/{n}" for n in (10, 32, 65, 66, 4096)),
    *(f"serde_json/deserialize/{n}" for n in (32, 4096, 65536)),
    *(f"git_prefix/{operation}/{size}b_{digits}digits" for operation in ("buffer", "display")
      for size, digits in ((20, 7), (20, 8), (20, 40), (32, 7), (32, 64))),
}


def prepare_checkouts(baseline, candidate):
    # The caller supplies disposable checkouts. The new workloads run with the
    # same timers on both sides. Only the Git prefix adapter follows the revision.
    old = baseline / "benches"
    new = candidate / "benches"
    if not (old / "prefix.rs").exists():
        shutil.copy(candidate / "ci/bench_prefix_v2.rs", old / "support/prefix.rs")
        with (baseline / "Cargo.toml").open("a") as manifest:
            manifest.write('\n[[bench]]\nname = "prefix"\nharness = false\nrequired-features = ["std"]\n')
    for name in ("prefix.rs", "serde.rs", "support/mod.rs"):
        shutil.copy(new / name, old / name)
    shutil.copytree(old, new, dirs_exist_ok=True, ignore=shutil.ignore_patterns("prefix.rs"))
    if not (baseline / "Cargo.lock").exists():
        subprocess.run(["cargo", "generate-lockfile"], cwd=baseline, check=True)
    shutil.copy(baseline / "Cargo.lock", candidate / "Cargo.lock")


def estimates(samples, label, cases):
    values = {}
    for info in samples.rglob(f"{label}/benchmark.json"):
        case = json.loads(info.read_text())["full_id"]
        stats = json.loads(info.with_name("estimates.json").read_text())
        values[case] = stats["slope"] or stats["mean"]
    if values.keys() != cases:
        raise ValueError(f"{label}: missing {sorted(cases - values.keys())}, unexpected {sorted(values.keys() - cases)}")
    return values


def slower(base, head):
    # Require separation across both run orders, including variation between
    # the two estimates for the same revision. A second experiment must agree.
    return (min(v["confidence_interval"]["lower_bound"] for v in head)
            > max(v["confidence_interval"]["upper_bound"] for v in base))


def main():
    baseline, candidate, results = (Path(arg).resolve() for arg in sys.argv[1:])
    results.mkdir(parents=True, exist_ok=True)
    samples = Path(tempfile.mkdtemp(prefix="samples-", dir=results))
    prepare_checkouts(baseline, candidate)
    shutil.copy(baseline / "Cargo.lock", results / "Cargo.lock")

    linux = platform.system() == "Linux"
    cpu = ["lscpu"] if linux else ["sysctl", "-n", "machdep.cpu.brand_string"]
    metadata = [subprocess.check_output(cpu, text=True), subprocess.check_output(["rustc", "-vV"], text=True)]
    for checkout in (baseline, candidate):
        metadata.append(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True))
    (results / "host.txt").write_text("\n".join(metadata))
    print("".join(metadata), flush=True)

    pin = ["taskset", "-c", str(min(os.sched_getaffinity(0)))] if linux else []
    command = ["cargo", "bench", "--locked", "--bench", "hex", "--bench", "check",
               "--bench", "format", "--bench", "serde", "--bench", "prefix"]
    env = dict(os.environ, CRITERION_HOME=str(samples), CARGO_TARGET_DIR="target")
    with (results / "binary-sizes.txt").open("w") as sizes:
        for checkout in (baseline, candidate):
            built = subprocess.check_output(command + ["--no-run", "--message-format=json"],
                                            cwd=checkout, env=env, text=True)
            for line in built.splitlines():
                artifact = json.loads(line)
                if artifact.get("executable") and "bench" in artifact["target"]["kind"]:
                    print(f"{checkout.name}/{artifact['target']['name']}", file=sizes, flush=True)
                    subprocess.run(["size", artifact["executable"]], stdout=sizes, check=True)

    def measure(order, cases, seconds, count):
        pattern = "^(" + "|".join(re.escape(case) for case in sorted(cases)) + ")$"
        runs = {}
        for label in order:
            checkout = baseline if label.startswith("base") else candidate
            args = ["--", pattern, "--warm-up-time", "0.2", "--measurement-time", str(seconds),
                    "--sample-size", str(count), "--noplot", "--save-baseline", label]
            subprocess.run(pin + command + args, cwd=checkout, env=env, check=True)
            runs[label] = estimates(samples, label, cases)
        return runs

    runs = measure(("base1", "head1", "head2", "base2"), CASES, 1, 30)
    def regressed(case, first, second):
        return slower([runs[f"base{n}"][case] for n in (first, second)],
                      [runs[f"head{n}"][case] for n in (first, second)])

    suspect = {case for case in CASES if regressed(case, 1, 2)}
    if suspect:
        runs.update(measure(("head3", "base3", "base4", "head4"), suspect, 2, 40))
    confirmed = {case for case in suspect if regressed(case, 3, 4)}

    rows = [f"### Bench LTO {os.environ.get('CARGO_PROFILE_BENCH_LTO', 'default')}", "",
            "| Case (ns) | Base 1 | Head 1 | Base 2 | Head 2 | Retest |",
            "|---|---:|---:|---:|---:|---|"]
    for case in sorted(CASES):
        values = [runs[label][case]["point_estimate"] for label in ("base1", "head1", "base2", "head2")]
        status = "confirmed slower" if case in confirmed else "not confirmed" if case in suspect else ""
        rows.append(f"| {case} | " + " | ".join(f"{v:.3f}" for v in values) + f" | {status} |")
    report = "\n".join(rows) + "\n"
    (results / "comparison.md").write_text(report)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as out:
            out.write(report)
    if confirmed:
        raise SystemExit("Confirmed slower in both experiments: " + ", ".join(sorted(confirmed)))


if __name__ == "__main__":
    main()
