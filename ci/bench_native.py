"""Compare public codec and downstream workloads on one host with paired builds."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

from bench_linked import build_linked

CASES = {
    *(f"encode/faster_hex/{n}" for n in (2, 4, 8, 16, 20, 32, 64, 65, 256, 4096)),
    *(f"decode/faster_hex_mixed/{n}" for n in (2, 4, 20, 32, 4096)),
    *(f"rotating_encode/faster_hex/{n}" for n in (8, 32, 64)),
    "rotating_decode/faster_hex/32", "decode_array/faster_hex/32",
    "format/borrowed/32", "format/borrowed/4096", "format/alternate/32", "format/padded_upper/32",
    *(f"invalid/decode/{position}/{n}" for position in ("first", "last") for n in (1, 32, 4096)),
    *(f"serde_json/serialize_reuse/{n}" for n in (10, 32, 65, 66, 4096)),
    *(f"serde_json/serialize_text_reuse/{n}" for n in (10, 32, 65, 66, 4096)),
    *(f"serde_json/deserialize/{n}" for n in (32, 4096, 65536)),
    *(f"serde_postcard/serialize_reuse/{n}" for n in (32, 4096)),
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
    for name in ("prefix.rs", "serde.rs", "support/mod.rs", "support/format.rs"):
        shutil.copy(new / name, old / name)
    # The released crate can run all common formatting workloads. The
    # leading_digits benchmark in the development driver requires the new API.
    (old / "format.rs").write_text(
        'mod support;\n#[path = "support/format.rs"] mod format;\n'
        'criterion::criterion_group!(benches, format::formatting);\n'
        'criterion::criterion_main!(benches);\n')
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


def case_filter(cases):
    return "^(" + "|".join(re.escape(case) for case in sorted(cases)) + ")$"


def build(checkout, work, role, env, sizes, cases):
    # Cargo's package identity includes the source path. Compile both revisions
    # here so moving identical source cannot change symbol hashes or code layout.
    source = work / "source"
    shutil.copytree(checkout, source, copy_function=shutil.copy,
                    ignore=shutil.ignore_patterns(".git", "target", "__pycache__"))
    subprocess.run(["cargo", "clean", "--package", "faster-hex", "--profile", "bench"],
                   cwd=source, env=env, check=True)
    args = ["cargo", "bench", "--locked", "--no-run", "--message-format=json-render-diagnostics"]
    for name in ("hex", "check", "format", "serde", "prefix"):
        args.extend(["--bench", name])
    built = subprocess.check_output(args, cwd=source, env=env, text=True)
    binaries = []
    digests = {}
    folder = work / role
    folder.mkdir()
    for artifact in map(json.loads, built.splitlines()):
        if not artifact.get("executable") or "bench" not in artifact["target"]["kind"]:
            continue
        exe = Path(shutil.copy2(artifact["executable"], folder / artifact["target"]["name"]))
        binaries.append(exe)
        digest = hashlib.sha256(exe.read_bytes()).hexdigest()
        print(f"{role}/{exe.name} {digest}", file=sizes, flush=True)
        subprocess.run(["size", exe], stdout=sizes, check=True)
        listing = subprocess.check_output([exe, "--list", case_filter(cases)], cwd=work, env=env, text=True)
        for line in listing.splitlines():
            if line.endswith(": benchmark"):
                digests[line.removesuffix(": benchmark")] = (exe.name, digest)
    if digests.keys() != cases:
        raise ValueError(f"{role}: missing {sorted(cases - digests.keys())}, unexpected {sorted(digests.keys() - cases)}")
    shutil.rmtree(source)
    return sorted(binaries), digests


def compare(baseline, candidate, results, work):
    selection = re.compile(os.environ.get("FASTER_HEX_BENCH_FILTER", ""))
    cases = {case for case in CASES if selection.search(case)}
    if not cases:
        raise ValueError("benchmark filter selected no cases")
    results.mkdir(parents=True, exist_ok=True)
    samples = Path(tempfile.mkdtemp(prefix="samples-", dir=results))
    prepare_checkouts(baseline, candidate)
    shutil.copy(baseline / "Cargo.lock", results / "Cargo.lock")

    linux = platform.system() == "Linux"
    cpu = ["lscpu"] if linux else ["sysctl", "-n", "machdep.cpu.brand_string"]
    metadata = [subprocess.check_output(cpu, text=True), subprocess.check_output(["rustc", "-vV"], text=True)]
    revisions = [subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True)
                 for checkout in (baseline, candidate)]
    metadata.extend(revisions)
    (results / "host.txt").write_text("\n".join(metadata))
    print("".join(metadata), flush=True)

    pin = ["taskset", "-c", str(min(os.sched_getaffinity(0)))] if linux else []
    env = dict(os.environ, CRITERION_HOME=str(samples), CARGO_TARGET_DIR=str(candidate / "target/native-comparison"))
    with (results / "binary-sizes.txt").open("w") as sizes:
        base_bins, base_hashes = build(baseline, work, "base", env, sizes, cases)
        head_bins, head_hashes = build(candidate, work, "head", env, sizes, cases)

    def measure(order, cases, seconds, count, linked=None):
        runs = {}
        for label in order:
            role = "base" if label.startswith("base") else "head"
            binaries = base_bins if role == "base" else head_bins
            if linked:
                binaries, role = linked[label]
            args = ["--bench", case_filter(cases), "--warm-up-time", "1" if linked else "0.2", "--measurement-time", str(seconds),
                    "--sample-size", str(count), "--noplot", "--save-baseline", label]
            for exe in binaries:
                subprocess.run(pin + [exe] + args, cwd=work,
                               env={**env, "FASTER_HEX_BENCH_REVISION": role}, check=True)
            runs[label] = estimates(samples, label, cases)
        return runs

    runs = measure(("base1", "head1", "head2", "base2"), cases, 1, 30)
    def regressed(case, first, second):
        return slower([runs[f"base{n}"][case] for n in (first, second)],
                      [runs[f"head{n}"][case] for n in (first, second)])

    suspect = {case for case in cases if regressed(case, 1, 2)}
    if suspect:
        runs.update(measure(("head3", "base3", "base4", "head4"), suspect, 2, 40))
    repeated = {case for case in suspect if regressed(case, 3, 4)}
    same_binary = {case for case in repeated if base_hashes[case] == head_hashes[case]}
    independent = repeated - same_binary
    linked_cases = independent | {case.replace("/serialize_reuse/", "/serialize_text_reuse/")
                                  for case in independent if case.startswith("serde_json/serialize_reuse/")}
    if revisions[0] == revisions[1]:
        linked_cases.update(cases)
    if linked_cases:
        targets = sorted({base_hashes[case][0] for case in linked_cases if case in base_hashes})
        forward = build_linked({"base": baseline, "head": candidate}, work / "linked", work / "forward", env, targets)
        reverse = build_linked({"base": candidate, "head": baseline}, work / "linked", work / "reverse", env, targets)
        # Swap the library occupying each call site as well as the time order.
        # A branch or a code address that favors one slot then favors each revision once.
        slots = {"base5": (forward, "base"), "head5": (forward, "head"),
                 "head6": (reverse, "base"), "base6": (reverse, "head")}
        runs.update(measure(tuple(slots), linked_cases, 3, 50, slots))
    confirmed = {case for case in independent if all(
        slower([runs[f"base{n}"][case]], [runs[f"head{n}"][case]]) for n in (5, 6))}

    rows = [f"### Bench LTO {os.environ.get('CARGO_PROFILE_BENCH_LTO', 'default')}", "",
            "| Case (ns) | Base 1 | Head 1 | Base 2 | Head 2 | Result |",
            "|---|---:|---:|---:|---:|---|"]
    for case in sorted(cases):
        values = [runs[label][case]["point_estimate"] for label in ("base1", "head1", "base2", "head2")]
        status = ""
        if case in suspect:
            status = "confirmed slower" if case in confirmed else "not confirmed"
        if case in same_binary:
            status = "same executable, timing drift"
        if case in independent - confirmed:
            status = "slower in independent builds only"
        rows.append(f"| {case} | " + " | ".join(f"{v:.3f}" for v in values) + f" | {status} |")
    if linked_cases:
        rows.extend(["", "Each pair shares an executable. The second pair swaps library slots. Serde shares the payload type and JSON writer.", "",
                     "| Case (ns) | Base 5 | Head 5 | Base 6 | Head 6 |", "|---|---:|---:|---:|---:|"])
        for case in sorted(linked_cases):
            values = [runs[label][case]["point_estimate"] for label in ("base5", "head5", "base6", "head6")]
            rows.append(f"| {case} | " + " | ".join(f"{v:.3f}" for v in values) + " |")
    report = "\n".join(rows) + "\n"
    (results / "comparison.md").write_text(report)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as out:
            out.write(report)
    if confirmed:
        raise SystemExit("Slower in independent and shared executables: " + ", ".join(sorted(confirmed)))


def main():
    baseline, candidate, results = (Path(arg).resolve() for arg in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="faster-hex-bench-") as work:
        compare(baseline, candidate, results, Path(work))


if __name__ == "__main__":
    main()
