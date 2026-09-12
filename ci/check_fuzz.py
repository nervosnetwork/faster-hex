#!/usr/bin/env python3
"""Grow and minimize a separate persistent corpus for each instrumented feature set."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from corpus import merge, replace


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=30, help="time per feature set, between 1 and 900 seconds")
    parser.add_argument("--corpus", type=Path, default=root / "target/fuzz-corpus/libfuzzer")
    parser.add_argument("--out", type=Path, default=root / "target/fuzz-results")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 900:
        parser.error("--seconds must be between 1 and 900")
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error("use a new, empty output directory for each fuzz run")
    out.mkdir(parents=True, exist_ok=True)
    corpus = args.corpus.resolve()
    env = {**os.environ, "CARGO_TARGET_DIR": os.environ.get("CARGO_TARGET_DIR", str(root / "target/fuzz"))}
    report = {"status": "running", "seconds_per_case": args.seconds, "cases": [], "commands": []}

    def save():
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(name, command):
        print(f"Running fuzz / {name}", flush=True)
        with (out / f"{name}.log").open("w") as log:
            result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
        report["commands"].append({"name": name, "command": command, "exit_code": result.returncode})
        save()
        if result.returncode:
            print((out / f"{name}.log").read_text()[-8000:], flush=True)
            raise ValueError(f"fuzz {name} failed with exit code {result.returncode}")

    try:
        run("version", ["cargo", "fuzz", "--version"])
        seeds = out / "seeds"
        run("seed", ["python3", "fuzz/seed.py", "--out", str(seeds)])
        for name, target, features in [
            ("all", "faster-hex", ["--all-features"]),
            ("core", "faster-hex", ["--no-default-features"]),
            ("alloc", "faster-hex", ["--no-default-features", "--features", "alloc"]),
            ("serde", "serde", []),
        ]:
            saved = corpus / name
            working = out / "working" / name
            case = {"name": name, "restored_and_seeded": merge([saved, seeds / target], working)}
            report["cases"].append(case)
            artifacts = out / "artifacts" / name
            artifacts.mkdir(parents=True)
            common = ["-max_len=16384", "-timeout=10", "-rss_limit_mb=2048",
                      f"-artifact_prefix={artifacts}/"]
            command = ["cargo", "fuzz", "run", *features, "--sanitizer", "address", target]
            run(name, [*command, str(working), "--", f"-max_total_time={args.seconds}",
                       "-dict=fuzz/hex.dict", *common])
            minimized = out / "minimized" / name
            minimized.mkdir(parents=True)
            # Use libFuzzer's merge mode through `run`: cargo-fuzz 0.13.2's
            # `cmin` returns success even when the underlying merge fails.
            run(name + "-minimize", [*command, str(minimized), str(working), "--", "-merge=1", *common])
            case["saved"] = replace(minimized, saved)
            save()
        report["status"] = "passed"
    except (OSError, ValueError) as error:
        report.update(status="failed", error=str(error))
        save()
        raise SystemExit(str(error)) from error
    save()
    print("Fuzz passed: all four feature sets ran and saved minimized corpora", flush=True)


if __name__ == "__main__":
    main()
