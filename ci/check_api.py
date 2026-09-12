#!/usr/bin/env python3
"""Compare public APIs under every baseline feature set, allowing compatible additions."""
import argparse
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib


def enabled_features(graph, requested):
    enabled = set(requested)
    while True:
        expanded = enabled | {dependency for feature in enabled for dependency in graph[feature]
                              if dependency in graph}
        if expanded == enabled:
            return enabled - {"default"}
        enabled = expanded


def feature_sets(graph):
    selectable = sorted(set(graph) - {"default"})
    return sorted({tuple(sorted(enabled_features(graph, selection)))
                   for count in range(len(selectable) + 1)
                   for selection in itertools.combinations(selectable, count)},
                  key=lambda value: (len(value), value))


def check_manifest(baseline, current):
    if baseline["package"]["name"] != current["package"]["name"]:
        raise ValueError("package name changed")
    old, new = baseline.get("features", {}), current.get("features", {})
    if removed := old.keys() - new.keys():
        raise ValueError(f"public features removed: {sorted(removed)}")
    if set(old.get("default", [])) != set(new.get("default", [])):
        raise ValueError("default features changed")
    for feature in old:
        if lost := enabled_features(old, [feature]) - enabled_features(new, [feature]):
            raise ValueError(f"feature {feature!r} no longer enables {sorted(lost)}")
    old_release = baseline["package"]["version"].split(".")[:2]
    new_release = current["package"]["version"].split(".")[:2]
    if old_release == new_release and baseline["package"].get("rust-version") != current["package"].get("rust-version"):
        raise ValueError("the minimum Rust version must remain fixed within the 1.0.x line")


def main():
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "ci/api-baseline.toml").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", type=Path, default=root / "Cargo.toml")
    parser.add_argument("--baseline-rev", default=config["revision"])
    parser.add_argument("--out", type=Path, default=root / "target/ci/api")
    parser.add_argument("--only", help="run one named feature set, for diagnosing a failure")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report = {"status": "running", "checks": []}

    def save():
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "--verify", args.baseline_rev + "^{commit}"], cwd=root, text=True).strip()
        report["baseline"] = revision
        version = subprocess.check_output(["cargo", "semver-checks", "--version"], text=True).strip()
        if version != "cargo-semver-checks " + config["cargo-semver-checks"]:
            raise ValueError(f"expected cargo-semver-checks {config['cargo-semver-checks']}, found {version}")
        report["tool"] = version
        archive = subprocess.check_output(["git", "archive", "--format=tar", revision], cwd=root)
        with tempfile.TemporaryDirectory(prefix="baseline-", dir=out) as temporary:
            baseline = Path(temporary)
            with tarfile.open(fileobj=io.BytesIO(archive)) as source:
                source.extractall(baseline, filter="data")
            manifest = tomllib.loads((baseline / "Cargo.toml").read_text())
            current = tomllib.loads(args.manifest_path.read_text())
            check_manifest(manifest, current)
            cases = {"-".join(features) or "core": ["--only-explicit-features", *(
                ["--features", ",".join(features)] if features else [])]
                for features in feature_sets(manifest.get("features", {}))}
            cases["default"] = ["--default-features"]
            if args.only:
                if args.only not in cases:
                    raise ValueError(f"unknown feature set {args.only!r}; choose from {list(cases)}")
                cases = {args.only: cases[args.only]}
            env = {**os.environ, "CARGO_TARGET_DIR": str(root / "target/api-cargo")}
            consumer = out / "trait-consumer"
            consumer.mkdir(exist_ok=True)
            for name, flags in cases.items():
                # Explicitly require 1.x compatibility even while both versions
                # carry prerelease suffixes or a proposed change bumps the major.
                command = ["cargo", "semver-checks", "--manifest-path", str(args.manifest_path.resolve()),
                           "--baseline-root", str(baseline), "--release-type", "minor", "--color", "never", *flags]
                print(f"Checking API / {name}", flush=True)
                with (out / f"{name}.log").open("w") as log:
                    result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
                checked = {"features": name, "command": command, "exit_code": result.returncode}
                report["checks"].append(checked)
                save()
                if result.returncode:
                    print((out / f"{name}.log").read_text()[-12000:], flush=True)
                    raise ValueError(f"API compatibility check failed for {name}")
                explicit = flags[flags.index("--features") + 1].split(",") if "--features" in flags else []
                (consumer / "Cargo.toml").write_text(f'''[package]
name = "faster-hex-api-traits"
version = "0.0.0"
edition = "2021"
[lib]
path = {json.dumps(str(root / "ci/api_traits.rs"))}
[dependencies]
faster-hex = {{ path = {json.dumps(str(args.manifest_path.resolve().parent))}, default-features = {str(name == "default").lower()}, features = {json.dumps(explicit)} }}
''')
                command = ["cargo", "check", "--manifest-path", str(consumer / "Cargo.toml")]
                with (out / f"{name}-traits.log").open("w") as log:
                    result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
                checked.update(traits_command=command, traits_exit_code=result.returncode)
                save()
                if result.returncode:
                    print((out / f"{name}-traits.log").read_text()[-12000:], flush=True)
                    raise ValueError(f"API trait contract failed for {name}")
        report["status"] = "passed"
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        report.update(status="failed", error=str(error))
        save()
        raise SystemExit(str(error)) from error
    save()
    print(f"API compatibility passed: {len(report['checks'])} feature sets against {revision}")


if __name__ == "__main__":
    main()
