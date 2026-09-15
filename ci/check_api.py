#!/usr/bin/env python3
"""Compare public APIs under every baseline feature set, allowing compatible additions."""
import itertools
import os
from pathlib import Path
import subprocess
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
    revision = config["revision"]
    baseline = tomllib.loads(subprocess.check_output(
        ["git", "show", f"{revision}:Cargo.toml"], cwd=root, text=True))
    current = tomllib.loads((root / "Cargo.toml").read_text())
    check_manifest(baseline, current)
    version = subprocess.check_output(["cargo", "semver-checks", "--version"], text=True).strip()
    if version != "cargo-semver-checks " + config["cargo-semver-checks"]:
        raise SystemExit(f"expected cargo-semver-checks {config['cargo-semver-checks']}, found {version}")
    env = {**os.environ, "CARGO_TARGET_DIR": str(root / "target/api-cargo")}
    cases = {",".join(features) or "core": ["--only-explicit-features", *(
        ["--features", ",".join(features)] if features else [])]
        for features in feature_sets(baseline["features"])}
    cases["default"] = ["--default-features"]
    for name, flags in cases.items():
        print(f"Checking API / {name}", flush=True)
        # Require compatibility even while versions carry prerelease suffixes.
        subprocess.run(["cargo", "semver-checks", "--baseline-rev", revision,
                        "--release-type", "minor", *flags], cwd=root, env=env, check=True)
    print(f"API compatibility passed: {len(cases)} feature sets against {revision}")


if __name__ == "__main__":
    main()
