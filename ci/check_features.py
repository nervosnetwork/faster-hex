#!/usr/bin/env python3
"""Compile downstream API contracts without dev-dependency feature unification."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib

from check_api import feature_sets

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--target")
parser.add_argument("--no-std-only", action="store_true")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
graph = tomllib.loads((root / "Cargo.toml").read_text())["features"]
# Mirror local feature implications so the Rust fixture can use ordinary cfgs.
# Direct dependencies enable no extra features: only faster-hex may grant them.
forwarded = {name: [f"faster-hex/{name}", *[
    value for value in values if value in graph or value.startswith("dep:")]]
    for name, values in graph.items()}
manifest = f'''[package]
name = "faster-hex-consumer"
version = "0.0.0"
edition = "2021"
[lib]
path = {json.dumps(str(root / "ci/consumer.rs"))}
[dependencies]
faster-hex = {{ path = {json.dumps(str(root))}, default-features = false }}
serde = {{ version = "1", default-features = false, optional = true }}
heapless = {{ version = "=0.9.4", default-features = false, optional = true }}
defmt = {{ version = "0.3", default-features = false, optional = true }}
[features]
''' + "\n".join(f"{name} = {json.dumps(values)}" for name, values in forwarded.items())
env = {**os.environ, "CARGO_TARGET_DIR": str(root / "target/feature-consumers")}
with tempfile.TemporaryDirectory(prefix="faster-hex-features-") as temporary:
    project = Path(temporary) / "Cargo.toml"
    project.write_text(manifest)
    for features in feature_sets(graph):
        if args.no_std_only and "std" in features:
            continue
        print(f"Checking {args.target or 'host'} / {','.join(features) or 'core'}", flush=True)
        command = ["cargo", "check", "--manifest-path", str(project), "--no-default-features"]
        if features:
            command += ["--features", ",".join(features)]
        if args.target:
            command += ["--target", args.target]
        subprocess.run(command, env=env, check=True)
    if not args.no_std_only:
        command = ["cargo", "check", "--manifest-path", str(project)]
        if args.target:
            command += ["--target", args.target]
        subprocess.run(command, env=env, check=True)

if args.target is None and not args.no_std_only:
    # Request the exact feature names a downstream manifest uses. The matrix
    # above also enables their implied features, which can mask a broken alias.
    logging_source = '''#![no_std]
pub fn report(error: faster_hex::Error, case: faster_hex::CheckCase) {
    defmt::warn!("{:?} {:?}", error, case);
}
'''
    for features, defmt_requirement, source in [
        (["std"], "=0.3.10", "pub use faster_hex::hex_string;\n"),
        (["defmt"], "1", logging_source),
        (["defmt-03"], "1", logging_source),
        (["defmt", "defmt-03"], "1", logging_source),
    ]:
        with tempfile.TemporaryDirectory(prefix="faster-hex-consumer-") as temporary:
            project = Path(temporary) / "Cargo.toml"
            project.write_text(f'''[package]
name = "feature-consumer"
version = "0.0.0"
edition = "2021"
[lib]
path = "lib.rs"
[dependencies]
faster-hex = {{ path = {json.dumps(str(root))}, default-features = false, features = {json.dumps(features)} }}
defmt = {json.dumps(defmt_requirement)}
''')
            project.with_name("lib.rs").write_text(source)
            print(f"Checking {','.join(features)} with defmt {defmt_requirement}", flush=True)
            subprocess.run(["cargo", "check", "--manifest-path", str(project)], env=env, check=True)
