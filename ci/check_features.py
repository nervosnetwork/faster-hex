#!/usr/bin/env python3
"""Compile every distinct feature set and real dependency-unification consumers."""
import argparse
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--target")
parser.add_argument("--no-std-only", action="store_true")
parser.add_argument("--report-dir", type=Path, help="retain each consumer's inputs, lockfile and build log")
args = parser.parse_args()
if args.report_dir:
    args.report_dir.mkdir(parents=True, exist_ok=True)
results = []
root = Path(__file__).resolve().parents[1]
feature_graph = tomllib.loads((root / "Cargo.toml").read_text())["features"]


def enabled_features(requested):
    enabled = set(requested)
    while True:
        expanded = enabled | {dependency for feature in enabled for dependency in feature_graph[feature]
                              if dependency in feature_graph}
        if expanded == enabled:
            return sorted(enabled - {"default"})
        enabled = expanded


# std and serde imply alloc: 32 selections currently produce 20 distinct sets.
# Derive the sets from Cargo.toml so newly added features cannot be silently omitted.
selectable = sorted(set(feature_graph) - {"default"})
combinations = sorted({tuple(enabled_features(selection))
                       for count in range(len(selectable) + 1)
                       for selection in itertools.combinations(selectable, count)}, key=lambda value: (len(value), value))


def consumer(features, *, defaults=False):
    requested = [] if defaults else features
    manifest = f'''[package]
name = "faster-hex-feature-consumer"
version = "0.0.0"
edition = "2021"
[dependencies]
faster-hex = {{ path = {json.dumps(str(root))}, default-features = {str(defaults).lower()}, features = {json.dumps(requested)} }}
'''
    source = '''#![no_std]
pub fn slices() {
    let mut encoded = [0; 2];
    faster_hex::hex_encode(&[255], &mut encoded).unwrap();
    faster_hex::hex_decode_with_case(&encoded, &mut [0], faster_hex::CheckCase::Lower).unwrap();
    let _: [u8; 1] = faster_hex::hex_decode_array(&encoded).unwrap();
    let _: [u8; 1] = faster_hex::hex_decode_array_with_case(&encoded, faster_hex::CheckCase::Lower).unwrap();
}
pub fn formatted<W: core::fmt::Write>(writer: &mut W, bytes: &[u8]) -> core::fmt::Result {
    let view = faster_hex::Hex::new(bytes);
    core::write!(writer, "{view:#X}")
}
'''
    if "alloc" in features:
        source += '''extern crate alloc;
pub fn strings() {
    let mut string = faster_hex::hex_string(&[0]);
    faster_hex::hex_append_upper(&[255], &mut string);
    let _: alloc::vec::Vec<u8> = faster_hex::hex_decode_vec(b"ff").unwrap();
    let _: alloc::vec::Vec<u8> = faster_hex::hex_decode_vec_with_case(b"FF", faster_hex::CheckCase::Upper).unwrap();
}
'''
    if "heapless-08" in features:
        manifest += 'heapless = { version = "0.8", default-features = false }\n'
        source += '''pub fn heapless() {
    let _: heapless::String<2> = faster_hex::heapless_08::hex_string(&[0]).unwrap();
    let _: heapless::String<2> = faster_hex::heapless_08::hex_string_upper(&[255]).unwrap();
}
'''
    if "defmt-03" in features:
        manifest += 'defmt = { version = "0.3", default-features = false }\n'
        source += '''fn assert_defmt<T: defmt::Format>() {}
pub fn errors_and_case_support_defmt() {
    assert_defmt::<faster_hex::Error>();
    assert_defmt::<faster_hex::CheckCase>();
}
'''
    if "serde" in features:
        # Grant no serde features from this direct dependency.
        manifest += 'serde = { version = "1", default-features = false }\n'
        source += '''pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<alloc::vec::Vec<u8>, D::Error> {
    faster_hex::deserialize(d)
}
pub fn array<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
    faster_hex::array::deserialize(d)
}
pub fn optional_array<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
    faster_hex::option_nopfx_uppercase::array::deserialize(d)
}
pub fn bounded<'de, D: serde::Deserializer<'de>>(d: D) -> Result<alloc::vec::Vec<u8>, D::Error> {
    faster_hex::deserialize_bounded::<64, _, _>(d)
}
pub fn optional_bounded<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<alloc::vec::Vec<u8>>, D::Error> {
    faster_hex::option_nopfx_uppercase::deserialize_bounded::<64, _, _>(d)
}
'''
    return manifest, source


def check(project, name, features, kind):
    command = ["cargo", "check", "--manifest-path", str(project / "Cargo.toml")]
    if args.target:
        command += ["--target", args.target]
    print(f"Checking {args.target or 'host'} / {name}", flush=True)
    env = {**os.environ, "CARGO_TARGET_DIR": str(root / "target/feature-consumers")}
    destination = args.report_dir / name if args.report_dir else None
    if destination:
        destination.mkdir(parents=True, exist_ok=True)
        # Save both packages of the unification fixture, before invoking Cargo.
        for source in project.rglob("*"):
            if source.is_file() and (source.name == "Cargo.toml" or source.suffix == ".rs"):
                saved = destination / source.relative_to(project)
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, saved)
        with (destination / "check.log").open("w") as log:
            result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        if (project / "Cargo.lock").exists():
            shutil.copyfile(project / "Cargo.lock", destination / "Cargo.lock")
    else:
        result = subprocess.run(command, env=env)
    results.append(dict(target=args.target or "host", kind=kind, features=features, exit_code=result.returncode))
    if args.report_dir:
        (args.report_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    if result.returncode:
        if destination:
            print((destination / "check.log").read_text(), flush=True)
        raise SystemExit(result.returncode)


with tempfile.TemporaryDirectory(prefix="faster-hex-features-") as temporary:
    project = Path(temporary)
    (project / "src").mkdir()
    for combination in combinations:
        features = list(combination)
        if args.no_std_only and "std" in features:
            continue
        manifest, source = consumer(features)
        (project / "Cargo.toml").write_text(manifest)
        (project / "src/lib.rs").write_text(source)
        check(project, "-".join(features) or "core", features, "combination")

    defaults = enabled_features(["default"])
    if not args.no_std_only or "std" not in defaults:
        manifest, source = consumer(defaults, defaults=True)
        (project / "Cargo.toml").write_text(manifest)
        (project / "src/lib.rs").write_text(source)
        check(project, "default-dependency", defaults, "default")

    # The root asks only for alloc. Its peer activates Serde, defmt and heapless.
    # Both must retain String's identity and the same versioned heapless type.
    union = enabled_features(["alloc", "serde", "defmt-03", "heapless-08"])
    manifest, source = consumer(["alloc"])
    manifest += 'peer = { path = "peer" }\nheapless = { version = "0.8", default-features = false }\n'
    source += '''pub fn shared_types() {
    let _: alloc::string::String = faster_hex::hex_string(&[0]);
    let _: alloc::string::String = peer::text();
    let _: heapless::String<2> = faster_hex::heapless_08::hex_string(&[0]).unwrap();
    let _: heapless::String<2> = peer::fixed();
}
'''
    (project / "Cargo.toml").write_text(manifest)
    (project / "src/lib.rs").write_text(source)
    (project / "peer/src").mkdir(parents=True)
    (project / "peer/Cargo.toml").write_text(f'''[package]
name = "peer"
version = "0.0.0"
edition = "2021"
[dependencies]
faster-hex = {{ path = {json.dumps(str(root))}, default-features = false, features = ["serde", "defmt-03", "heapless-08"] }}
heapless = {{ version = "0.8", default-features = false }}
''')
    (project / "peer/src/lib.rs").write_text('''#![no_std]
extern crate alloc;
pub fn text() -> alloc::string::String { faster_hex::hex_string(&[0]) }
pub fn fixed() -> heapless::String<2> { faster_hex::heapless_08::hex_string(&[0]).unwrap() }
''')
    check(project, "dependency-unification", union, "unification")
print(f"Passed {len(results)} independent consumer checks", flush=True)
