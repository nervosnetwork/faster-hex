"""Link both codec revisions into one consumer to check layout-sensitive timings."""

import json
from pathlib import Path
import shutil
import subprocess


def build_linked(checkouts, root, output, env, targets):
    benches = root / "benches"
    benches.mkdir(parents=True)
    manifest = (checkouts["head"] / "Cargo.toml").read_text()
    manifest = manifest.replace('name = "faster-hex"', 'name = "codec-comparison"', 1)
    registered = sorted(source.stem for source in (checkouts["head"] / "benches").glob("*.rs"))
    for role, checkout in checkouts.items():
        codec = root / role
        shutil.copytree(checkout, codec, ignore=shutil.ignore_patterns(".git", "target", "__pycache__"))
        codec_manifest = (checkout / "Cargo.toml").read_text().replace(
            'name = "faster-hex"', f'name = "faster-hex-{role}"', 1)
        (codec / "Cargo.toml").write_text(codec_manifest)
        manifest += f'\n[dev-dependencies.codec_{role}]\npackage = "faster-hex-{role}"\npath = "{role}"\n'
        for target in registered:
            if target == "serde":
                continue
            module = benches / target / role
            module.mkdir(parents=True)
            shutil.copytree(checkout / "benches/support", module / "support")
            entry = module / "mod.rs"
            shutil.copyfile(checkout / f"benches/{target}.rs", entry)
            for source in module.rglob("*.rs"):
                contents = source.read_text()
                if "faster_hex::" in contents or 'with = "faster_hex"' in contents:
                    source.write_text(contents + f"\nuse codec_{role} as faster_hex;\n")
            with entry.open("a") as out:
                out.write("\npub(super) fn run() { main() }\n")
    for target in registered:
        if target == "serde":
            entry = benches / "serde.rs"
            shutil.copyfile(checkouts["head"] / "benches/serde.rs", entry)
            module = benches / "serde_dispatch/mod.rs"
            module.parent.mkdir()
            shutil.copyfile(Path(__file__).with_name("bench_serde_dispatch.rs"), module)
            with entry.open("a") as out:
                out.write('\n#[path = "serde_dispatch/mod.rs"] mod faster_hex;\n')
            continue
        (benches / f"{target}.rs").write_text(
            f'#[path = "{target}/base/mod.rs"] mod base;\n'
            f'#[path = "{target}/head/mod.rs"] mod head;\n'
            'fn main() {\n'
            '    match std::env::var("FASTER_HEX_BENCH_REVISION").as_deref() {\n'
            '        Ok("base") => base::run(),\n'
            '        Ok("head") => head::run(),\n'
            '        _ => panic!("expected base or head"),\n'
            '    }\n}\n')
    (root / "Cargo.toml").write_text(manifest)
    lock = root / "Cargo.lock"
    shutil.copy(checkouts["base"] / "Cargo.lock", lock)

    def registry_checksums():
        return {line for line in lock.read_text().splitlines() if line.startswith("checksum = ")}

    pinned = registry_checksums()
    # Cargo adds the two local package identities. Registry dependencies still
    # have to match the versions and checksums from the independent builds.
    # Each local package keeps its name and source path as its revision changes.
    # Discard its artifacts before swapping slots, including compiled consumers.
    subprocess.run(["cargo", "clean", "--profile", "bench", "-p", "faster-hex-base",
                    "-p", "faster-hex-head", "-p", "codec-comparison"], cwd=root, env=env, check=True)
    command = ["cargo", "bench", "--no-run", "--message-format=json-render-diagnostics"]
    for target in targets:
        command.extend(["--bench", target])
    built = subprocess.check_output(command, cwd=root, env=env, text=True)
    if not pinned or registry_checksums() - pinned:
        raise ValueError("linked consumer changed the registry dependency lock")
    output.mkdir()
    binaries = sorted(shutil.copy2(artifact["executable"], output / artifact["target"]["name"])
                      for artifact in map(json.loads, built.splitlines())
                      if artifact.get("executable") and "bench" in artifact["target"]["kind"])
    shutil.rmtree(root)
    return binaries
