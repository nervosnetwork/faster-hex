"""Stage the native benchmarks with a common driver and dependency graph."""
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


def load(path):
    with path.open("rb") as source:
        return tomllib.load(source)


def set_package_version(root, version):
    manifest = root / "Cargo.toml"
    lines = manifest.read_text().splitlines(keepends=True)
    package = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith("["):
            package = line.partition("#")[0].strip() == "[package]"
        if package and line.partition("=")[0].strip() == "version":
            lines[i] = f'version = "{version}"\n'
            manifest.write_text("".join(lines))
            return
    raise ValueError(f"missing package.version in {manifest}")


def dependency_lock(root):
    lock = load(root / "Cargo.lock")
    for package in lock["package"]:
        if package["name"] == "faster-hex" and "source" not in package:
            del package["version"]
    return lock


def prepare(mode):
    if mode not in ("source", "version", "release"):
        raise ValueError(f"unknown benchmark comparison {mode!r}")
    baseline, candidate, head = map(Path, ("baseline", "candidate", "head"))
    old = load(baseline / "Cargo.toml")["package"]["version"]
    new = load(candidate / "Cargo.toml")["package"]["version"]
    source = baseline if mode == "version" else candidate
    shutil.copytree(source, head, ignore=shutil.ignore_patterns(".git", "target", "benches"))
    shutil.copytree(baseline / "benches", head / "benches")
    for root in (baseline, head):
        shutil.copyfile(candidate / ".cargo/config.toml", root / ".cargo/config.toml")

    if old != new and mode == "source":
        set_package_version(baseline, new)
    elif old != new and mode == "version":
        set_package_version(head, new)
    left = load(baseline / "Cargo.toml")["package"]["version"]
    right = load(head / "Cargo.toml")["package"]["version"]
    print(f"{mode} comparison ({old} -> {new}): baseline {left}, {source} source {right}", flush=True)

    subprocess.run(["cargo", "fetch"], cwd=baseline, check=True)
    shutil.copyfile(baseline / "Cargo.lock", head / "Cargo.lock")
    # Cargo may rebind the workspace package when its declared version differs.
    subprocess.run(["cargo", "fetch", "--offline" if left != right else "--locked"],
                   cwd=head, check=True)
    if dependency_lock(baseline) != dependency_lock(head):
        raise ValueError("the two builds resolved different dependencies")


if __name__ == "__main__":
    prepare(sys.argv[1])
