#!/usr/bin/env python3
"""Check a built crate's release documents, local links and clean Git provenance."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import tarfile
import tomllib
from urllib.parse import unquote, urlsplit


def inspect_package(archive, name, version, commit):
    prefix = f"{name}-{version}/"
    with tarfile.open(archive, "r:gz") as package:
        files = {}
        for member in package.getmembers():
            if member.isdir():
                continue
            if not member.isfile() or not member.name.startswith(prefix):
                raise ValueError(f"unexpected package member: {member.name}")
            path = member.name[len(prefix):]
            if path.startswith("/") or ".." in PurePosixPath(path).parts or path in files:
                raise ValueError(f"invalid or duplicate package path: {path}")
            files[path] = package.extractfile(member).read()

    required = {"Cargo.toml", "src/lib.rs", "README.md", "LICENSE", "CHANGELOG.md", "MIGRATION.md",
                ".cargo_vcs_info.json", "LICENSE-THIRD-PARTY/Rust Project Developers",
                "LICENSE-THIRD-PARTY/fast-hex", "LICENSE-THIRD-PARTY/const-hex"}
    if missing := required - files.keys():
        raise ValueError(f"missing release files: {sorted(missing)}")
    vcs = json.loads(files[".cargo_vcs_info.json"])
    if vcs.get("git", {}).get("sha1") != commit or vcs.get("git", {}).get("dirty", False):
        raise ValueError(f"package must identify the clean checked-out commit {commit}: {vcs}")
    manifest = tomllib.loads(files["Cargo.toml"].decode())
    if (manifest["package"]["name"], manifest["package"]["version"]) != (name, version):
        raise ValueError("packaged manifest name/version differs from the checkout")
    if manifest["package"].get("license") != "MIT":
        raise ValueError("packaged manifest must declare the MIT license")
    # Check the grant, inclusion condition and disclaimer, not just filenames:
    # an empty or truncated notice is not a usable license in a release archive.
    notices = {"LICENSE": "Copyright (c) 2018 Nervos Foundation",
               "LICENSE-THIRD-PARTY/Rust Project Developers": "Copyright (c) 2017 The Rust Project Developers",
               "LICENSE-THIRD-PARTY/fast-hex": "Copyright (c) 2017 Zach Bjornson",
               "LICENSE-THIRD-PARTY/const-hex": "const-hex 1.19.1"}
    grant = " ".join(files["LICENSE"].decode().split()).split("Permission is hereby granted", 1)
    ending = "THE SOFTWARE."
    if len(grant) != 2 or ending not in grant[1]:
        raise ValueError("incomplete MIT license text")
    terms = "Permission is hereby granted" + grant[1].split(ending, 1)[0] + ending
    if not all(clause in terms for clause in ["free of charge", "this permission notice shall be included",
                                              'THE SOFTWARE IS PROVIDED "AS IS"', "LIABILITY"]):
        raise ValueError("incomplete MIT license text")
    for path, holder in notices.items():
        text = " ".join(files[path].decode().split())
        if holder not in text or terms not in text:
            raise ValueError(f"missing original copyright or complete MIT terms: {path}")

    links = []
    for path, content in files.items():
        if not path.endswith(".md"):
            continue
        markdown = content.decode()
        # Inline/image links and reference definitions; anchors and remote links
        # need no archive member. This checks destinations, not Markdown rendering.
        destinations = re.findall(r"\]\(\s*(<[^>]*>|[^\s)]+)", markdown)
        destinations += re.findall(r"(?m)^ {0,3}\[[^\]\n]+\]:\s*(<[^>]*>|[^\s]+)", markdown)
        for destination in destinations:
            url = urlsplit(destination.strip("<>"))
            if url.scheme or url.netloc or not url.path:
                continue
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), unquote(url.path)))
            if target not in files and not any(file.startswith(target + "/") for file in files):
                raise ValueError(f"broken packaged Markdown link: {path} -> {destination}")
            links.append(dict(source=path, destination=destination, member=target))
    return dict(archive=str(archive), sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                bytes=archive.stat().st_size, commit=commit, files=sorted(files), relative_links=links)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--report", type=Path, default=Path("target/ci/package.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = tomllib.loads((root / "Cargo.toml").read_text())["package"]
    target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
    archive = args.archive or target / "package" / f"{manifest['name']}-{manifest['version']}.crate"
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        report = inspect_package(archive, manifest["name"], manifest["version"], commit)
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        args.report.write_text(json.dumps(dict(status="failed", error=str(error)), indent=2) + "\n")
        raise SystemExit(str(error)) from error
    report["status"] = "passed"
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Package verified: {len(report['files'])} files, {len(report['relative_links'])} local links; {commit}")


if __name__ == "__main__":
    main()
