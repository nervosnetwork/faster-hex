#!/usr/bin/env python3
"""Build and execute deterministic 32-bit Wasm checks with core/alloc and SIMD on/off."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, default=root / "target/wasm-runtime")
args = parser.parse_args()
out = args.out.resolve()
if out.exists() and any(out.iterdir()):
    parser.error("use a new, empty output directory for each Wasm run")
out.mkdir(parents=True, exist_ok=True)
sources = sorted((root / "src").rglob("*.rs")) + [root / "README.md", root / "Cargo.toml",
          root / "ci/check_wasm.py", root / "ci/wasm_runtime.rs", root / "ci/wasm_runtime.mjs"]
metadata = dict(commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
                git_status=subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip(),
                rustc=subprocess.check_output(["rustc", "-Vv"], text=True),
                sources={str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
                commands=[], status="running")


def save():
    (out / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")


def run(name, command):
    print(f"Running {name}", flush=True)
    with (out / f"{name}.log").open("w") as log:
        result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
    metadata["commands"].append(dict(name=name, command=command, exit_code=result.returncode))
    save()
    if result.returncode:
        metadata["status"] = "failed"
        save()
        print((out / f"{name}.log").read_text(), flush=True)
        raise SystemExit(result.returncode)


save()
executions = []
for alloc in [False, True]:
    for simd in [False, True]:
        name = ("alloc" if alloc else "core") + ("-simd128" if simd else "-scalar")
        directory = out / name
        directory.mkdir(exist_ok=True)
        flags = ["--edition=2021", "--target=wasm32-unknown-unknown", "-Copt-level=3",
                 "-Cpanic=abort", "-Ctarget-feature=" + ("+simd128" if simd else "-simd128")]
        features = ["--cfg", 'feature="alloc"'] if alloc else []
        run(name + "-library", ["rustc", "--crate-name=faster_hex", "--crate-type=rlib", *flags,
                                *features, str(root / "src/lib.rs"), "-o", str(directory / "libfaster_hex.rlib")])
        harness = ["--cfg", "alloc_api"] if alloc else []
        run(name + "-harness", ["rustc", "--crate-type=cdylib", *flags, *harness,
                                str(root / "ci/wasm_runtime.rs"), "--extern",
                                f"faster_hex={directory / 'libfaster_hex.rlib'}", "-o", str(directory / "checks.wasm")])
        executions.append((name, ["node", str(root / "ci/wasm_runtime.mjs"),
                                 str(directory / "checks.wasm"), str(directory / "results.json")]))
for name, command in executions:
    run(name + "-execute", command)
metadata["status"] = "passed"
save()
print("All four Wasm runtime configurations passed", flush=True)
