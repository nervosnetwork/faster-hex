#!/usr/bin/env python3
"""Bounded native measurements for this experimental branch; no production gate."""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import time

root = Path(__file__).resolve().parents[1]
out = root / "target/native-benchmark"
out.mkdir(parents=True)
records = []
env = {**os.environ, "CARGO_TERM_COLOR": "never", "CRITERION_HOME": str(out / "criterion")}
assert not env.get("RUSTFLAGS") and not env.get("CARGO_ENCODED_RUSTFLAGS")
if platform.machine().lower() not in ["x86_64", "amd64"]:
    raise SystemExit("Native x86 required")
if platform.system() == "Darwin":
    translated = subprocess.run(["sysctl", "-n", "sysctl.proc_translated"], capture_output=True, text=True)
    if translated.returncode == 0 and translated.stdout.strip() != "0":
        raise SystemExit("Translated execution is not native evidence")


def run(name, command, extra=None, cwd=root):
    print("Running " + name, flush=True)
    start = time.monotonic()
    with (out / (name + ".log")).open("w") as log:
        result = subprocess.run(command, cwd=cwd, env={**env, **(extra or {})}, stdout=log, stderr=subprocess.STDOUT)
    records.append(dict(name=name, command=command, cwd=str(cwd), environment=extra or {},
                        seconds=time.monotonic() - start, exit_code=result.returncode))
    (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
    if result.returncode:
        print((out / (name + ".log")).read_text()[-12000:])
        raise SystemExit(result.returncode)
    return (out / (name + ".log")).read_text()


def read(command):
    return subprocess.check_output(command, cwd=root, env=env, text=True).strip()


run("build-probe", ["rustc", "--edition=2021", "ci/cpu_probe.rs", "-o", str(out / "cpu-probe")])
probe = dict(line.split("=", 1) for line in run("cpu-probe", [str(out / "cpu-probe")]).splitlines())
assert probe["sse41"] == "true" and probe["avx2"] == "true", probe
metadata = dict(commit=read(["git", "rev-parse", "HEAD"]), timestamp=datetime.now(timezone.utc).isoformat(),
                rustc=read(["rustc", "-Vv"]), cpu_probe=probe, platform=platform.platform(),
                cpu=read(["sysctl", "-n", "machdep.cpu.brand_string"]) if platform.system() == "Darwin" else json.loads(read(["lscpu", "--json"])),
                limitations="Hosted VM timing; one benchmark process, no concurrent builds; not dedicated CPU evidence.",
                variants={}, binary_sha256={}, files={})
print("ENVIRONMENT " + json.dumps(metadata), flush=True)

variants = {"before_simd": "a16739c0cd45e842c2d68a2509d54d70225e7387",
            "before_format": "ae9535a73c8126555222287534533783173b60f5",
            "current": "3b9fdf29b5d6d2c28d1bfda43555bf044a9888ed",
            "forced_sse41": "3b9fdf29b5d6d2c28d1bfda43555bf044a9888ed"}
artifacts = {}
for variant, revision in variants.items():
    work = out / "build" / variant
    work.mkdir(parents=True)
    archive = subprocess.check_output(["git", "archive", revision, "src"], cwd=root)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(work, filter="data")
    shutil.copytree(root / "benches", work / "benches")
    shutil.copyfile(root / "Cargo.toml", work / "Cargo.toml")
    shutil.copyfile(root / "ci/native-bench.lock", work / "Cargo.lock")
    if variant == "forced_sse41":
        lib = work / "src/lib.rs"
        text = lib.read_text()
        assert text.count("return Vectorization::AVX2;") == 2
        lib.write_text(text.replace("return Vectorization::AVX2;", "return Vectorization::SSE41;"))
    metadata["variants"][variant] = dict(source=revision, forced_sse41=variant == "forced_sse41")
    for path in [*work.glob("src/**/*.rs"), *work.glob("benches/**/*.rs"), work / "Cargo.toml", work / "Cargo.lock"]:
        metadata["files"][f"{variant}/{path.relative_to(work)}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    command = ["cargo", "bench", "--manifest-path", str(work / "Cargo.toml"), "--locked", "--no-run", "--message-format=json"]
    benches = ["hex", "format", "consumers", "check"]
    if variant == "current": benches.append("native_prototype")
    for bench in benches: command += ["--bench", bench]
    build = run("build-" + variant, command, {"CARGO_TARGET_DIR": str(work / "target")})
    for line in build.splitlines():
        if not line.startswith("{"): continue
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact" and item["target"]["kind"] == ["bench"]:
            path = Path(item["executable"])
            name = item["target"]["name"]
            artifacts[variant, name] = str(path)
            metadata["binary_sha256"][variant + "/" + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    for bench in benches:
        run("correctness-" + variant + "-" + bench, [artifacts[variant, bench], "--test"])

(out / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
filters = {
    "hex": r"^((encode/(faster_hex|const_hex|hex_simd|fashex|better_hex)|decode/(faster_hex_mixed|const_hex|hex_simd|fashex|better_hex)|rotating_(encode|decode)/(faster_hex|const_hex|hex_simd|fashex|better_hex))/32|(encode/faster_hex|decode/faster_hex_mixed)/(1|8|16|256|4096))$",
    "format": r"^format/(borrowed|padded_upper|per_byte)/(1|10|32|65|4096)$",
    "consumers": r"^((ckb_fixed_(buffer|json|parse))/(faster_hex|const_hex|hex_simd)/(10|32)|molecule_(string|display)/(faster_hex|const_hex|hex_simd)/(1|10|32)|molecule_display/faster_hex_borrowed/(1|10|32)|ckb_pool_rpc/(faster_hex|const_hex|hex_simd)/256)$",
    "check": r"^check_compare/(faster_hex|const_hex|hex_simd|better_hex)/32$",
}
# Build everything first. Baseline/after/after/baseline controls ordering drift.
order = [("before_simd", "before-simd"), ("before_format", "before-1"),
         ("current", "current-1"), ("current", "current-2"),
         ("before_format", "before-2"), ("forced_sse41", "forced-sse41")]
launcher = []
if hasattr(os, "sched_getaffinity"):
    cpu = min(os.sched_getaffinity(0))
    launcher = ["taskset", "-c", str(cpu)]
metadata["benchmark_launcher"] = launcher
(out / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
for variant, tag in order:
    for bench, pattern in filters.items():
        run(tag + "-" + bench, [*launcher, artifacts[variant, bench], "--bench", pattern,
            "--warm-up-time", "0.1", "--measurement-time", "0.7", "--sample-size", "40",
            "--noplot", "--save-baseline", tag])
for index in [1, 2]:
    run("prototype-" + str(index), [*launcher, artifacts["current", "native_prototype"], "--bench",
        "--warm-up-time", "0.2", "--measurement-time", "2", "--sample-size", "60", "--noplot",
        "--save-baseline", "prototype-" + str(index)])

results = {}
for path in (out / "criterion").rglob("estimates.json"):
    if path.parent.name in ["new", "base"]: continue
    estimates = json.loads(path.read_text())
    result = estimates.get("slope") or estimates["mean"]
    name = path.parent.parent.relative_to(out / "criterion").as_posix()
    results.setdefault(path.parent.name, {})[name] = result
(out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
for tag, values in results.items():
    print("RESULTS " + json.dumps(dict(tag=tag,ns={name:round(value["point_estimate"],4) for name,value in values.items()})), flush=True)
print("Native benchmarks complete", flush=True)
