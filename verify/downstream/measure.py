"""Compare the same CKB and gix source on each faster-hex revision."""
from pathlib import Path
import hashlib
import json
import os
import platform
import random
import re
import shutil
import statistics
import subprocess

repo = Path.cwd()
work = repo / "real"
driver = work / "caller"
codec = work / "codec"
results = repo / "results"
results.mkdir(exist_ok=True)
codec.mkdir(exist_ok=True)
shutil.copytree(repo / "verify/downstream/caller", driver, dirs_exist_ok=True)
lock = (driver / "Cargo.lock").read_text()
env = dict(os.environ, CARGO_TARGET_DIR=str(work / "target"))
linux = platform.system() == "Linux"
pin = ["taskset", "-c", str(min(os.sched_getaffinity(0)))] if linux else []
names = ["ckb_caller", "gix_caller"]
cases = [(names[1], n, "parse") for n in (20, 32)]
cases += [(names[0], n, m) for n in (32, 4096) for m in ("plain", "escaped")]

def call(args, cwd=driver):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True)

def text_section(exe):
    if linux:
        header = call(["readelf", "-SW", exe])
        match = re.search(r"\]\s+\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", header)
        address, offset, size = [int(x, 16) for x in match.groups()]
    else:
        parts = call(["otool", "-l", exe]).split("Section\n")
        sec = next(x for x in parts if re.match(r"\s*sectname __text\s+segname __TEXT", x))
        address, offset, size = [int(re.search(r"\b" + name + r"\s+(\S+)", sec)[1], 0) for name in ("addr", "offset", "size")]
    return address, size, hashlib.sha256(exe.read_bytes()[offset:offset + size]).hexdigest()

roles = {"release": ("6d84260fe321669e7f93ecfb8aecb4db0f582f14", "2.0.0"),
         "pr": ("25cfd8eb6a4cd8257a96fabaf73771cabcced4b4", "2.1.0"),
         "visitor": ("9fa6d71209957bd5e03c8f6ff39bb3fd59ac8685", "2.1.0")}
sections = {}
for role, (ref, version) in roles.items():
    call(["git", "archive", "-o", work / "product.tar", ref], repo)
    call(["tar", "-xf", work / "product.tar", "-C", codec], repo)
    assert lock.count('name = "faster-hex"\nversion = "2.1.0"') == 1
    text = lock.replace('name = "faster-hex"\nversion = "2.1.0"', 'name = "faster-hex"\nversion = "' + version + '"')
    (driver / "Cargo.lock").write_text(text.replace('"faster-hex 2.1.0"', '"faster-hex ' + version + '"'))
    graph = call(["cargo", "tree", "--locked", "-i", "faster-hex@" + version])
    assert str(codec) in graph and "ckb-jsonrpc-types " in graph and "gix-hash " in graph, graph
    if (work / "target").exists():
        call(["cargo", "clean", "--release", "-p", "faster-hex@" + version, "-p", "real-hex-consumers"])
    call(["cargo", "build", "--release", "--bins", "--locked"])
    for name in names:
        exe = work / (role + "-" + name)
        shutil.copy2(work / "target/release" / name, exe)
        sections[role + "/" + name] = text_section(exe)
(results / "sections.json").write_text(json.dumps(sections, indent=2))
host_command = ["lscpu"] if linux else ["sysctl", "-n", "machdep.cpu.brand_string"]
host_probe = subprocess.run(host_command, capture_output=True, text=True)
host = host_probe.stdout if host_probe.returncode == 0 else platform.platform() + "\n"
(results / "host.txt").write_text(host + call(["rustc", "-vV"]))
if os.environ.get("BUILD_CALLERS_ONLY"):
    raise SystemExit(0)
pairs = [(a, b, 20) for a, b in (("release", "pr"), ("pr", "visitor"), ("release", "visitor"))]
pairs += [(role, role, 8) for role in roles]
rng = random.Random(64370)
summary = {}
raw = {}
for name, n, mode in cases:
    def timed(role, count):
        return float(call(pin + [work / (role + "-" + name), str(n), mode, str(count)]))
    def iterations(time):
        return max(1000, min(4000000, int(22000000 / max(0.5, time))))
    count = iterations(timed("pr", 4000))
    order = [(a, b, swap) for a, b, k in pairs for swap in (True, False) for _ in range(k // 2)]
    rng.shuffle(order)
    samples = {}
    for a, b, swap in order:
        if swap:
            second = timed(b, count)
            first = timed(a, count)
        else:
            first = timed(a, count)
            second = timed(b, count)
        samples.setdefault(a + "-" + b, []).append((first, second))
    case = f"{name}/{n}/{mode}"
    raw[case] = samples
    summary[case] = {}
    for kind, ab in samples.items():
        ratios = [y/x for x, y in ab]
        bs = sorted(statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(5000))
        summary[case][kind] = dict(ns_a=statistics.median(x for x, y in ab), ns_b=statistics.median(y for x, y in ab), ratio=statistics.median(ratios), lo=bs[124], hi=bs[4874])
    print(case, summary[case]["pr-visitor"], flush=True)
    (results / "summary.json").write_text(json.dumps(summary, indent=2))
    (results / "samples.json").write_text(json.dumps(raw))
