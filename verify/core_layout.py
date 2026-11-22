"""Compare actual checked decode and change only the conversion loop's code position."""
from pathlib import Path
import hashlib
import json
import os
import platform
import random
import re
import shutil
import statistics
import subprocess as sp
import sys

from cause_common import compare, measure, pin, save, section

root = Path(__file__).resolve().parent.parent
work = Path(os.environ.get("CORE_WORK", root / "core-study")).resolve()
out = work / "results"
out.mkdir(parents=True, exist_ok=True)
driver = work / "downstream"
codec = work / "codec"
codec.mkdir(exist_ok=True)
target = os.getenv("CORE_TARGET")
is_mach = target == "x86_64-apple-darwin" or platform.system() == "Darwin"
base = os.environ.copy()
roles = ("release", "pr", "reverse")
placements = (0, 16, 32, 48)

def output(cmd, **kwargs):
    return sp.check_output(cmd, text=True, **kwargs)

def addresses(image):
    syms = {}
    for match in re.finditer(r"(?m)^([a-f0-9]+) ([TtSsDdBbRr]) (\S+)$", output(["nm", "-n", image])):
        syms.setdefault(match[3], []).append(int(match[1], 16))
    (name,) = [k for k in syms if re.search(r"3x8615hex_decode_avx217h", k)]
    (pos,) = syms.pop(name)
    syms.pop("_layout_lead", None)
    syms.pop("_layout_fill", None)
    return pos, syms

def describe_loop(image, addr):
    code = output(["xcrun", "llvm-objdump", "-d", "--no-show-raw-insn",
                   f"--start-address={addr}", f"--stop-address={addr+1280}", image])
    ops = [(int(m[1], 16), m[2], m[3]) for m in
           re.finditer(r"(?m)^\s*([0-9a-f]+):[ \t]+(\w+)[ \t]*(.*?)$", code)]
    for i, (p, op, operand) in enumerate(ops):
        jump = re.match(r"0x([0-9a-f]+)",operand)
        if not op.startswith("j") or not jump:
            continue
        dest = int(jump[1],16)
        body = [entry for entry in ops[:i] if dest <= entry[0] < p]
        if dest < p and any(instruction == "vpermq" for _,instruction,_ in body):
            return dict(start=dest-addr, instructions=[x[1] for x in body]+[op],
                        branch_end_mod32=ops[i+1][0]%32, byte_length=ops[i+1][0]-dest)
    raise ValueError(f"bulk conversion loop missing in {image} at {addr:x}")

sp.run([sys.executable, str(root / "verify/consumer.py")], cwd=root, check=True,
       env=dict(base, GENERATE_ONLY="1", RELEASE_FOCUS="1", STUDY_WORK=str(work),
                RESULTS=str(out), PRODUCT_REV="25cfd8e"))
shutil.copy2(root / "verify/core-downstream.lock", driver / "Cargo.lock")
shutil.copy2(root / "verify/stream_decode.rs", driver / "src/bin/stream_decode.rs")
info = {}
for role in roles:
    ref = "v2.0.0" if role == "release" else "25cfd8e"
    arc = work / "product.tar"
    sp.run(["git", "archive", "-o", arc, ref], cwd=root, check=True)
    sp.run(["tar", "-xf", arc, "-C", codec], check=True)
    if role == "reverse":
        file = codec / "src/decode/x86.rs"
        data = file.read_text()
        start = data.index("pub(super) unsafe fn hex_decode_avx2(")
        before, rest = data[:start], data[start:]
        old = "blocks.iter().zip(dst.as_chunks_mut::<32>().0)"
        assert rest.count(old) == 1
        file.write_text(before + rest.replace(old, old + ".rev()"))
    profile = base.get("CARGO_PROFILE_RELEASE_LTO", "false")
    dest = work / ("target-" + role)
    env = dict(base, CARGO_TARGET_DIR=str(dest))
    if is_mach:
        env.update(PATH=str(root / "verify/mach-probe") + os.pathsep + base["PATH"],
                   MACH_LAYOUT=str(work / role))
    lockpath = driver / "Cargo.lock"
    lockpath.write_text((root / "verify/core-downstream.lock").read_text().replace(
        'name = "faster-hex"\nversion = "2.1.0"',
        f'name = "faster-hex"\nversion = "{("2.0.0" if role == "release" else "2.1.0")}"'))
    flags = ["--target", target] if target else []
    sp.run(["cargo", "build", "--release", "--locked", "--bin", "decode", "--bin", "stream_decode", *flags],
           cwd=driver, env=env, check=True)
    exe = dest / (target or "") / "release/decode"
    folder = work / role
    folder.mkdir(exist_ok=True)
    shutil.copy2(exe, folder / "natural")
    shutil.copy2(exe.parent/"stream_decode", folder/"stream")
    info[role + "/natural"] = {"text": section(exe)}
    if not is_mach:
        continue
    groups = []
    for name in ["natural"] + [f"pos{p}" for p in placements]:
        image = folder / name
        addr, others = addresses(image)
        shared = hashlib.sha256(json.dumps(others, sort_keys=True).encode()).hexdigest()
        info[role + "/" + name] = dict(converter=addr, address_mod64=addr%64,
            back_jumps=describe_loop(image,addr), other_symbols=len(others),
            other_symbol_addresses=shared, text=section(image))
        if name != "natural":
            assert addr % 64 == int(name[3:]), (name, addr, hex(addr))
            groups.append(others)
    assert all(g == groups[0] for g in groups), [k for k in groups[0] if len({str(g.get(k)) for g in groups}) > 1][:30]
    print(role, {k: v["address_mod64"] for k,v in info.items() if k.startswith(role+"/")}, flush=True)
save(out / "layout.json", info)
if os.getenv("CORE_BUILD_ONLY"):
    sys.exit(0)
pin()
host = output(["sysctl", "-n", "machdep.cpu.brand_string"] if is_mach else ["lscpu"])
(out / "host.txt").write_text(host + "\n" + output(["rustc", "-vV"]))
seq = random.Random(88241)
site = work / "same-decode"
summaries = {}
raw = {}
for n in [4, 16, 32, 64, 96, 97, 128, 256, 1024, 4096, 32768]:
    keys = [role + "/natural" for role in roles] + ["control"]
    if is_mach and n in (256,4096):
        keys += [role + f"/pos{p}" for role in roles for p in placements]
    def time(key, count):
        image = work / ("pr/natural" if key == "control" else key)
        return measure(site, image, [n,count], driver)
    count = max(50, min(4000000, int(22000000 / max(.5,time("pr/natural",3000)))))
    samples = []
    for _ in range(19):
        order = keys.copy()
        seq.shuffle(order)
        groups = {k: [] for k in keys}
        for key in order + order[::-1]:
            groups[key].append(time(key,count))
        samples.append({k: statistics.mean(v) for k,v in groups.items()})
    pairs = [("release/natural","pr/natural"),("release/natural","reverse/natural"),
             ("pr/natural","reverse/natural"),("pr/natural","control")]
    if len(keys) > 4:
        for role in roles:
            pairs += [(f"{role}/pos0",f"{role}/pos{p}") for p in (16,32,48)]
        for p in placements:
            pairs += [(f"release/pos{p}",f"pr/pos{p}"),(f"pr/pos{p}",f"reverse/pos{p}")]
    summaries[str(n)] = {"|".join(pair): compare(samples,*pair) for pair in pairs}
    raw[str(n)] = samples
    print(n, {k:round((v["ratio"]-1)*100,2) for k,v in summaries[str(n)].items()}, flush=True)
    save(out / "times.json", summaries)
    save(out / "samples.json", raw)
for n in (65536,1048576):
    samples = []
    keys = list(roles) + ["control"]
    for cycle in range(13):
        order = keys.copy()
        seq.shuffle(order)
        data = {}
        for key in order:
            data[key] = measure(site,work / ("pr" if key=="control" else key) / "stream",[n,4],driver)
        samples.append(data)
    name = "stream/" + str(n)
    summaries[name] = {"|".join(p):compare(samples,*p) for p in
                       [("release","pr"),("release","reverse"),("pr","reverse"),("pr","control")]}
    raw[name] = samples
    save(out/"times.json",summaries)
    save(out/"samples.json",raw)
    print(name,{k:round((v["ratio"]-1)*100,2) for k,v in summaries[name].items()},flush=True)
