import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

repo = Path.cwd()
study = repo / "verify"
out = Path(os.environ.get("RESULTS", "results")).resolve()
work = Path(os.environ.get("STUDY_WORK", "study-work")).resolve()
out.mkdir(parents=True, exist_ok=True)
work.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, CARGO_TARGET_DIR=str(work / "target"), CRITERION_HOME=str(out / "samples"))
pin = ["taskset", "-c", str(min(os.sched_getaffinity(0)))] if sys.platform == "linux" else []
targets = ["hex", "check", "format", "serde", "field"]
base = "25cfd8eb6a4cd8257a96fabaf73771cabcced4b4"
head = os.environ["PRODUCT_REV"]

def run(args, cwd, **kw):
    return subprocess.run(args, cwd=cwd, env=kw.pop("env", env), check=True, **kw)

def checkout(ref, dest):
    dest.mkdir(parents=True)
    archive = work / "snapshot.tar"
    run(["git", "archive", "-o", str(archive), ref], repo)
    run(["tar", "-xf", str(archive)], dest)
    shutil.copy(study / "field.rs", dest / "benches/field.rs")
    with (dest / "Cargo.toml").open("a") as f:
        f.write('\n[[bench]]\nname="field"\nharness=false\n')

def lock(dest):
    saved = work / "Cargo.lock"
    if not saved.exists():
        run(["cargo", "generate-lockfile"], dest)
        shutil.copy(dest / "Cargo.lock", saved)
    shutil.copy(saved, dest / "Cargo.lock")

def compile_benches(source, role, names, locked=True):
    folder = work / "bin" / role
    folder.mkdir(parents=True, exist_ok=True)
    args = ["cargo", "bench", "--no-run", "--message-format=json-render-diagnostics"]
    if locked: args.append("--locked")
    for name in names: args += ["--bench", name]
    result = run(args, source, stdout=subprocess.PIPE, text=True)
    bins = {}
    for line in result.stdout.splitlines():
        msg = json.loads(line)
        if msg.get("executable") and "bench" in msg["target"]["kind"]:
            name = msg["target"]["name"]
            dest = folder / name
            shutil.copy2(msg["executable"], dest)
            bins[name] = dest
    assert set(bins)==set(names), bins
    return bins

def standalone(role, ref):
    source = work / "source"
    checkout(ref, source)
    lock(source)
    run(["cargo", "clean", "--profile", "bench", "-p", "faster-hex"], source, stdout=subprocess.DEVNULL)
    result = compile_benches(source, role, targets)
    shutil.rmtree(source)
    return result

def linked(refs, names, label):
    root = work / "linked"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src/lib.rs").write_text("")
    benches = root / "benches"
    benches.mkdir()
    for role, ref in refs.items():
        src = root / role
        checkout(ref, src)
        manifest = (src / "Cargo.toml").read_text()
        (src / "Cargo.toml").write_text(manifest.replace('name = "faster-hex"', f'name = "codec-{role}"', 1))
        for name in targets:
            module = benches / name / role
            module.mkdir(parents=True)
            shutil.copytree(src / "benches/support", module / "support")
            (module / "mod.rs").write_text(f"use codec_{role} as faster_hex;\n" + (src / f"benches/{name}.rs").read_text().replace("//!", "//") + "\npub(super) fn run() { main() }\n")
    manifest = manifest.replace('name = "faster-hex"', 'name = "codec-comparison"', 1)
    for role in refs:
        manifest += f'\n[dev-dependencies.codec_{role}]\npackage="codec-{role}"\npath="{role}"\n'
    (root / "Cargo.toml").write_text(manifest)
    for name in targets:
        (benches / (name + ".rs")).write_text(f'#[path="{name}/a/mod.rs"] mod a;\n#[path="{name}/b/mod.rs"] mod b;\nfn main() {{ if std::env::var_os("SLOT_B").is_some() {{ b::run() }} else {{ a::run() }} }}\n')
    shutil.copy(work / "Cargo.lock", root / "Cargo.lock")
    # Package identities and paths stay fixed when the two revisions exchange slots.
    run(["cargo", "clean", "--profile", "bench", "-p", "codec-a", "-p", "codec-b", "-p", "codec-comparison"], root)
    built = compile_benches(root, label, names, locked=False)
    shutil.rmtree(root)
    return built

def section(exe):
    if sys.platform == "darwin":
        header=subprocess.check_output(["otool","-l",exe],text=True)
        part=next(x for x in header.split("Section\n") if re.match(r"\s*sectname __text\s+segname __TEXT",x))
        address,size,offset=[int(re.search(r"\b"+n+r"\s+(\S+)",part)[1],0) for n in ["addr","size","offset"]]
        data=exe.read_bytes()[offset:offset+size]
    else:
        part=work/"machine-code.bin"
        run(["objcopy","--dump-section",".text="+str(part),exe],work)
        header=subprocess.check_output(["objdump","-h",exe],text=True)
        address=int(next(l.split()[3] for l in header.splitlines() if re.search(r"^\s*\d+\s+\.text\s",l)),16)
        data=part.read_bytes()
    return {"address":address,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}

def estimate(path):
    obj=json.loads(path.read_text())
    est=obj["slope"] or obj["mean"]
    return [est["point_estimate"], est["confidence_interval"]["lower_bound"], est["confidence_interval"]["upper_bound"]]

def measure(binaries, cases, label, seconds=.45, sample=30, add_env=None):
    regex = "^(" + "|".join(re.escape(n) for n in sorted(cases)) + ")$"
    results = {}
    for name, exe in binaries.items():
        run(pin + [str(exe), "--bench", regex, "--warm-up-time", str(min(.3,seconds/2)), "--measurement-time", str(seconds),
                   "--sample-size", str(sample), "--nresamples","5000","--noplot","--save-baseline",label], work, env={**env, **(add_env or {})}, stdout=subprocess.DEVNULL)
    for info in (out / "samples").rglob(f"{label}/benchmark.json"):
        n=json.loads(info.read_text())["full_id"]
        results[n]=estimate(info.with_name("estimates.json"))
    assert results.keys()==cases, (sorted(cases-results.keys()), sorted(results.keys()-cases))
    return results

def save(name, data):
    (out / name).write_text(json.dumps(data, indent=2))

def summarize(s):
    print(s, flush=True)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path,"a") as f: f.write(s+"\n")

def regress():
    cases={
        *(f"{p}/{n}" for p in ["encode/faster_hex","decode/faster_hex_mixed"] for n in [4,8,32,65,256,4096]),
        *(f"{p}/32" for p in ["encode/faster_hex_upper","rotating_encode/faster_hex","rotating_decode/faster_hex","check_valid/byte_pairs","check_valid/lower","field/borrowed_array","field/transient_array","field/bounded_vec","field/optional_array"]),
        *(f"decode_array/faster_hex/{n}" for n in [4,32]),"decode_vec/faster_hex/4096",
        *(f"decode_append/{n}" for n in [32,4096]),*(f"invalid/decode/{x}/4096" for x in ["first","middle","last"]),
        *(f"prefix/{op}/{n}" for op in ["buffer","display"] for n in [7,12]),
        *(f"format/borrowed/{n}" for n in [32,4096]),
        *(f"serde_json/{op}/{n}" for op in ["serialize_reuse","deserialize","deserialize_escaped"] for n in [10,32,65,256,4096]),
        "serde_postcard/serialize_reuse/32","field/wrong_length_array/4096","field/wrong_length_field/4096",
        *(f"string/{op}/{n}" for op in ["faster_hex_alloc", "faster_hex_reuse"] for n in [32,4096]),
        *(f"field/borrowed_array/{n}" for n in [4,20,65,256,4096]),
    }
    if os.environ.get('FOCUS_REGRESS'):
        cases={n for n in cases if n in {'field/borrowed_array/4','field/borrowed_array/32','field/wrong_length_field/4096','decode/faster_hex_mixed/4','decode_array/faster_hex/4','serde_json/serialize_reuse/10','serde_json/serialize_reuse/32','serde_json/serialize_reuse/65','serde_json/deserialize/65'}}
    if os.environ.get('WRITER_FOCUS'):
        cases={f"serde_json/{op}/{n}" for op in ["serialize_reuse","serialize_text_reuse"] for n in [10,32,65,256,4096]}
        # The bare JSON writer receives pre-encoded text and never calls the hex crate.
        # Retain its same-executable timings for each candidate, including the reversed-link trials.
    bins={r: standalone(r,ref) for r,ref in [("base",base),("head",head)]}
    save("sections.json",{role:{name:section(exe) for name,exe in executables.items()} for role,executables in bins.items()})
    times={}
    for label in ["base1","head1","head2","base2"]:
        role=label[:-1]
        times[label]=measure(bins[role],cases,label)
    def slower(n,b,h): return min(times[i][n][1] for i in h)>max(times[i][n][2] for i in b)
    candidates={n for n in cases if slower(n,["base1","base2"],["head1","head2"])}
    # Some other cases may look slower but just miss the confidence criterion.
    # Repeat a consistent >3% shift as well, then require separated intervals to confirm.
    candidates.update(n for n in cases if min(times[f"head{i}"][n][0]/times[f"base{i}"][n][0] for i in [1,2])>1.03)
    save("standalone.json", times)
    print("Repeat candidates:", sorted(candidates),flush=True)
    suspect=set()
    if candidates:
        for label in ["head3","base3","base4","head4"]:
            times[label]=measure(bins[label[:-1]],candidates,label,.8,40)
        suspect={n for n in candidates if slower(n,["base3","base4"],["head3","head4"])}
    save("standalone.json",times)
    confirmed=set()
    if suspect or os.environ.get("FORCE_LINKED"):
        pool=suspect or cases
        if os.environ.get('WRITER_FOCUS'):
            pool=cases
        names=[k for k,exe in bins["base"].items() if any((n+": benchmark") in subprocess.check_output([exe,"--list"],text=True) for n in pool)]
        forward=linked({"a":base,"b":head},names,"linked-forward")
        reverse=linked({"a":head,"b":base},names,"linked-reverse")
        for label,binary,bslot in [("base5",forward,False),("head5",forward,True),("head6",reverse,False),("base6",reverse,True)]:
            times[label]=measure(binary,pool,label,1.2,45,{"SLOT_B":"1"} if bslot else {})
        confirmed={n for n in suspect if all(slower(n,[f"base{i}"],[f"head{i}"]) for i in [5,6])}
    save("measurements.json",times)
    save("verdict.json",{"cases":len(cases),"repeated":sorted(candidates),"linked":sorted(suspect),"confirmed":sorted(confirmed)})
    rows=["| Existing API case | Base 1 | Head 1 | Head 2 | Base 2 |","|---|---:|---:|---:|---:|"]
    for n in sorted(cases):
        rows.append("| "+n+" | "+" | ".join(f"{times[i][n][0]:.3f}" for i in ["base1","head1","head2","base2"])+" |")
    summarize(f"Existing API trials: {len(cases)} cases; repeated: {len(candidates)}; linked controls: {len(suspect)}; confirmed slower: {sorted(confirmed)}.\n\n"+"\n".join(rows))
    if confirmed: raise SystemExit("repeatable regression in "+", ".join(sorted(confirmed)))

(out/"host.txt").write_text(platform.platform()+"\n"+subprocess.check_output(["lscpu"] if sys.platform=="linux" else ["sysctl","-n","machdep.cpu.brand_string"],text=True)+"\n"+subprocess.check_output(["rustc","-vV"],text=True)+"\n"+base+"\n"+head+"\n")
regress()
