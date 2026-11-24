"""Isolate the 64-digit validation result in the original Criterion consumer."""
import hashlib
import io
import json
import math
import os
from pathlib import Path
import random
import shutil
import statistics
import subprocess
import sys
import tarfile

replica = int(sys.argv[1])
root = Path.cwd()
work = root / "study"
source = work / "source"
results = work / "results"
results.mkdir(parents=True)
base = "25cfd8eb6a4cd8257a96fabaf73771cabcced4b4"
head = "848c4e239714cb3e2312abb9f38c2b3679439a0a"
env = dict(os.environ, CARGO_TARGET_DIR=str(work / "target"))

def run(args, cwd=root, **kw):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True, **kw)

def extract(ref):
    if subprocess.run(["git","cat-file","-e",ref+"^{commit}"],capture_output=True).returncode:
        run(["git","fetch","--no-tags","origin",ref])
    if source.exists():
        shutil.rmtree(source)
    source.mkdir()
    data = subprocess.check_output(["git","archive",ref])
    with tarfile.open(fileobj=io.BytesIO(data)) as ar:
        ar.extractall(source, filter="data")

def binary(tag, ref, mask=False, cold=True):
    extract(ref)
    if (work / "Cargo.lock").exists():
        shutil.copyfile(work / "Cargo.lock", source / "Cargo.lock")
    else:
        run(["cargo","generate-lockfile"],source)
        shutil.copyfile(source / "Cargo.lock",work / "Cargo.lock")
    if tag == "a":
        shutil.copytree(source / "benches",work / "benches")
    else:
        shutil.copytree(work / "benches",source / "benches",dirs_exist_ok=True)
    if mask:
        f = source / "src/lib.rs"
        s = f.read_text()
        before = "return Vectorization::AVX512;"
        assert s.count(before) == 2
        f.write_text(s.replace(before,"return Vectorization::AVX2;"))
    if not cold:
        f = source / "src/decode/validate.rs"
        before = "#[cold]\n#[inline(always)]\npub(super) fn diagnose_invalid"
        s = f.read_text()
        assert s.count(before) == 1
        f.write_text(s.replace(before,before.removeprefix("#[cold]\n")))
    # Source revisions deliberately share a checkout path, dependency artifacts and lock.
    run(["cargo","clean","--release","-p","faster-hex"], source)
    compiled = run(["cargo","bench","--locked","--bench","check","--no-run","--message-format=json"],source)
    objs=[json.loads(line) for line in compiled.splitlines() if line.startswith("{")]
    exe,=[x["executable"] for x in objs if x.get("executable") and x["target"]["name"]=="check"]
    assert any(x.get("reason")=="compiler-artifact" and x["target"]["name"]=="faster_hex" and not x["fresh"] for x in objs)
    path=work/tag
    shutil.copy2(exe,path)
    return path

hardware=run(["lscpu"] if sys.platform.startswith("linux") else ["sysctl","machdep.cpu.brand_string","machdep.cpu.features","machdep.cpu.leaf7_features"])
(results/"host.txt").write_text(hardware+"\n"+run(["rustc","-Vv"]))
print(hardware,flush=True)
a = binary("a",base)
b = binary("b",head)
backend = run(["cargo","test","--locked","--lib","tests::feature_detection_matches_host","--","--exact","--nocapture"],source,stderr=subprocess.STDOUT)
(results/"backend.txt").write_text(backend)
print("\n".join(l for l in backend.splitlines() if "backend" in l),flush=True)
paths={"a":a,"b":b,"precold":binary("precold",head,cold=False)}
# Only mask features actually detected by faster-hex. All SIMD entry points keep OS checks.
if "selected backend: AVX512" in backend:
    paths.update(avx2a=binary("avx2a",base,mask=True),avx2b=binary("avx2b",head,mask=True))
    masked=run(["cargo","test","--locked","--lib","tests::feature_detection_matches_host","--","--exact","--nocapture"],source,stderr=subprocess.STDOUT)
    assert "selected backend: AVX2" in masked
for tag in ["a","b"]:
    paths[tag*2]=work/(tag*2)
    shutil.copy2(paths[tag],paths[tag*2])
hashes={k:hashlib.sha256(p.read_bytes()).hexdigest() for k,p in paths.items()}
assert hashes["a"]==hashes["aa"] and hashes["b"]==hashes["bb"]
(results/"binaries.json").write_text(json.dumps(hashes,indent=2))
if hasattr(os,"sched_getaffinity"):
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
rows=[]
criterion=work/"criterion"
env["CRITERION_HOME"]=str(criterion)
rng=random.Random(23977+replica*17)
def timed(tag):
    run([str(paths[tag]),"--bench","^check_valid/byte_pairs/32$","--warm-up-time","0.2","--measurement-time","0.7","--sample-size","30","--noplot"],source,stderr=subprocess.DEVNULL)
    e,=criterion.glob("**/new/estimates.json")
    return json.loads(e.read_text())["mean"]["point_estimate"]
def summarize():
    pairs=[("a","aa"),("b","bb"),("a","b"),("precold","b")]
    if "avx2b" in paths: pairs += [("avx2a","avx2b"),("avx2a","a"),("avx2b","b")]
    summary={}
    for left,right in pairs:
        ratios=[r[right]/r[left] for r in rows]
        k=sum(x>1 for x in ratios)
        p=min(1.0,2*sum(math.comb(len(ratios),i) for i in range(min(k,len(ratios)-k)+1))/2**len(ratios))
        summary[right+"/"+left]=dict(median_pct=100*(statistics.median(ratios)-1),halves=[100*(statistics.median(p)-1) for p in (ratios[:len(ratios)//2],ratios[len(ratios)//2:])],slower=k,n=len(ratios),p=p, ns=[statistics.median(r[x] for r in rows) for x in (left,right)])
    return summary
for block in range(12):
    order=list(paths);rng.shuffle(order)
    samples={k:[] for k in paths}
    for tag in order+order[::-1]: samples[tag].append(timed(tag))
    rows.append({k:statistics.mean(s) for k,s in samples.items()})
    (results/"raw.json").write_text(json.dumps(rows))
    print("finished block",block+1,flush=True)
print(json.dumps(summarize(),indent=2),flush=True)
(results/"summary.json").write_text(json.dumps(summarize(),indent=2))
