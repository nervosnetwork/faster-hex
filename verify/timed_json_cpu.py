from pathlib import Path
import ctypes.util, hashlib, json, os, random, re, shutil, statistics, subprocess as sp

root = Path.cwd()
work = root / "consumer-work"
out = root / "results" / "cpu"
out.mkdir(parents=True, exist_ok=True)
site = work / "timed-json"
os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
cases = [("mixed", 4096), ("escapedmixed", 4096), ("hash_slice", 32)]
old = json.loads((root / "results/roundtrip/sections.json").read_text())
metadata = {}
def link(role, name):
    binary = work / role / name
    site.unlink(missing_ok=True)
    os.link(binary, site)
    assert os.path.samefile(site, binary)
    return binary

def time(role, name, size, count, extra=None):
    link(role, name)
    env = dict(os.environ)
    if extra:
        env.update(extra)
    value = sp.check_output([site, str(size), str(count)], cwd=work / "downstream", env=env, text=True)
    return float(value)

def report(rows, x, y):
    rng = random.Random(12079)
    ratios = [row[y] / row[x] for row in rows]
    sample = sorted(statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(6000))
    return dict(a_ns=statistics.median(row[x] for row in rows), b_ns=statistics.median(row[y] for row in rows),
                ratio=statistics.median(ratios), lo=sample[149], hi=sample[5849])

for name,size in cases:
    for role in ("base","head"):
        binary = link(role,name)
        metadata[role+"/"+name] = {"file_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
                                    "text":old[role+"/"+name]}
    assert metadata["base/"+name]["file_sha256"] != metadata["head/"+name]["file_sha256"]
    n = max(5000,round(19_000_000 / time("base",name,size,6000)))
    rng = random.Random(8735)
    rows = []
    for _ in range(26):
        sequence = ["base","head","control_base","control_head"]
        rng.shuffle(sequence)
        by_role = {k:[] for k in sequence}
        for key in sequence+sequence[::-1]:
            by_role[key].append(time(key.removeprefix("control_"),name,size,n))
        rows.append({k:statistics.mean(values) for k,values in by_role.items()})
    key = f"{name}-{size}"
    (out/(key+"-timings.json")).write_text(json.dumps({"pair":report(rows,"base","head"),
        "aa":report(rows,"base","control_base"),"bb":report(rows,"head","control_head"),"samples":rows},indent=2))

profiler = ctypes.util.find_library("profiler")
analyze = shutil.which("google-pprof") or shutil.which("pprof")
assert profiler and analyze, (profiler,analyze)
metadata["profiler"] = profiler
metadata["frequency_hz"] = 497
for name,size in cases[:2]:
    n = max(10000,round(3_000_000_000 / time("base",name,size,8000)))
    for seq, role in enumerate(("base","head","head","base")):
        profile = out/"active.prof"
        profile.unlink(missing_ok=True)
        samples_at = {"LD_PRELOAD":profiler, "CPUPROFILE":str(profile), "CPUPROFILE_FREQUENCY":"497"}
        sampled_ns = time(role,name,size,n,samples_at)
        # Analyze at the same executable path while it still names the sampled image.
        report_bytes = sp.check_output([analyze,"--text","--nodefraction=0.0001",site,profile],
                                       stderr=sp.DEVNULL)
        text = report_bytes.decode("utf-8",errors="replace")
        assert "Total:" in text or "Total samples" in text or "Total=" in text, text[:500]
        stem = f"{name}-{role}-{seq}"
        (out/(stem+".txt")).write_text(text)
        profile.replace(out/(stem+".prof"))
        metadata[stem] = {"sampled_ns":sampled_ns,"measured_iterations":n,"warmup_iterations":max(32,n//6)}
    print(name, "sampled",flush=True)
(out/"metadata.json").write_text(json.dumps(metadata,indent=2))
