"""Run unmodified consumer binaries through one path and one argv[0]."""
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

root = Path.cwd()
work, results = root / "real", root / "results"
mac = platform.system() == "Darwin"
if not mac:
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
cases = [("gix_caller", 20, "parse"), ("gix_caller", 32, "parse")] if mac else [
    ("ckb_caller", 32, "plain"), ("ckb_caller", 32, "escaped"),
    ("ckb_caller", 4096, "plain"), ("ckb_caller", 4096, "escaped")]
base, head = ("pr", "visitor") if mac else ("release", "pr")
site = work / "same-caller"
records, summaries, sources = {}, {}, {}
rng = random.Random(335933)
for name, size, mode in cases:
    original = [work / (role + "-" + name) for role in (base, head)]
    twin = [work / ("copy-" + p.name) for p in original]
    for p, q in zip(original, twin):
        if not q.exists():
            shutil.copy2(p, q)
        assert p.read_bytes() == q.read_bytes()
    sources[name] = [hashlib.sha256(p.read_bytes()).hexdigest() for p in original]
    def timed(path, argv0, use_shared, count):
        target = path
        if use_shared:
            site.unlink(missing_ok=True)
            os.link(path, site)
            target = site
        return float(subprocess.check_output([argv0, str(size), mode, str(count)],
                                              executable=target, cwd=work/"caller", text=True))
    count = max(3000, min(5000000, int(25000000 / max(.5, timed(original[0], site, True, 4000)))))
    # The canonical pair changes only the binary. Same-image pairs isolate the
    # original argument string and the file copy, with the executable path fixed.
    variants = {
        "natural": [(p, p, False) for p in original],
        "canonical": [(p, site, True) for p in original],
        "canonical_copies": [(p, site, True) for p in twin],
        "argv_control": [(original[0], p, True) for p in original],
        "base_copy_control": [(p, site, True) for p in (original[0], twin[0])],
        "head_copy_control": [(p, site, True) for p in (original[1], twin[1])],
    }
    case = f"{name}/{size}/{mode}"
    data = {label:[] for label in variants}
    for _ in range(24):
        order = list(variants)
        rng.shuffle(order)
        for label in order:
            mix = rng.choice([[0,1],[1,0]])
            samples = [[],[]]
            for i in mix + mix[::-1]:
                samples[i].append(timed(*variants[label][i], count))
            data[label].append([statistics.mean(seq) for seq in samples])
    records[case] = data
    summaries[case] = {}
    for label, samples in data.items():
        ratios = [b/a for a,b in samples]
        bs = sorted(statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(6000))
        summaries[case][label] = [statistics.median(a for a,b in samples), statistics.median(b for a,b in samples),
                                   statistics.median(ratios), bs[149], bs[5849]]
    print(case, summaries[case]["canonical"], flush=True)
    (results / "crossover.json").write_text(json.dumps(summaries, indent=2))
    (results / "crossover-samples.json").write_text(json.dumps(records))
(results / "full-image-digests.json").write_text(json.dumps(sources, indent=2))
if mac:
    def segments(path):
        output = subprocess.check_output(["otool","-l",path],text=True)
        data = path.read_bytes()
        found = {}
        for part in output.split("Section\n")[1:]:
            fields = re.match(r"\s*sectname (\S+)\s+segname (\S+)",part)
            if not fields:
                continue
            addr, off, size = [int(re.search(r"\b"+k+r"\s+(\S+)",part)[1],0) for k in ("addr","offset","size")]
            if off:
                found[fields[2]+"/"+fields[1]]=(addr, data[off:off+size])
        return found
    info = {}
    a,b = [segments(work/(role+"-gix_caller")) for role in (base,head)]
    assert a.keys()==b.keys()
    for key,(va,old) in a.items():
        vb,new=b[key]
        item=dict(addresses=[va,vb], lengths=[len(old),len(new)], identical=(va==vb and old==new))
        if len(old)==len(new) and old!=new:
            changed=[i for i,(x,y) in enumerate(zip(old,new)) if x!=y]
            item["changed_bytes"]=len(changed)
            words=list(dict.fromkeys(i//4*4 for i in changed))[:8]
            item["first_changed_words"]=[[n,int.from_bytes(old[n:n+4],"little"),int.from_bytes(new[n:n+4],"little")] for n in words]
        info[key]=item
    (results/"mapped-sections.json").write_text(json.dumps(info,indent=2))
