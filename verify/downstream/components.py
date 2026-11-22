from pathlib import Path
import json
import os
import random
import statistics
import subprocess

roles = ["release", "pr", "release_encoder", "release_diagnostics", "release_both"]
names = ["ckb_caller", "ckb_read", "ckb_write"]

def add_phases(driver):
    sources = driver / "src/bin"
    original = (sources / "ckb_caller.rs").read_text()
    read = "let parsed:ckb_jsonrpc_types::JsonBytes=serde_json::from_slice(black_box(json)).unwrap();"
    write = "output.clear();serde_json::to_writer(&mut output,&parsed).unwrap();black_box(output.as_slice());"
    assert original.count(read) == original.count(write) == 1
    (sources / "ckb_read.rs").write_text(original.replace(write,"black_box(parsed);").replace("let mut output=Vec::with_capacity(expected.len());",""))
    (sources / "ckb_write.rs").write_text(original.replace(read,"").replace(write,write.replace("&parsed)","black_box(&parsed))")))

def restore_component(root, codec, role, release_ref):
    files = {}
    if role in ("release_encoder","release_both"):
        files["src/encode.rs"] = ("pub(crate) unsafe fn hex_encode_neon(", '\n#[inline]\n#[target_feature(enable = "neon")]\n#[cfg(target_arch = "aarch64")]\nunsafe fn encode_neon_16(')
    if role in ("release_diagnostics","release_both"):
        files["src/decode.rs"] = ("fn decode_diagnosed(", "\n}\n")
    for path,(start,end) in files.items():
        def span(text):
            a=text.index(start);b=text.index(end,a)
            return a, b + (3 if end=="\n}\n" else 0)
        old = subprocess.check_output(["git","show",release_ref+":"+path],cwd=root,text=True)
        dest = codec / path; new=dest.read_text()
        u,v=span(old);x,y=span(new)
        assert new[x:y] != old[u:v]
        dest.write_text(new[:x]+old[u:v]+new[y:])
        after = dest.read_text(); l,r=span(after)
        assert after[l:r] == old[u:v]

def time_phases():
    root=Path.cwd(); work=root/"real"; results=root/"results"; site=work/"same-component-caller"
    if hasattr(os,"sched_setaffinity"):
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    cases=[(op,n,mode) for op in names for n in [32,4096] for mode in (["plain"] if op=="ckb_write" else ["plain","escaped"])]
    rng=random.Random(835872)
    samples={}; summaries={}
    for op,n,mode in cases:
        def measure(role,count):
            binary=work/(("pr" if role=="pr_control" else role)+"-"+op)
            site.unlink(missing_ok=True);os.link(binary,site)
            return float(subprocess.check_output([site,str(n),mode,str(count)],cwd=work/"caller",text=True))
        count=max(1200,min(2500000,int(18000000/max(.5,measure("pr",4000)))))
        data=[]
        for _ in range(18):
            sequence=roles+["pr_control"];rng.shuffle(sequence)
            groups={key:[] for key in sequence}
            for key in sequence+sequence[::-1]:
                groups[key].append(measure(key,count))
            data.append({key:statistics.mean(group) for key,group in groups.items()})
        case=f"{op}/{n}/{mode}"; samples[case]=data; summary={}
        pairs=[("release","pr")]+[(baseline,v) for v in roles[2:] for baseline in ("pr","release")]+[("pr","pr_control")]
        for a,b in pairs:
            ratios=[row[b]/row[a] for row in data]
            bs=sorted(statistics.median(rng.choices(ratios,k=len(ratios))) for _ in range(5000))
            summary[a+"/"+b]=[statistics.median(row[a] for row in data),statistics.median(row[b] for row in data),statistics.median(ratios),bs[124],bs[4874]]
        summaries[case]=summary
        print(case,{k:round((v[2]-1)*100,2) for k,v in summary.items()},flush=True)
        (results/"components.json").write_text(json.dumps(summaries,indent=2))
        (results/"component-samples.json").write_text(json.dumps(samples))

if __name__ == "__main__":
    time_phases()
