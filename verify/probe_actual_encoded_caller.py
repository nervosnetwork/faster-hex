"""Locate the measured release/candidate loops and vary only their placement."""
from pathlib import Path
import hashlib, json, math, os, random, re, shutil, statistics, subprocess as sp, sys, tempfile

original=Path(__file__).with_name("official-paired.py")
exec(compile(original.read_text().split("programs={};",1)[0],str(original),"exec"))
config=readj(repo/"verify/actual-caller.json")
assert "Neoverse-N2" in run(["lscpu"])
profiles=["base","head"]
variants=["native","old","new"]
cases=["encode/faster_hex/8","encode/faster_hex/32","encode/faster_hex_upper/8"]
binary={}
wrapper=w/"wrapper";wrapper.mkdir()
shutil.copy2(repo/"verify/bench_caller_link.py",wrapper/"cc")
(wrapper/"cc").chmod(0o755)
systemcc=shutil.which("cc")
lock=(repo/"verify/caller-input.lock").read_bytes()
assert digest(lock)==config["lock"]
layouts={}; images={}; map8={}
for role in profiles:
    snapshot(config[role])
    manifest=src/"Cargo.toml"
    if role=="base":
        shutil.copytree(src/"benches",w/"driver")
        from_version='version = "2.0.0"'
        text=manifest.read_text();assert text.count(from_version)==1
        manifest.write_text(text.replace(from_version,'version = "2.1.0"',1))
    else:
        shutil.rmtree(src/"benches");shutil.copytree(w/"driver",src/"benches")
    (src/"Cargo.lock").write_bytes(lock)
    stage=w/("layout-"+role)
    opts={"CARGO_TARGET_DIR":str(w/("target-"+role)),"PATH":str(wrapper)+os.pathsep+env["PATH"],
          "ORIGINAL_CC":systemcc,"CALLER_ROLE":role,"CALLER_OUTPUT":str(stage)}
    rows=list(map(json.loads,run(["cargo","bench","--locked","--bench","hex","--no-run","--message-format=json"],src,opts).splitlines()))
    bench,=[x for x in rows if x.get("target",{}).get("kind")==["bench"] and x["target"]["name"]=="hex"]
    assert not bench["fresh"]
    assert Path(bench["executable"]).read_bytes()==(stage/"native").read_bytes()
    assert (src/"Cargo.lock").read_bytes()==lock
    layouts[role]=readj(stage/"layout.json")
    for tag in variants:
        path=stage/tag;binary[role,tag]=path;images[role+"/"+tag]=machine(path)
    assert images[role+"/native"]["text"]==config["anchors"][role],images[role+"/native"]
    save("addresses.json",layouts);save("images.json",images)
    print(role,layouts[role],flush=True)
    lower=layouts[role]["tables"]["0123456789abcdef"]
    upper=layouts[role]["tables"]["0123456789ABCDEF"]
    flags=[str(binary[role,"native"]),"--bench","^encode/faster_hex/8$","--profile-time","2","--warm-up-time","0.12","--noplot"]
    cpu0=os.sched_getaffinity(0);os.sched_setaffinity(0,{min(cpu0)})
    prof=shutil.which("gprofng") or shutil.which("aarch64-linux-gnu-gprofng")
    trace=w/(role+".er")
    sp.run([prof,"collect","app","-p","hi","-o",trace,*flags],cwd=src,capture_output=True,check=True)
    os.sched_setaffinity(0,cpu0)
    pcs=run([prof,"display","text","-name","mangled","-metrics","e.totalcpu:name","-limit","22","-pcs",str(trace)])
    active=[x for x in pcs.splitlines() if re.match(r"^\s*[0-9.]+\s+",x) and "Bencher" in x]
    (out/(role+"-hot-pcs.txt")).write_text("\n".join(active[:15])+"\n")
    if active and (lower["symbol"] in active[0] or lower["symbol"][-18:-1] in active[0]):
        assert any(re.search(r"\+ 0x0*(?:BC|CC|D4|D8|178|18C|190)\b",x,re.I) for x in active)
        map8[role]="sampled mangled function"
    else:
        # Directly observe the load path if gprofng suppresses Rust linkage names.
        sym,=[x for x in run(["nm","-n",str(stage/"native")]).splitlines() if x.endswith(" T _start")]
        start=int(sym.split()[0],16)
        script=w/(role+".gdb")
        script.write_text("set pagination off\nset debuginfod enabled off\nset disable-randomization off\nstarti\n"
                          +"python slide = int(gdb.parse_and_eval('(unsigned long)&_start')) - "+str(start)+"\n"
                          +"python low = gdb.Breakpoint('*'+hex(slide+"+str(lower["address"]+0x178)+"))\n"
                          +"python high = gdb.Breakpoint('*'+hex(slide+"+str(upper["address"]+0x178)+"))\ncontinue\n"
                          +"python print('HEX-PC',hex(int(gdb.parse_and_eval('$pc'))-slide))\n")
        check=sp.run(["gdb","-q","-nx","--batch","-x",str(script),"--args",*flags],cwd=src,stdout=sp.PIPE,stderr=sp.STDOUT,text=True)
        (out/(role+"-debugger.txt")).write_text(check.stdout[-4000:])
        assert "HEX-PC "+hex(lower["address"]+0x178) in check.stdout,check.stdout[-1800:]
        map8[role]="native breakpoint at lowercase 8-byte loop"
    save("active.json",map8)
assert layouts["base"]["original_sites_already_match"]==layouts["head"]["original_sites_already_match"]
assert layouts["base"]["sites"]==layouts["head"]["sites"]
save("environment.json",{"cpu":run(["lscpu"]),"toolchain":run(["rustc","-Vv"]),"lock":digest(lock),"refs":config})
os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
fmt=lambda p,v:p+"/"+v
keys=[(p,k) for p in profiles for k in variants]
labels=keys*2;n=len(labels)
rng=random.Random(725260)
order_index=[0,1,11,2,10,3,9,4,8,5,7,6]
rows={case:[] for case in cases}; site=w/"measure"
perm=list(range(n));rng.shuffle(perm); shifts=list(range(n));rng.shuffle(shifts)
for it,shift in enumerate(shifts):
    if it%6==0:
        # Fresh copies for each half; the 12 positions stay balanced across the full run.
        copies={}
        for i,label in enumerate(labels):
            item=w/f"copy-{it}-{i}"
            shutil.copy2(binary[label],item);copies[i]=item
    order=[perm[(x+shift)%n] for x in order_index]
    shuffled=cases[:];rng.shuffle(shuffled)
    for case in shuffled:
        sample=[None]*n
        for i in order:
            site.unlink(missing_ok=True);os.link(copies[i],site)
            with tempfile.TemporaryDirectory(dir=w) as h:
                args=[str(site),"--bench","^"+re.escape(case)+"$","--warm-up-time","0.12","--measurement-time","0.36","--sample-size","25","--nresamples","2000","--noplot"]
                proc=sp.run(args,cwd=src,env={**env,"CRITERION_HOME":h},capture_output=True,text=True)
                assert proc.returncode==0,proc.stderr[-900:]
                e,=list(Path(h).rglob("new/estimates.json"))
                assert readj(e.parent/"benchmark.json")["full_id"]==case
                sample[i]=readj(e)["mean"]["point_estimate"]
        rows[case].append(sample)
    save("raw.json",rows)
    if (it+1)%6==0:print("Completed paired blocks",it+1,flush=True)
def summary(vals):
    delta=lambda v:100*(statistics.median(v)-1)
    nonzero=[v for v in vals if v!=1];k=sum(v>1 for v in nonzero);count=len(nonzero)
    sig=lambda x:sum(math.comb(count,i) for i in range(x,count+1))/2**count
    return {"median":delta(vals),"halves":[delta(vals[:6]),delta(vals[6:])],"slow_p":sig(k),"fast_p":sig(count-k)}
results={}
for case,measured in rows.items():
    vec=[{key:(z[i]+z[i+6])/2 for i,key in enumerate(keys)} for z in measured]
    ratio=lambda a,b:summary([v[a]/v[b] for v in vec])
    results[case]={"candidate_vs_base":{k:ratio(("head",k),("base",k)) for k in variants},
                   "site_change":{p:ratio((p,"new"),(p,"old")) for p in profiles},
                   "copies":{fmt(*k):summary([z[i]/z[i+6] for z in measured]) for i,k in enumerate(keys)}}
save("result.json",results)
print("Matched loops:",map8,"native addresses already equal:",layouts["base"]["original_sites_already_match"],flush=True)
