"""Profile exactly the real fixed-array and Vec reader programs that showed different results."""
from cause_common import *
import re
import shutil

work=ROOT/"field-cause-work";out=ROOT/"reader-profile"
out.mkdir(exist_ok=True)
sp.run([sys.executable,"verify/which_field_slows.py"],cwd=ROOT,check=True,env=dict(os.environ,FIELD_DRIVERS_ONLY="1"))
driver=work/"downstream";codec=work/"codec";codec.mkdir(exist_ok=True)
profile=os.environ["CARGO_PROFILE_RELEASE_LTO"]
known=json.loads((ROOT/"verify/reader-sections.json").read_text())[profile]
names=("array_read_reader","vec_read_reader")
actual={};images={}
for role,ref in (("base",BASE),("head",HEAD)):
    archive=work/"src.tar"
    sp.run(["git","archive","-o",archive,ref],cwd=ROOT,check=True)
    sp.run(["tar","-xf",archive,"-C",codec],check=True)
    target=work/("target-"+role)
    sp.run(["cargo","build","--quiet","--release","--bins"],cwd=driver,
           check=True,env=dict(os.environ,CARGO_TARGET_DIR=str(target)))
    for n in names:
        img=target/"release"/n;k=role+"/"+n
        sg=section(img)
        actual[k]=dict(actual=sg,previous=known[k],matches=(sg==known[k]))
        images[k]=img
        (out/(role+"-"+n+".symbols")).write_bytes(sp.check_output(["nm","-nSC","--defined-only",img]))
        import gzip
        with gzip.open(out/(role+"-"+n+".asm.gz"),"wb") as f:
            f.write(sp.check_output(["objdump","-dC","--no-show-raw-insn",img]))
save(out/"sections.json",actual)
print("exact previous normal text sections", {k:v["matches"] for k,v in actual.items()},flush=True)
pin()
site=work/"same-reader"
def selected(key):
    site.unlink(missing_ok=True);os.link(images[key],site)
    return site
rng=random.Random(72564)
samples={};summaries={};records={}
for name in names:
    roles=("base","head","aa")
    def time(role,n):
        return float(sp.check_output([selected(("base" if role=="aa" else role)+"/"+name),"4096",str(n),"reader"],text=True))
    loops=max(250,round(35000000/time("base",1300)))
    rows=[]
    for _ in range(22):
        ordered=list(roles);rng.shuffle(ordered);d={k:[] for k in ordered}
        for role in ordered+ordered[::-1]:d[role].append(time(role,loops))
        rows.append({k:statistics.mean(v) for k,v in d.items()})
    samples[name]=rows;summaries[name]={k:compare(rows,"base",role) for k,role in (("pair","head"),("same","aa"))}
    save(out/"timings.json",summaries);save(out/"samples.json",samples)
    print(name,summaries[name],flush=True)
    count=round(4700000000 / summaries[name]["pair"]["base_ns"])
    for i,role in enumerate(["base","head","head","base"]):
        basepath=out/f"{name}-{role}-{i}"
        program=selected(role+"/"+name)
        profile_path=work/"sample.prof"
        profile_path.unlink(missing_ok=True)
        cmd=[str(program),"4096",str(count),"reader"]
        env=dict(os.environ,CPUPROFILE=str(profile_path),CPUPROFILE_FREQUENCY="499",LD_PRELOAD="libprofiler.so.0")
        run=sp.run(cmd,check=True,capture_output=True,text=True,env=env)
        assert profile_path.stat().st_size>128,run.stderr
        # Keep only symbolized results and inspect the concentrated instructions.
        for suffix,flags in [("functions",[]),("pc",["--addresses"])]:
            report=sp.run(["google-pprof","--text","--nodecount=80",*flags,str(program),str(profile_path)],check=True,capture_output=True,text=True)
            assert "Total:" in report.stdout or "Total samples:" in report.stdout,report.stdout[:400]
            (Path(str(basepath)+"-"+suffix+".txt")).write_text(report.stdout)
        records[name+"/"+role+"/"+str(i)]=dict(iterations=count,observed_ns=float(run.stdout.strip()),profiler=run.stderr.strip())
        save(out/"runs.json",records)
(out/"host.txt").write_text(sp.check_output(["lscpu"],text=True)+"\n"+sp.check_output(["rustc","-vV"],text=True))
