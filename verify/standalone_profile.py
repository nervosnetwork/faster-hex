from pathlib import Path
import gzip,hashlib,json,os,shutil,subprocess as sp,tempfile
root=Path.cwd()
work=root/"consumer-work"
out=root/"results/profile"
out.mkdir(parents=True,exist_ok=True)
modes={}
def command(args):
    return sp.run(args,text=True,stdout=sp.PIPE,stderr=sp.STDOUT,check=False)
def choose():
    for name in ("gprofng","x86_64-linux-gnu-gprofng"):
        if exe:=shutil.which(name):
            return ("gprofng",exe)
    paths=[shutil.which("perf"),*map(str,sorted(Path("/usr/lib/linux-tools").glob("*/perf"),reverse=True))]
    for p in paths:
        if p and command([p,"stat","-e","task-clock","--","true"]).returncode==0:
            return ("perf",p)
    return ("callgrind",shutil.which("valgrind"))
kind,prof=choose()
assert prof,(kind,prof)
baseline=json.loads((root/"results/paired/independent-summary.json").read_text())
for op in ("mixed","escapedmixed"):
    base_ns=baseline[f"{op}/4096"]["pair"]["a_ns"]
    repeats=3000 if kind=="callgrind" else round(4_000_000_000/base_ns)
    for role in ("base","head"):
        binary=work/role/op
        assembly=sp.check_output(["objdump","-dC","--no-show-raw-insn",binary])
        with gzip.open(out/f"{role}-{op}.asm.gz","wb") as f: f.write(assembly)
        modes[f"{role}/{op}"]={"sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"mode":kind,"repeats":repeats}
    for i,role in enumerate(("base","head","head","base")):
        binary=work/role/op
        args=[str(binary),"4096",str(repeats)]
        dest=out/f"{op}-{role}-{i}.txt"
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)
            if kind=="gprofng":
                record=command([prof,"collect","app","-p","hi","-o",str(path/"sample.er"),*args])
                assert record.returncode==0,record.stdout[-1600:]
                report=command([prof,"display","text","-limit","65","-functions",str(path/"sample.er")])
                assert report.returncode==0 and "<Total>" in report.stdout,report.stdout[:900]
            elif kind=="perf":
                record=command([prof,"record","-q","-e","cpu-clock:u","-F","499","-o",str(path/"perf.data"),"--",*args])
                assert record.returncode==0,record.stdout[-1200:]
                report=command([prof,"report","--stdio","--show-nr-samples","--percent-limit","0.2","--no-children","-i",str(path/"perf.data")])
                assert report.returncode==0 and "Samples:" in report.stdout,report.stdout[:900]
            else:
                record=command([prof,"--tool=callgrind","--collect-jumps=yes","--callgrind-out-file="+str(path/"callgrind.out"),*args])
                assert record.returncode==0,record.stdout[-1200:]
                report=command(["callgrind_annotate","--auto=no","--inclusive=no","--threshold=99",str(path/"callgrind.out")])
                assert report.returncode==0 and "PROGRAM TOTALS" in report.stdout,report.stdout[:900]
            dest.write_text(f"{kind}, identical executable and input, {repeats} iterations\n"+record.stdout+"\n"+report.stdout)
            print(dest.name,kind,repeats,flush=True)
(out/"profile.json").write_text(json.dumps(modes,indent=2))
