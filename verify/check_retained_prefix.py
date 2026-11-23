"""Check two changes to private output independently in the original callers."""
from pathlib import Path
import json
import os
import sys

v = Path(__file__).resolve().parent
sys.path.insert(0,str(v))
import isolated_cases as scope
from cause_common import pin, save, section
from cross_file_copies import crossover

key=os.environ["HOST_KEY"]
spec=json.loads((v/"retained_prefix_inputs.json").read_text())
scope.revisions=spec["refs"]
cases={
    "gix_prefix":[(7,"sha1-adopt"),(0,"sha256-adopt"),(64,"sha256-adopt")],
    "prefix_buffer":[(4,"buffer")], "full_buffer":[(32,"buffer"),(65,"buffer")],
    "vec_round_slice":[(4096,"plain")], "append_call":[(4096,"valid")]
}
scope.cases=[(op,n,kind) for op,seq in cases.items() for n,kind in seq]
scope.pairs=[]
driver=v/"isolate_callers.py"
source,sep,_=driver.read_text().partition("\npin();rng=")
assert sep
guard="    if SCOPE in ('fmt-join','fmt-field','prefix-length','release-audit','prefix-kernel-exchange','prefix-operation') and role in ('release','version'):"
assert source.count(guard)==1
source=source.replace(guard,guard[:-1]+" and 'gix_prefix' in bins:")
ns={"__name__":"__main__","__file__":str(driver)}
exec(compile(source,str(driver),"exec"),ns)
out,work=ns["out"],ns["work"]
metadata=json.loads((out.parent/"archives.json").read_text())
assert {p["role"]:p["sha"] for p in metadata}==spec["refs"]
assert next(p["checksum"] for p in metadata if p["role"]=="release")=="e4ede54fe330383a5de28c0a1f06668ff9dbf06c8094e1c5150c39488a5e911d"
load_source=(v/"pr_components.py").read_text().split("spec=json.loads",1)[0]
load_ns={"__file__":str(v/"pr_components.py")}
exec(compile(load_source,str(v/"pr_components.py"),"exec"),load_ns)
loaded=load_ns["load_image"]
signatures={}
images={}
for role in scope.revisions:
    for op in cases:
        exe=out/(role+"-"+op)
        if role=="release" and op in ("append_call","prefix_buffer"):
            assert not exe.exists()
            continue
        signatures[role+"/"+op]={k:section(exe,k) for k in (".text",".rodata")}
        images[role+"/"+op]=loaded(exe)
checks={name:all(signatures[name][section_name]==value for section_name,value in sig.items()) for name,sig in spec["anchors"][key].items()}
save(out/"anchors.json",checks)
assert all(checks.values()),[k for k,b in checks.items() if not b]
save(out/"fingerprints.json",signatures)
pin()
comparisons={}
def check(base,candidate,op,seq):
    name=base+"-vs-"+candidate+"-"+op
    assert name not in comparisons
    same=images[base+"/"+op]==images[candidate+"/"+op]
    comparisons[name]=dict(identical_loaded_image=same,cases=seq)
    save(out/"comparisons.json",comparisons)
    if not same:
        crossover([out/(base+"-"+op),out/(candidate+"-"+op)],out/"fixed-program",work/"caller",out/name,seq,count_last=op=="ckb_caller")


for op,seq in cases.items():
    check("append_both","retained",op,seq)
    if op in ("gix_prefix","prefix_buffer"):
        check("pr","retained",op,seq)
    if op in ("vec_round_slice","full_buffer"):
        check("release","retained",op,seq)
