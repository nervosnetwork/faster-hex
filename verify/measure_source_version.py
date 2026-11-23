from pathlib import Path
import hashlib
import json
import os
import shutil
import sys

v=Path(__file__).resolve().parent;sys.path.insert(0,str(v))
import isolated_cases as scope
from cause_common import pin,save,section
from cross_file_copies import crossover
spec=json.loads((v/"source_version_inputs.json").read_text())
refs=spec["refs"];scope.revisions=refs
scope.cases=[("vec_round_slice",4096,"plain")];scope.pairs=[]
work=v.parent/"real"
wrapper=work/"order-wrapper";wrapper.mkdir()
realcc=shutil.which("cc")
shutil.copy2(v/"allocator_order_link.py",wrapper/"cc");(wrapper/"cc").chmod(0o755)
os.environ["ORIGINAL_CC"]=realcc;os.environ["PATH"]=str(wrapper)+os.pathsep+os.environ["PATH"]
driver=v/"isolate_callers.py"
code,sep,_=driver.read_text().partition("\npin();rng=")
assert sep
mark='    cargo=["cargo",*config]'
assert code.count(mark)==1
code=code.replace(mark,'    build_env["ALLOCATOR_ORDER_OUTPUT"]=str(work/"object-order"/role)\n'+mark)
guard="    if SCOPE in ('fmt-join','fmt-field','prefix-length','release-audit','prefix-kernel-exchange','prefix-operation') and role in ('release','version'):"
assert code.count(guard)==1
code=code.replace(guard,guard[:-1]+" and 'gix_prefix' in bins:")
ns={"__name__":"__main__","__file__":str(driver)}
exec(compile(code,str(driver),"exec"),ns)
out=ns["out"]
assert "Neoverse-N2" in json.loads((out/"host.json").read_text())["cpu"]
metadata=json.loads((out.parent/"archives.json").read_text())
assert {row["role"]:row["sha"] for row in metadata}==refs
assert next(q["checksum"] for q in metadata if q["role"]=="release")=="e4ede54fe330383a5de28c0a1f06668ff9dbf06c8094e1c5150c39488a5e911d"
layouts={};sections={}
utf="core::str::converts::from_utf8"
for role in refs:
    loc=work/"object-order"/role
    layouts[role]=json.loads((loc/"link-order.json").read_text())
    assert (loc/"native").read_bytes()==(out/(role+"-vec_round_slice")).read_bytes()
    if role in spec["anchors"]:
        assert {k:section(loc/"native",k) for k in (".text",".rodata")}==spec["anchors"][role]
    sections[role]={item:{k:section(loc/item,k) for k in (".text",".rodata")} for item in layouts[role]}
save(out/"link-order.json",layouts);save(out/"sections.json",sections)
for role,sites in layouts.items():
    print(role,{a:hex(s["routines"][utf][0]) for a,s in sites.items()},flush=True)
assert layouts["release"]["native"]["routines"][utf][0]==0xf068 and layouts["version"]["native"]["routines"][utf][0]==0xef64
pin()
pairs=[("version/native","candidate/native"), ("release/native","candidate/before-core"),
       ("release/native","candidate/native"), ("release/native","version/native"), ("version/native","pr/native")]
for a,b in pairs:
    x,y=(work/"object-order"/name for name in (a,b));pair=out/(a.replace("/","_")+"-vs-"+b.replace("/","_"))
    if x.read_bytes()==y.read_bytes():
        save(pair/"same.json",{"sha256":hashlib.sha256(x.read_bytes()).hexdigest()})
    else:
        crossover([x,y],out/"fixed-program",work/"caller",pair,[(4096,"plain")])
