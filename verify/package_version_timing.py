"""Change only the faster-hex package version within each source family."""
import json
import os
import re
import subprocess as sp
import sys
import tomllib
from pathlib import Path

v=Path(__file__).resolve().parent
root=v.parent
sys.path.insert(0,str(v))
import isolated_cases as scope
from cause_common import pin,save,section
from cross_file_copies import crossover

spec=json.loads((v/"package_version_inputs.json").read_text())
refs=spec["refs"]
scope.revisions=refs
scope.cases=[("vec_round_slice",4096,"plain")]
scope.pairs=[]
versions={k:tomllib.loads(sp.check_output(["git","show",ref+":Cargo.toml"],cwd=root,text=True))["package"]["version"] for k,ref in refs.items()}
assert {name for name,ver in versions.items() if ver=="3.0.0"}=={"old_3","pr_3","candidate_3"}
for a,b in [("release","old_3"),("pr","pr_3"),("combined_paths","candidate_3")]:
    assert sp.check_output(["git","diff","--numstat",refs[a],refs[b]],cwd=root,text=True).strip()=="1\t1\tCargo.toml"

# These two unmodified Rust checkouts use ^2 in their manifests. The benchmark
# admits either major in those manifests in EVERY build, including both anchors.
for package,rel,old in [("ckb","Cargo.toml","2.0"),("gitoxide","gix-hash/Cargo.toml","2.0.0")]:
    path=root/"real"/package/rel
    original=path.read_text()
    dep='faster-hex = { version = "'+old+'"'
    assert original.count(dep)==1
    path.write_text(original.replace(dep,'faster-hex = { version = ">=2.0, <4"'))
    assert sp.check_output(["git","diff","--name-only"],cwd=root/"real"/package,text=True).splitlines()==[rel]

driver=v/"isolate_callers.py"
code,separator,_=driver.read_text().partition("\npin();rng=")
assert separator
def change(old,new):
    global code
    assert code.count(old)==1,old
    code=code.replace(old,new)
change("    ver='2.0.0' if role=='release' else '2.1.0'","    ver=version_for[role]")
change('pkg = target/"package"/"faster-hex-2.1.0.crate"','pkg = target/"package"/("faster-hex-"+ver+".crate")')
change('dest=vendor/"faster-hex-2.1.0"','dest=vendor/("faster-hex-"+version)')
guard="    if SCOPE in ('fmt-join','fmt-field','prefix-length','release-audit','prefix-kernel-exchange','prefix-operation') and role in ('release','version'):"
change(guard,guard[:-1]+" and 'gix_prefix' in bins:")
mark='    available = list(bins)'
change(mark,'''    edges={p["name"] for p in meta["packages"] if p["id"] in consumers}
    assert {"ckb-fixed-hash-core","ckb-jsonrpc-types","gix-hash","real-hex-consumers"} <= edges
    captures[role] = [(p["name"], "tested-version" if p["id"] == own["id"] else p["version"],p["source"]) for p in meta["packages"]]
    available = list(bins)''')
captures={}
ns={"__file__":str(driver),"__name__":"__main__","version_for":versions,"captures":captures}
exec(compile(code,str(driver),"exec"),ns)
assert len(set(json.dumps(sorted(xs),sort_keys=True) for xs in captures.values()))==1
out,work=ns["out"],ns["work"]
assert "Neoverse-N2" in json.loads((out/"host.json").read_text())["cpu"]
archives=json.loads((out.parent/"archives.json").read_text())
assert {q["role"]:q["sha"] for q in archives}==refs
assert next(q["checksum"] for q in archives if q["role"]=="release")=="e4ede54fe330383a5de28c0a1f06668ff9dbf06c8094e1c5150c39488a5e911d"
sig={}
layout={}
for role in refs:
    image=out/(role+"-vec_round_slice")
    sig[role]={k:section(image,k) for k in (".text",".rodata")}
    syms=sp.check_output(["nm","-nS","-C","--defined-only",image],text=True)
    layout[role]={}
    for name in ("core::str::converts::from_utf8","vec_round_slice::measure","serde_json::ser::format_escaped_str"):
        matches=re.findall("^([a-f0-9]+) ([a-f0-9]+) [tT] "+re.escape(name)+"$",syms,re.M)
        assert len(matches)==1,(role,name)
        addr,size=map(lambda x:int(x,16),matches[0])
        layout[role][name]={"address":hex(addr),"page_offset":hex(addr%4096),"size":size}
save(out/"addresses.json",layout);save(out/"fingerprints.json",sig)
assert all(sig[k]==s for k,s in spec["anchors"].items())
print("Verified unchanged 2.x caller binaries. UTF-8 entry addresses",[(r,v["core::str::converts::from_utf8"]["address"]) for r,v in layout.items()],flush=True)
pin()
pairs=[("release","version"),("release","old_3"),("version","old_3"),("pr","pr_3"),("release","pr_3"),
       ("combined_paths","candidate_3"),("release","candidate_3")]
for a,b in pairs:
    pair=out/(a+"-vs-"+b)
    x,y=[out/(k+"-vec_round_slice") for k in (a,b)]
    if x.read_bytes()==y.read_bytes():
        pair.mkdir();save(pair/"same.json",{"identical_executable":True})
    else:
        crossover([x,y],out/"fixed-program",work/"caller",pair,[(4096,"plain"),(32,"plain")])
