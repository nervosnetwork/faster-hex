"""Run the published CKB round trip and cross its real readers/writers in one executable."""
from pathlib import Path
import os
import random
import shutil
import statistics
import subprocess as sp
import sys

from cause_common import compare, measure, pin, save, section

root = Path(__file__).resolve().parent.parent
work = root / "real"
out = root / "results"
driver = work / "caller"
codec2 = work / "old-codec"
old = "6d84260fe321669e7f93ecfb8aecb4db0f582f14"
codec2.mkdir(exist_ok=True)
archive = work / "old-product.tar"
sp.run(["git","archive","-o",archive,old],check=True,cwd=root)
sp.run(["tar","-xf",archive,"-C",codec2],check=True)
package = work / "ckb/util/jsonrpc-types"
manifest = package / "Cargo.toml"
manifest.write_text(manifest.read_text().replace("[dependencies]\n",
    '[dependencies]\nold-hex = {package="faster-hex",path="../../../old-codec",default-features=false,features=["std","serde"]}\n'))
original = (package / "src/bytes.rs").read_text()
assert original.count("faster_hex::") == 2
(package / "src/release_bytes.rs").write_text(original.replace("faster_hex::","old_hex::"))
lib = package / "src/lib.rs"
assert lib.read_text().count("mod bytes;") == 1
lib.write_text(lib.read_text().replace("mod bytes;","mod bytes;\n#[allow(missing_docs)]\npub mod release_bytes;"))
caller_manifest = driver / "Cargo.toml"
caller_manifest.write_text(caller_manifest.read_text().replace("[dependencies]\n",'[dependencies]\nbytes="1"\n'))
shutil.copy2(root / "verify/cross_ckb.rs", driver / "src/bin/cross_ckb.rs")
env = dict(os.environ, CARGO_TARGET_DIR=str(work/"target"))
sp.run(["cargo","build","--release","--offline","--bin","cross_ckb"],check=True,cwd=driver,env=env)
exe = work / "target/release/cross_ckb"
save(out/"crossed-ckb-code.json",dict(text=section(exe), real_ckb=sp.check_output(
    ["git","rev-parse","HEAD"],cwd=work/"ckb",text=True).strip()))
if os.getenv("CKB_BUILD_ONLY"):
    raise SystemExit(0)
pin()
rng=random.Random(429453)
keys=["release","pr","oo","on","no","nn","control"]
cases=[(32,"plain"),(32,"escaped"),(4096,"plain"),(4096,"escaped")]
site=work/"same-read-write"
raw={}
summaries={}
pairs=[("release","pr"),("oo","nn"),("oo","on"),("no","nn"),
       ("oo","no"),("on","nn"),("nn","control")]
for n, mode in cases:
    def time(key,count):
        if key in ("pr","release"):
            return measure(site,work/(key+"-ckb_caller"),[n,mode,count],driver)
        return measure(site,exe,[n,mode,count,"nn" if key=="control" else key],driver)
    count=max(500,min(3000000,int(28000000/max(.5,time("pr",6000)))))
    rows=[]
    for _ in range(26):
        order=keys.copy()
        rng.shuffle(order)
        groups={k:[] for k in keys}
        for key in order+order[::-1]:
            groups[key].append(time(key,count))
        rows.append({k:statistics.mean(v) for k,v in groups.items()})
    name=f"{n}/{mode}"
    raw[name]=rows
    summaries[name]={"|".join(p):compare(rows,*p) for p in pairs}
    save(out/"ckb-timings.json",summaries)
    save(out/"ckb-samples.json",raw)
    print(name,{k:round((v["ratio"]-1)*100,2) for k,v in summaries[name].items()},flush=True)
