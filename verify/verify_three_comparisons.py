"""Exercise the production benchmark preparer against real source archives."""
from pathlib import Path
import hashlib
import io
import json
import os
import re
import shutil
import subprocess as sp
import sys
import tarfile
import tomllib

repo, run = (Path(p).resolve() for p in sys.argv[1:3])
base, cand = sys.argv[3:5]
run.mkdir(parents=True, exist_ok=True)
env = {**os.environ, "CARGO_TERM_COLOR":"never","CARGO_INCREMENTAL":"0"}
def archive(rev, folder):
    folder.mkdir()
    data=sp.check_output(["git","archive",rev],cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(folder,filter="data")
def files(path):
    return {str(p.relative_to(path)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(path.rglob("*")) if p.is_file()}
def version(p):
    return tomllib.loads((p/"Cargo.toml").read_text())["package"]["version"]
def prepare(w,mode):
    return sp.run([sys.executable,"candidate/ci/prepare_benchmarks.py",mode],cwd=w,
                  env=env,text=True,stdout=sp.PIPE,stderr=sp.STDOUT)
def stage(w):
    w.mkdir()
    archive(base,w/"baseline")
    archive(cand,w/"candidate")

def probe(root,target):
    f=root/"src/bin/version_comparison.rs"
    f.parent.mkdir(exist_ok=True)
    f.write_text('''fn main() {
    let input = std::env::args().nth(1).unwrap();
    let mut output = [0; 64];
    let hex = faster_hex::hex_encode(input.as_bytes(), &mut output).unwrap();
    println!("{hex}");
}
''')
    p=sp.run(["cargo","build","--release","--locked","--offline","--no-default-features",
              "--bin","version_comparison","-vv"],cwd=root,
             env={**env,"CARGO_TARGET_DIR":str(target),"CARGO_PROFILE_RELEASE_LTO":"thin"},
             stdout=sp.PIPE,stderr=sp.STDOUT,text=True)
    if p.returncode: raise RuntimeError(p.stdout[-4000:])
    line=next(x for x in p.stdout.splitlines() if "--crate-name faster_hex " in x and "--crate-type lib" in x)
    crate_id=re.search(r"-C metadata=(\w+)",line).group(1)
    binary=target/"release/version_comparison"
    s="0123456789abcdef"*2
    assert sp.check_output([binary,s],text=True).strip()==s.encode().hex()
    f.unlink()
    return {"binary":hashlib.sha256(binary.read_bytes()).hexdigest(),"crate":crate_id}

layout={"source": (("base","2.1.0"),("candidate","2.1.0")),
        "version": (("base","2.0.0"),("base","2.1.0")),
        "release": (("base","2.0.0"),("candidate","2.1.0"))}
images={}
for mode, pair in layout.items():
    w=run/mode
    stage(w)
    src={"base":files(w/"baseline/src"),"candidate":files(w/"candidate/src")}
    cases=files(w/"baseline/benches")
    assert src["base"]!=src["candidate"]
    p=prepare(w,mode)
    if p.returncode:raise RuntimeError(p.stdout)
    print(p.stdout.splitlines()[0],flush=True)
    for side,(source,expected_version) in zip(("baseline","head"),pair):
        root=w/side
        assert version(root)==expected_version
        assert files(root/"src")==src[source]
        assert files(root/"benches")==cases
        assert (root/".cargo/config.toml").read_bytes()==(w/"candidate/.cargo/config.toml").read_bytes()
        images[mode+"/"+side]=probe(root,run/("target-"+mode+"-"+side))
    if mode=="source":
        assert (w/"baseline/Cargo.lock").read_bytes()==(w/"head/Cargo.lock").read_bytes()
    print(mode,"both source trees, harnesses, locks and binaries checked",flush=True)
assert images["source/baseline"]==images["version/head"],images
assert images["source/head"]==images["release/head"],images
assert images["version/baseline"]==images["release/baseline"],images
assert images["version/baseline"]["crate"]!=images["version/head"]["crate"],images

w=run/"dependency-change"
stage(w)
extra=w/"candidate/lock-probe"
extra.mkdir()
(extra/"lib.rs").touch()
(extra/"Cargo.toml").write_text('[package]\nname="lock-probe"\nversion="0.1.0"\nedition="2021"\n[lib]\npath="lib.rs"\n')
with (w/"candidate/Cargo.toml").open("a") as f:
    f.write('\n[dev-dependencies.lock-probe]\npath="lock-probe"\n')
p=prepare(w,"release")
assert p.returncode and 'different dependencies' in p.stdout,p.stdout
print("A different dependency graph is rejected before measurement",flush=True)
(run/"images.json").write_text(json.dumps(images,indent=2)+"\n")
print("All three repeated binaries match byte-for-byte",flush=True)
