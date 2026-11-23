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

def image_hashes(path):
    import struct
    original=path.read_bytes()
    result={"binary":hashlib.sha256(original).hexdigest(),"metadata_bytes":[]}
    if original.startswith(b"\xcf\xfa\xed\xfe"):
        data=bytearray(original)
        uuid=None
        sig=None
        cursor=32
        for _ in range(struct.unpack_from("<I",data,16)[0]):
            tag,size=struct.unpack_from("<II",data,cursor)
            if tag==0x1b:
                assert size==24 and uuid is None
                uuid=cursor+8
            if tag==0x1d:
                sig=struct.unpack_from("<II",data,cursor+8)
            cursor+=size
        if uuid is not None:
            data[uuid:uuid+16]=bytes(16)
            result["metadata_bytes"].append([uuid,16,"LC_UUID"])
            if sig is not None:
                start,length=sig
                magic,used,count=struct.unpack_from(">III",original,start)
                assert magic==0xfade0cc0 and used<=length
                for j in range(count):
                    slot,off=struct.unpack_from(">II",original,start+12+8*j)
                    if slot!=0:continue
                    cd=start+off
                    assert struct.unpack_from(">I",original,cd)[0]==0xfade0c02
                    hashes=struct.unpack_from(">I",original,cd+16)[0]
                    hlen,htype,_,pages=original[cd+36:cd+40]
                    assert hlen==32 and htype==2
                    pagesize=1<<pages
                    page=uuid//pagesize
                    assert (uuid+15)//pagesize==page
                    offset=cd+hashes+page*hlen
                    assert start<=offset<=start+length-hlen
                    pos=page*pagesize
                    assert original[offset:offset+hlen]==hashlib.sha256(original[pos:pos+pagesize]).digest()
                    data[offset:offset+hlen]=hashlib.sha256(data[pos:pos+pagesize]).digest()
                    result["metadata_bytes"].append([offset,hlen,"verified page hash covering LC_UUID"])
        result["comparable_image"]=hashlib.sha256(data).hexdigest()
    else:
        assert original.startswith(b"\x7fELF")
        result["comparable_image"]=result["binary"]
    return result

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
    return dict(image_hashes(binary),crate=crate_id)

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
for left,right in [("source/baseline","version/head"),("source/head","release/head"),("version/baseline","release/baseline")]:
    for key in ["comparable_image","crate","metadata_bytes"]:
        assert images[left][key]==images[right][key],(left,right,key,images)
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
print("All three independent controls match, including code, placement and data",flush=True)
