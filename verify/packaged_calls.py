"""Build the pinned consumers from crate archives, using the same registry source ID and lock graph."""
from pathlib import Path
import hashlib
import json
import os
import random
import shutil
import statistics
import subprocess as sp
import sys
import tarfile
from cause_common import BASE, ROOT, compare, measure, pin, save, section

PREPARED = "bbf8a73963c39bd5e2eb1b41bbf8727877e95bbc"
RELEASE = "6d84260fe321669e7f93ecfb8aecb4db0f582f14"
PUBLISHED = "e4ede54fe330383a5de28c0a1f06668ff9dbf06c8094e1c5150c39488a5e911d"
SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
work = Path(os.environ.get("PACKAGED_WORK", ROOT / "real")).resolve()
work.mkdir(parents=True, exist_ok=True)
driver = work / "caller"
vendor = work / "vendor"
out = work / "qualification"
out.mkdir(exist_ok=True)
shutil.copytree(ROOT / "verify/downstream/caller", driver, dirs_exist_ok=True)
template = (driver / "Cargo.toml").read_text().split("[patch.crates-io]")[0]
template += 'serde = { version = "=1.0.229", features = ["derive"] }\n'
lock = (driver / "Cargo.lock").read_text().replace(' "gix-hash",\n "serde_json",',' "gix-hash",\n "serde",\n "serde_json",')
assert ' "gix-hash",\n "serde",\n "serde_json",' in lock
env = dict(os.environ)
offline = ["--offline"] if env.get("CARGO_NET_OFFLINE") == "true" else []
def digest(b):
    return hashlib.sha256(b).hexdigest()
def git(*args):
    return sp.check_output(["git", *args], cwd=ROOT)
def run(cmd, cwd=driver, e=env):
    sp.run(cmd, cwd=cwd, env=e, check=True)
def resolve(version, checksum):
    (driver / "Cargo.toml").write_text(template.replace('{path="../codec"}', '"='+version+'"'))
    orig = 'name = "faster-hex"\nversion = "2.1.0"\n'
    assert lock.count(orig) == 1
    record = f'name = "faster-hex"\nversion = "{version}"\nsource = "{SOURCE}"\nchecksum = "{checksum}"\n'
    (driver / "Cargo.lock").write_text(lock.replace(orig,record).replace('"faster-hex 2.1.0"', '"faster-hex '+version+'"'))
resolve("2.0.0", PUBLISHED)
if not (vendor / "faster-hex-2.0.0/.cargo-checksum.json").exists():
    run(["cargo", "vendor", "--locked", *offline, "--versioned-dirs", str(vendor)])
assert json.loads((vendor / "faster-hex-2.0.0/.cargo-checksum.json").read_text())["package"] == PUBLISHED
config=["--config",'source.crates-io.replace-with="release-check"',"--config","source.release-check.directory="+json.dumps(str(vendor))]
registry = []
packages = {}
for ref, ver, role in [(RELEASE,"2.0.0","release"),(BASE,"2.1.0","pr"),(PREPARED,"2.1.0","prepared")]:
    if role == "release":
        cargo_home = Path(env.get("CARGO_HOME",Path.home()/".cargo"))
        pkg = next(cargo_home.glob("registry/cache/*/faster-hex-2.0.0.crate"))
        assert digest(pkg.read_bytes()) == PUBLISHED
    else:
        var = "QUALIFY_"+role.upper()+"_CRATE"
        if var in env:
            pkg = Path(env[var])
        else:
            src = work / ("source-"+role)
            if not src.exists():
                run(["git","worktree","add","--quiet","--detach",str(src),ref],cwd=ROOT)
            assert sp.check_output(["git","rev-parse","HEAD"],cwd=src,text=True).strip()==ref
            target = work / ("package-"+role)
            run(["cargo","package","--no-verify",*offline], cwd=src,e=dict(env,CARGO_TARGET_DIR=str(target)))
            pkg = target/"package"/"faster-hex-2.1.0.crate"
    with tarfile.open(pkg) as t:
        prefix = "faster-hex-"+ver+"/"
        files = {m.name[len(prefix):]:t.extractfile(m).read() for m in t if m.isfile() and m.name.startswith(prefix)}
    assert json.loads(files[".cargo_vcs_info.json"])["git"]=={"sha1":ref}
    sources = git("ls-tree","-r","--name-only",ref,"src").decode().splitlines()
    assert set(sources)=={p for p in files if p.startswith("src/")}
    for p in sources+["README.md","Cargo.toml.orig"]:
        assert files[p]==git("show",ref+":"+("Cargo.toml" if p=="Cargo.toml.orig" else p)),p
    packages[role]=(ver,files,digest(pkg.read_bytes()))
    registry.append({"role":role,"sha":ref,"checksum":packages[role][2],"src_files":len(sources)})
save(out/"archives.json",registry)
run([sys.executable, str(ROOT/"verify/which_field_slows.py")], cwd=ROOT,
    e=dict(env,FIELD_AREA=str(work/"probe"),FIELD_DRIVERS_ONLY="1"))
cases=[("ckb_caller",n,k) for n in (32,4096) for k in ("plain","escaped")]
cases += [("gix_caller",n,"parse") for n in (20,32)]
cases += [("checked",n,"codec") for n in (256,4096)]
cases += [(b,n,"plain") for b in ["array_read_slice","vec_read_slice","optvec_read_slice","array_round_slice","vec_round_slice"] for n in (32,4096)]
cases += [(b,4096,k) for b,k in [("array_read_reader","reader"),("vec_read_reader","reader"),("array_read_slice","escaped"),("vec_read_slice","escaped")]]
bins=sorted({b for b,_,_ in cases})
for b in bins:
    src=work/"probe/downstream/src/bin"/(b+".rs")
    if src.is_file():
        shutil.copy2(src,driver/"src/bin"/src.name)
shutil.copy2(ROOT/"verify/qualified_decode.rs",driver/"src/bin/checked.rs")
mode = env.get("CARGO_PROFILE_RELEASE_LTO","default")
out=out/mode
out.mkdir(exist_ok=True)
host_cmd = ['sysctl','-n','machdep.cpu.brand_string'] if sys.platform=='darwin' else ['lscpu']
save(out/'host.json', {'cpu':sp.check_output(host_cmd,text=True),'rustc':sp.check_output(['rustc','-vV'],text=True),'lto':mode})
sections={}
for role,(version,files,checksum) in packages.items():
    resolve(version,checksum)
    if role!="release":
        dest=vendor/"faster-hex-2.1.0"
        if dest.exists():
            dest.rename(work/("previous-vendor-"+role+"-"+mode))
        dest.mkdir()
        for name,data in files.items():
            p=dest/name
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(data)
        (dest/".cargo-checksum.json").write_text(json.dumps({"package":checksum,"files":{p:digest(s) for p,s in files.items()}}))
    build_env=dict(env,CARGO_TARGET_DIR=str(work/("target-"+role+"-"+mode)))
    cargo=["cargo",*config]
    meta=json.loads(sp.check_output([*cargo,"metadata","--format-version=1","--locked","--offline"],cwd=driver,env=build_env))
    own,=[p for p in meta["packages"] if p["name"]=="faster-hex" and p["version"]==version]
    assert own["source"]==SOURCE and Path(own["manifest_path"]).parent==vendor/("faster-hex-"+version)
    consumers={n["id"] for n in meta["resolve"]["nodes"] if own["id"] in n["dependencies"]}
    assert {"ckb-jsonrpc-types","gix-hash","real-hex-consumers"} <= {p["name"] for p in meta["packages"] if p["id"] in consumers}
    run([*cargo,"build","--release","--locked","--offline","--bins","--quiet"], e=build_env)
    for b in bins:
        img=out/(role+"-"+b)
        shutil.copy2(Path(build_env["CARGO_TARGET_DIR"])/"release"/b,img)
        sections[role+"/"+b]=section(img)
save(out/"sections.json",sections)
pin()
rng=random.Random(88589)
rng.shuffle(cases)
summary={}
samples={}
roles=list(packages)
for b,n,k in cases:
    def sample(role,repeat):
        args=([n,k,repeat] if b in ("ckb_caller","gix_caller") else [n,repeat] if b=="checked" else [n,repeat,k])
        return measure(out/"same-program",out/(("pr" if role=="aa" else role)+"-"+b),args,driver)
    count=max(200,min(3500000,round(14000000/max(1,sample("pr",3000)))))
    rows=[]
    for _ in range(20):
        order=roles+["aa"];rng.shuffle(order);groups={r:[] for r in order}
        for role in order+order[::-1]:
            groups[role].append(sample(role,count))
        rows.append({r:statistics.mean(v) for r,v in groups.items()})
    key=f"{b}/{n}/{k}"
    summary[key]={x+"/"+y:compare(rows,x,y) for x,y in [("release","pr"),("release","prepared"),("pr","prepared"),("pr","aa")]}
    samples[key]=rows
    print(key,{p:round(100*(s["ratio"]-1),2) for p,s in summary[key].items()},flush=True)
    save(out/"times.json",summary);save(out/"samples.json",samples)
