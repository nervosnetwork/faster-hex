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
import tempfile
from isolated_cases import SCOPE, revisions, pairs, cases, SCOPE_BASE, APPEND, RECOVERY, VISITOR
from cause_common import BASE, ROOT, compare, measure, pin, save, section

PREPARED = "c2858276c1485881c1da8854c5fe1741d9df7cd9"
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
layout = SCOPE == 'short-json' and env.get('SHORT_JSON_LAYOUT') == '1'
if layout:
    env['JSON_REAL_CC'] = shutil.which('cc')
    wrapper = work / 'short-linker'
    wrapper.mkdir()
    shutil.copy2(ROOT/'verify/arm_json_link.py',wrapper/'cc')
    (wrapper/'cc').chmod(0o755)
    env['PATH'] = str(wrapper)+os.pathsep+env['PATH']
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
assert git('diff','--name-only',SCOPE_BASE,VISITOR).decode().splitlines()==['src/serde.rs']
assert git('diff','--name-only',APPEND,RECOVERY).decode().splitlines()==['src/decode.rs']
if SCOPE=='owned':
    assert git('diff','--name-only',SCOPE_BASE,revisions['owned']).decode().splitlines()==['src/serde.rs']
for role,ref in revisions.items():
    ver='2.0.0' if role=='release' else '2.1.0'

    if role == "release":
        cargo_home = Path(env.get("CARGO_HOME",Path.home()/".cargo"))
        pkg = Path(env["VERIFIED_RELEASE_ARCHIVE"]) if "VERIFIED_RELEASE_ARCHIVE" in env else next(cargo_home.glob("registry/cache/*/faster-hex-2.0.0.crate"))
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
bins=sorted({b for b,_,_ in cases})
for b in bins:
    src=work/"probe/downstream/src/bin"/(b+".rs")
    if src.is_file():
        shutil.copy2(src,driver/"src/bin"/src.name)
if SCOPE in ('visitor','owned'):
    shutil.copy2(ROOT/'verify/isolated_allocations.rs',driver/'src/bin/allocation_count.rs')
    shutil.copy2(work/'probe/downstream/src/bin/ownership.rs',driver/'src/bin/ownership.rs')

mode = env.get("CARGO_PROFILE_RELEASE_LTO","default")
out=out/mode
out.mkdir(exist_ok=True)
host_cmd = ['sysctl','-n','machdep.cpu.brand_string'] if sys.platform=='darwin' else ['lscpu']
cpu = env.get('VERIFIED_CPU_NAME') or sp.check_output(host_cmd,text=True)
save(out/'host.json', {'cpu':cpu,'rustc':sp.check_output(['rustc','-vV'],text=True),'lto':mode})
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
    transient=None
    if env.get('EPHEMERAL_BUILD')=='1':
        transient=tempfile.TemporaryDirectory(prefix='cargo-build-',dir=work)
        build_env['CARGO_TARGET_DIR']=transient.name
    if layout:
        build_env['JSON_LINK_WORK'] = str(work/'round-layout'/role)
    if SCOPE in ('legacy-errors','bounded-errors') and env.get('LEGACY_SITES')=='1' and role in ('release','version','scoped'):
        build_env['LEGACY_REAL_CC']=shutil.which('cc')
        build_env['LEGACY_WORK']=str(work/('table-sites' if SCOPE=='bounded-errors' else 'legacy-sites')/role)
        wrapper=work/'legacy-linker'
        wrapper.mkdir(exist_ok=True)
        shutil.copy2(ROOT/'verify'/('case_table_link.py' if SCOPE=='bounded-errors' else 'legacy_site_link.py'),wrapper/'cc')
        (wrapper/'cc').chmod(0o755)
        build_env['PATH']=str(wrapper)+os.pathsep+build_env['PATH']
    cargo=["cargo",*config]
    meta=json.loads(sp.check_output([*cargo,"metadata","--format-version=1","--locked","--offline"],cwd=driver,env=build_env))
    own,=[p for p in meta["packages"] if p["name"]=="faster-hex" and p["version"]==version]
    assert own["source"]==SOURCE and Path(own["manifest_path"]).parent==vendor/("faster-hex-"+version)
    consumers={n["id"] for n in meta["resolve"]["nodes"] if own["id"] in n["dependencies"]}
    assert {"ckb-jsonrpc-types","gix-hash","real-hex-consumers"} <= {p["name"] for p in meta["packages"] if p["id"] in consumers}
    available = list(bins)
    if SCOPE in ('fmt-join','fmt-field','append-shape','append-fill','prefix-kernel-exchange','prefix-operation','legacy-errors','bounded-errors','release-audit','append-storage','append-callsite','append-suffix') and role in ('release','version'):
        available = [b for b in bins if b not in ('append_call','append_storage','append_callsite','append_result','validate_call','prefix_buffer','prefix_format','prefix_extent')]
    if SCOPE in ('fmt-join','fmt-field','append-shape','append-fill','prefix-kernel-exchange','prefix-operation','append-storage','append-callsite','append-suffix','legacy-errors','bounded-errors','release-audit','surface','buffer','format','append','validation','append-report','arm-store','range-check','prefix-length','append-recovery','short-json'):
        if role in ('release','version') and SCOPE not in ('fmt-join','fmt-field','append-shape','append-fill','prefix-kernel-exchange','prefix-operation','append-storage','append-callsite','append-suffix','legacy-errors','bounded-errors','release-audit','arm-store','range-check','prefix-length','append-recovery','short-json'):
            available=[b for b in bins if b != 'append_call'] if SCOPE=='append-report' else [b for b in bins if b in ('full_format','full_buffer')]
        if SCOPE in ('append-recovery','short-json') and role in ('release','version'):
            available=[b for b in bins if b not in ('append_call','validate_call')]
        if SCOPE=='prefix-length' and role in ('release','version'):
            available=[b for b in bins if b not in ('prefix_buffer','prefix_format')]
        for name in available:
            harness = ROOT/'verify'/(name+'.rs')
            if harness.is_file():
                shutil.copy2(harness,driver/'src/bin'/(name+'.rs'))
            assert (driver/'src/bin'/(name+'.rs')).is_file()
    if SCOPE in ('fmt-join','fmt-field','prefix-length','release-audit','prefix-kernel-exchange','prefix-operation') and role in ('release','version'):
        probe=driver/'src/bin/gix_prefix.rs'
        use_view='faster_hex::Hex::new(prefix.as_oid().as_bytes()).leading_digits(prefix.hex_len()).encode_to(dst).unwrap()'
        code=probe.read_text();assert code.count(use_view)==1
        probe.write_text(code.replace(use_view,'prefix.hex_to_buf(dst)'))
    if SCOPE=='fmt-join':
        available.append('fmt_costs')
        shutil.copy2(ROOT/'verify/fmt_costs.rs',driver/'src/bin/fmt_costs.rs')
    run([*cargo,"build","--release","--locked","--offline","--quiet",*[item for b in available for item in ('--bin',b)],*(['--bin','allocation_count','--bin','ownership'] if SCOPE in ('visitor','owned') else [])], e=build_env)
    if SCOPE=='fmt-join':
        costs=sp.check_output([str(Path(build_env['CARGO_TARGET_DIR'])/'release/fmt_costs')],text=True)
        (out/(role+'-resource-costs.txt')).write_text(costs)
    if SCOPE in ('visitor','owned'):
        for name in ('allocation_count','ownership'):
            result=sp.check_output([str(Path(build_env['CARGO_TARGET_DIR'])/'release'/name)],text=True)
            (out/(role+'-'+name+'.txt')).write_text(result)
    if SCOPE == 'range-check':
        msg = sp.check_output([str(Path(build_env['CARGO_TARGET_DIR'])/'release/ascii_check'),'exhaustive'],text=True)
        (out/(role+'-byte-contract.txt')).write_text(msg)
    for b in available:
        img=out/(role+"-"+b)
        shutil.copy2(Path(build_env["CARGO_TARGET_DIR"])/"release"/b,img)
        sections[role+"/"+b]=section(img)
    if transient is not None: transient.cleanup()
save(out/"sections.json",sections)
if any(env.get(k)=='1' for k in ['INTEGRATED_CONFIRM','DIAGNOSTIC_BOUNDARY','PREFIX_ENTRY','DIAGNOSTIC_STEPS','DIAGNOSTIC_ROUTE']):
    fingerprints={}
    for key,text_section in sections.items():
        role,binary=key.split('/')
        img=out/(role+'-'+binary)
        fingerprints[key]={'whole_file':digest(img.read_bytes()),'text':text_section}
        if sys.platform.startswith('linux'):
            fingerprints[key]['rodata']=section(img,'.rodata')
    save(out/'program-fingerprints.json',fingerprints)
    if env.get('DIAGNOSTIC_ROUTE')=='1':
        from concrete_native_sections import owned_calls, record
        record(out,sections)
        owned_calls(out, fingerprints)

if SCOPE=='recovery' and sys.platform.startswith('linux'):
    from isolated_elf import record
    save(out/'elf.json',{role:record(out/(role+'-vec_round_slice')) for role in revisions})
pin();rng=random.Random(1837209 if env.get('INTEGRATED_CONFIRM')=='1' else (3691748 if env.get('DIAGNOSTIC_BOUNDARY')=='1' else (962539 if env.get('PREFIX_ENTRY')=='1' else (613870 if env.get('DIAGNOSTIC_STEPS')=='1' else (526769 if env.get('DIAGNOSTIC_ROUTE')=='1' else 602105)))))
rng.shuffle(cases)
summary={};samples={}
for b,n,k in cases:
    same_binary = SCOPE=='prefix-length' and b=='gix_prefix' and k.endswith('-adopt')
    def sample(role,repeat):
        how=k
        if env.get('DIAGNOSTIC_ROUTE')=='1' and role=='local_control':role='local'
        if env.get('DIAGNOSTIC_STEPS')=='1' and role=='groups_control':role='groups'
        if env.get('PREFIX_ENTRY')=='1' and role=='bounded_control':role='bounded'
        if env.get('DIAGNOSTIC_BOUNDARY')=='1' and role=='split_control':role='split'
        if env.get('INTEGRATED_CONFIRM')=='1':
            role={'aa':'combined','windows_control':'windows'}.get(role,role)
        if env.get('INTEGRATED_RELEASE')=='1' and role in ('view_control','combined_control'):
            role=role.removesuffix('_control')
        if same_binary and role.endswith('-legacy'):
            role=role.removesuffix('-legacy')
            how=k.removesuffix('-adopt')+'-legacy'
        args=[n,how,repeat] if b in ('gix_caller','ckb_caller') else [n,repeat,how]
        return measure(out/'same-program',out/(('scoped' if role=='aa' else role)+'-'+b),args,driver)
    count=max(200,min(5000000,round(17000000/max(1,sample('scoped',3000)))))
    rows=[]
    for _ in range(24):
        order=[r for r in revisions if (out/(r+"-"+b)).is_file()]+["aa"]
        if env.get('INTEGRATED_CONFIRM')=='1':
            # The public references for the existing and proposed operations have
            # already been qualified across all 101 cases. Repeat each actual
            # baseline for every relevant comparison, keeping provenance controls
            # for previously identified slow callers and common hash lengths.
            is_new=b in {'gix_prefix','prefix_buffer','prefix_format','append_call','validate_call'}
            baseline='pr' if is_new else 'release'
            order=[baseline,'owned','combined','selected','pairs','windows','aa','windows_control']
            key=(b,n,k)
            controls={
                ('full_buffer',65,'buffer'),('full_format',32,'display'),('full_format',32,'alternate'),
                ('owned_blocks',32,'array-late'),('owned_blocks',32,'vec-late'),('owned_blocks',4096,'vec-late'),
                ('ckb_caller',4096,'plain'),('gix_caller',20,'parse'),
                ('array_write',32,'plain'),('vec_write',4096,'plain'),
                ('vec_round_slice',4096,'plain'),('vec_round_slice',4096,'escaped'),
                ('gix_prefix',7,'sha1-adopt'),('prefix_buffer',64,'buffer'),('append_call',256,'valid')}
            if key in controls:
                for c in ('release','version','narrow','pr','scoped'):
                    if c not in order and (out/(c+'-'+b)).is_file(): order.append(c)
        if env.get('INTEGRATED_RELEASE')=='1': order += ['view_control','combined_control']
        if env.get('DIAGNOSTIC_BOUNDARY')=='1':order.append('split_control')
        if env.get('PREFIX_ENTRY')=='1':order.append('bounded_control')
        if env.get('DIAGNOSTIC_STEPS')=='1': order.append('groups_control')
        if env.get('DIAGNOSTIC_ROUTE')=='1': order.append('local_control')
        if same_binary: order += ['pr-legacy','scoped-legacy','candidate-legacy']
        rng.shuffle(order);groups={r:[] for r in order}
        for role in order+order[::-1]:groups[role].append(sample(role,count))
        rows.append({r:statistics.mean(v) for r,v in groups.items()})
    key=f'{b}/{n}/{k}'
    selected = pairs
    if same_binary: selected=pairs+[(r+'-legacy',r) for r in ('pr','scoped','candidate')]
    if SCOPE == 'append-report':
        selected = [pair for pair in pairs if (pair[0] != 'pr' or b == 'append_call') and (pair[0] != 'release' or b != 'append_call')]
    summary[key]={a+'/'+z:compare(rows,a,z) for a,z in selected if a in rows[0] and z in rows[0]}; samples[key]=rows
    print(key,{p:round(100*(v['ratio']-1),2) for p,v in summary[key].items()},flush=True)
    save(out/'times.json',summary);save(out/'samples.json',samples)
