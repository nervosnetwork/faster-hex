from pathlib import Path
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.request

v=Path(__file__).resolve().parent
sys.path.insert(0,str(v))
import isolated_cases as scope
from cause_common import pin,save,section
from cross_file_copies import crossover

spec=json.loads((v/'gix_public_usage_inputs.json').read_text())
scope.revisions=spec['refs']
scope.cases=[(op,n,mode) for op,seq in spec['standard_cases'].items() for n,mode in seq]
scope.pairs=[]
cases={'public_prefix':[(7,'sha1-adopt'),(0,'sha256-adopt')],
       'public_coexist':[(7,'sha1-adopt'),(0,'sha256-adopt'),(40,'sha1-full'),(64,'sha256-full')],
       'note_paths':[(0,'sha256'),(1,'sha1'),(2,'sha1'),(3,'sha256')]}
def hash_bytes(data):return hashlib.sha256(data).hexdigest()

def public_programs(role,driver,out,cargo,env):
    work=driver.parent;gitoxide=work/'gitoxide'
    sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=gitoxide,text=True).strip()
    assert sha==spec['gix']
    file=gitoxide/'gix-hash/src/prefix.rs'
    original=file.read_text()
    assert hash_bytes(original.encode())=='a8bac720a9c8b772cce903196fe5607c1f2698bbfd43f723c95b4feff4f47c10'
    i=original.index('        let complete_bytes = self.hex_len / 2;');j=original.index('\n    }',i)
    adopted=original[:i]+'''        faster_hex::Hex::new(self.as_oid().as_bytes())
            .leading_digits(self.hex_len())
            .encode_to(buf)
            .expect("buffer too small for hex prefix")'''+original[j:]
    notes=(gitoxide/'gix-note/src/lib.rs').read_text()
    i=notes.index("fn note_path<'a>(");j=notes.index('\n}',i)+2
    body=notes[i:j]
    assert hash_bytes(body.encode())==spec['note_path_sha256']
    existing=(v/'gix_usage/note_paths.rs').read_text()
    assert existing.count(body)==1
    for name in cases:shutil.copy2(v/'gix_usage'/(name+'.rs'),driver/'src/bin'/(name+'.rs'))
    bstr=next(p for p in tomllib.loads((gitoxide/'Cargo.lock').read_text())['package'] if p['name']=='bstr')
    assert bstr['version']=='1.13.1' and bstr['checksum']==spec['bstr_hash']
    location=work/'vendor'/('bstr-'+bstr['version'])
    if not location.exists():
        with urllib.request.urlopen('https://static.crates.io/crates/bstr/bstr-1.13.1.crate',timeout=45) as response:
            content=response.read()
        assert hash_bytes(content)==bstr['checksum']
        with tarfile.open(fileobj=io.BytesIO(content)) as tar:tar.extractall(work/'vendor',filter='data')
        members={str(p.relative_to(location)):hash_bytes(p.read_bytes()) for p in location.rglob('*') if p.is_file()}
        save(location/'.cargo-checksum.json',{'package':bstr['checksum'],'files':members})
    manifest=driver/'Cargo.toml';lock=driver/'Cargo.lock';toml=manifest.read_bytes();old_lock=lock.read_bytes()
    try:
        file.write_text(adopted)
        manifest.write_bytes(toml+b'bstr = { version = "=1.13.1", default-features = false }\n')
        meta=json.loads(subprocess.check_output([*cargo,'metadata','--format-version=1','--offline'],cwd=driver,env=env))
        pkg,=[p for p in meta['packages'] if p['name']=='faster-hex' and p['version']=='2.1.0']
        gix,=[p for p in meta['packages'] if p['name']=='gix-hash']
        assert pkg['source']=='registry+https://github.com/rust-lang/crates.io-index'
        assert Path(gix['manifest_path'])==gitoxide/'gix-hash/Cargo.toml'
        assert pkg['id'] in next(n['dependencies'] for n in meta['resolve']['nodes'] if n['id']==gix['id'])
        graph={p['id']:sorted(next(n['features'] for n in meta['resolve']['nodes'] if n['id']==p['id'])) for p in meta['packages']}
        graph_file=out/'public-dependency-graph.json'
        if graph_file.exists():assert graph==json.loads(graph_file.read_text())
        else:save(graph_file,graph)
        subprocess.run([*cargo,'build','--release','--locked','--offline','--quiet',*[arg for n in cases for arg in ('--bin',n)]],cwd=driver,env=env,check=True)
        for name,checks in cases.items():
            exe=out/(role+'-'+name)
            shutil.copy2(Path(env['CARGO_TARGET_DIR'])/'release'/name,exe)
            for n,k in checks:subprocess.run([exe,str(n),'350',k],stdout=subprocess.DEVNULL,check=True)
    finally:
        file.write_text(original);manifest.write_bytes(toml);lock.write_bytes(old_lock)

driver=v/'isolate_callers.py'
source,marker,_=driver.read_text().partition('\npin();rng=');assert marker
hook='    if transient is not None: transient.cleanup()'
assert source.count(hook)==1
source=source.replace(hook,'    public_programs(role,driver,out,cargo,build_env)\n'+hook)
ctx={'__name__':'__main__','__file__':str(driver),'public_programs':public_programs}
exec(compile(source,str(driver),'exec'),ctx)
out,work=ctx['out'],ctx['work']
assert {p['role']:p['sha'] for p in json.loads((out.parent/'archives.json').read_text())}==scope.revisions
key=os.environ['HOST_KEY']
checks={name:section(out/('previous-'+name))==expected for name,expected in spec['anchors'][key].items()}
save(out/'source-anchors.json',checks)
assert all(checks.values()),checks
pin();report={};all_cases={**spec['standard_cases'],**cases}
for name,seq in all_cases.items():
    a=out/('previous-'+name);b=out/('candidate-'+name)
    files=[hash_bytes(p.read_bytes()) for p in (a,b)]
    loaded={k:[section(p,k) for p in (a,b)] for k in ('.text','.rodata','.data.rel.ro','.data')}
    report[name]={'file_sha256':files,'sections':loaded}
    save(out/'runtime-sections.json',report)
    if any(left!=right for left,right in loaded.values()):
        crossover([a,b],out/'same-program',work/'caller',out/('previous-vs-candidate-'+name),seq,count_last=name=='ckb_caller')
qa=work/'product-qa';qa.mkdir()
with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['git','archive',spec['refs']['candidate']],cwd=v.parent))) as t:
    t.extractall(qa,filter='data')
env={**os.environ,'CARGO_TARGET_DIR':str(work/'product-qa-target')}
env.pop('CARGO_PROFILE_RELEASE_LTO',None)
for label,args in [('all-features',['--all-features']),('core-only',['--no-default-features'])]:
    p=subprocess.run(['cargo','test','--release',*args,'--lib','--tests'],cwd=qa,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    (out/(label+'.log')).write_text(p.stdout);assert p.returncode==0,p.stdout[-1800:]
