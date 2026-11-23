"""Measure the same gix Prefix in a mixed caller, a single-method caller and an adopted public method."""
from pathlib import Path
import hashlib,json,os,random,shutil,statistics,subprocess as sp,sys,tempfile
from cause_common import ROOT,compare,measure,pin,save,section

role_refs={
    'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4',
    'scoped':'88eccb90f29402f8e2a0b00d1d5d0a72b05f91bd',
    'donor':'09a50778d4d210a27fcaba7cc993a18e918ca4f6',
    'bounded':'d1ffe8ee992bd5267eced3c3e4b7e34340beb664',
}
root=Path(os.environ.get('ORIGINAL_CONSUMERS',ROOT/'real')).resolve()
work=Path(os.environ.get('PACKAGED_WORK',ROOT/'gix-check')).resolve()
work.mkdir(parents=True,exist_ok=True)
(work/'ckb').symlink_to(root/'ckb',target_is_directory=True)
local=work/'gitoxide';local.mkdir()
for entry in (root/'gitoxide').iterdir():
    if entry.name in {'.git','target'}:continue
    if entry.name=='gix-hash':
        shutil.copytree(entry,local/entry.name,symlinks=True)
    else:
        (local/entry.name).symlink_to(entry,target_is_directory=entry.is_dir())
prefix=local/'gix-hash/src/prefix.rs'
upstream=prefix.read_text()
assert hashlib.sha256(prefix.read_bytes()).hexdigest()=='a8bac720a9c8b772cce903196fe5607c1f2698bbfd43f723c95b4feff4f47c10'
a=upstream.index('        let complete_bytes = self.hex_len / 2;')
b=upstream.index('\n    }',a)
adopted=upstream[:a]+'''        faster_hex::Hex::new(self.as_oid().as_bytes())
            .leading_digits(self.hex_len())
            .encode_to(buf)
            .expect("buffer too small for hex prefix")'''+upstream[b:]
assert '.expect("hexadecimal object IDs are valid UTF-8")' in upstream[a:b]
fixture=(ROOT/'verify/gix_prefix.rs').read_text()
a=fixture.index('        result = match method {');b=fixture.index('        black_box(result);',a)
adopt_only=fixture[:a]+'''        assert_eq!(method, "adopt");
        result = run(&prefixes, &expected, n, selected);
'''+fixture[b:]
public=adopt_only.replace('result = run(&prefixes, &expected, n, selected);','result = run(&prefixes, &expected, n, Prefix::hex_to_buf);')
a=public.index('fn selected');b=public.index('fn run(',a)
public=public[:a]+public[b:]
assert 'Prefix::hex_to_buf' not in adopt_only and 'fn selected' not in public
variants={'mixed':(fixture,upstream),'single':(adopt_only,upstream),'public':(public,adopted)}
# Use exactly the package-origin checks, lockfile and vendoring logic of the
# preceding native comparison. Only the benchmark binary differs by experiment.
os.environ.update(ISOLATE='release-audit',AUDIT_SHA=role_refs['scoped'],PACKAGED_WORK=str(work))
qualified=(ROOT/'verify/isolate_callers.py').read_text()
setup=qualified[:qualified.index('sections={}')]
marker='for role,ref in revisions.items():'
assert setup.count(marker)==1
setup=setup.replace(marker, "revisions="+repr(role_refs)+"\ncases=[('gix_prefix',7,'sha1-adopt')]\n"+marker)
state={'__name__':'gix_registry_setup','__file__':str(ROOT/'verify/gix_adoption.py')}
exec(compile(setup,'registry-setup','exec'),state)
out=state['out'];driver=state['driver'];env=state['env'];packages=state['packages'];vendor=state['vendor']
assert list(packages)==list(role_refs)
prefix_input=driver/'src/bin/gix_prefix.rs'
images={};fingerprints={};definition=state['resolve'];digest=state['digest']
for role,(version,files,checksum) in packages.items():
    definition(version,checksum)
    dest=vendor/'faster-hex-2.1.0'
    if dest.exists():
        dest.rename(work/('previous-vendor-'+role))
    dest.mkdir()
    for name,data in files.items():
        p=dest/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    (dest/'.cargo-checksum.json').write_text(json.dumps({'package':checksum,'files':{k:digest(v) for k,v in files.items()}}))
    with tempfile.TemporaryDirectory(prefix='cargo-',dir=work) as td:
        e=dict(env,CARGO_TARGET_DIR=td)
        cargo=['cargo',*state['config']]
        meta=json.loads(sp.check_output([*cargo,'metadata','--format-version=1','--locked','--offline'],cwd=driver,env=e))
        own,=[p for p in meta['packages'] if p['name']=='faster-hex' and p['version']==version]
        gix,=[p for p in meta['packages'] if p['name']=='gix-hash' and p['source'] is None]
        assert own['source']==state['SOURCE'] and Path(own['manifest_path']).parent==dest
        assert Path(gix['manifest_path']).parent==local/'gix-hash'
        assert any(n['id']==gix['id'] and own['id'] in n['dependencies'] for n in meta['resolve']['nodes'])
        for kind,(binary,method) in variants.items():
            prefix.write_text(method);prefix_input.write_text(binary)
            sp.run([*cargo,'build','--release','--locked','--offline','--quiet','--bin','gix_prefix'],cwd=driver,env=e,check=True)
            name=role+'/'+kind;exe=out/(role+'-'+kind)
            shutil.copy2(Path(td)/'release/gix_prefix',exe);images[name]=exe
            fingerprints[name]={'whole':digest(exe.read_bytes()),'text':section(exe)}
            if sys.platform.startswith('linux'):
                fingerprints[name]['rodata']=section(exe,'.rodata')
            sp.run([exe,'7','20','sha1-adopt'],stdout=sp.DEVNULL,check=True)
    assert (root/'gitoxide/gix-hash/src/prefix.rs').read_text()==upstream
prefix.write_text(upstream)
save(out/'program-fingerprints.json',fingerprints)
cases=[(0,'sha1-adopt'),(7,'sha1-adopt'),(40,'sha1-adopt'),(0,'sha256-adopt'),(7,'sha256-adopt'),(64,'sha256-adopt')]
rng=random.Random(729553);rng.shuffle(cases);pin()
controls={'aa-mixed':'pr/mixed','aa-single':'pr/single','aa-public':'pr/public'}
pairs=[('pr/'+kind,r+'/'+kind) for r in ('scoped','donor','bounded') for kind in variants]
pairs += [(r+'/'+a,r+'/'+b) for r in role_refs for a,b in [('mixed','single'),('single','public')]]
pairs += [(role,key) for key,role in controls.items()]
summary={};raw={}
for n,k in cases:
    def take(role,rep):
        return measure(out/'same-program',images[controls.get(role,role)],(n,rep,k),driver)
    reps=max(200,min(5000000,round(14000000/max(1,take('pr/mixed',3000)))))
    rows=[]
    for i in range(24):
        order=list(images)+list(controls);rng.shuffle(order);values={r:[] for r in order}
        for r in order+order[::-1]:values[r].append(take(r,reps))
        rows.append({r:statistics.mean(v) for r,v in values.items()})
    key=f'{n}/{k}';summary[key]={a+' vs '+b:compare(rows,a,b) for a,b in pairs};raw[key]=rows
    save(out/'gix-samples.json',raw);save(out/'gix-times.json',summary)
    print(key,{r:round(100*(v['ratio']-1),2) for r,v in summary[key].items() if r.startswith('pr/')},flush=True)
