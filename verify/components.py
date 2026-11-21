"""Isolate changes with the published benchmark client, on one native machine."""
from pathlib import Path
import hashlib,json,os,platform,random,re,shutil,statistics,subprocess as sp,sys
repo=Path.cwd(); work=(repo/'component-work').resolve(); work.mkdir(exist_ok=True)
src=work/'codec';src.mkdir(exist_ok=True)
base='6d84260fe321669e7f93ecfb8aecb4db0f582f14';head='04ff3d5be797fcecd97135e42a295fc92e2e6c20'
driver=work/'driver.tar'
sp.run(['git','archive','-o',driver,base,'benches'],cwd=repo,check=True)
def show(ref,path):return sp.check_output(['git','show',ref+':'+path],cwd=repo,text=True)
def build_source(role):
 ref=head if role in ['full','release-errors','release-owned','release-services'] else base
 arc=work/'stage.tar'
 sp.run(['git','archive','-o',arc,ref],cwd=repo,check=True);sp.run(['tar','-xf',arc],cwd=src,check=True)
 sp.run(['tar','-xf',driver],cwd=src,check=True)
 c=src/'Cargo.toml';c.write_text(c.read_text().replace('version = "2.0.0"','version = "2.1.0"',1))
 lib=src/'src/lib.rs'
 if role=='encoding':
  for path in ['src/encode.rs','src/format.rs']:(src/path).write_text(show(head,path))
  lib.write_text(lib.read_text().replace('pub use crate::format::Hex;', 'pub use crate::format::{Hex, LeadingDigits};'))
 if role=='decoding':
  for path in ['src/decode.rs','src/decode/aarch64.rs','src/decode/x86.rs']:(src/path).write_text(show(head,path))
  s=lib.read_text().replace('    hex_decode_with_case, CheckCase,','    hex_decode_with_case, hex_validate, CheckCase,')
  lib.write_text(s.replace('pub use crate::decode::{hex_decode_vec, hex_decode_vec_with_case};','pub use crate::decode::{hex_decode_append, hex_decode_vec, hex_decode_vec_with_case};'))
 if role in ['release-errors','release-services']:
  d=src/'src/decode.rs';s=d.read_text();previous=show(base,'src/decode.rs')
  start='#[cold]\nfn decode_diagnosed('
  x=previous.index(start);y=previous.index('\n}',x)+2
  a=s.index(start);b=s.index('\n}',a)+2
  d.write_text(s[:a]+previous[x:y]+s[b:])
 if role in ['release-owned','release-services']:
  d=src/'src/decode.rs';s=d.read_text()
  entry='    unsafe { decode_owned(src, &mut bytes, check_case) }?;'
  assert s.count(entry)==2
  restored='''    if bytes.len() > 1024 {
        unsafe { decode_owned(src, &mut bytes, check_case) }?;
    } else {
        hex_decode_with_case(src, &mut bytes, check_case)?;
    }'''
  d.write_text(s.replace(entry,restored))
def clean_text(exe):
 text=sp.check_output(['otool','-l',exe],text=True)
 part=next(x for x in text.split('Section\n') if re.match(r'\s*sectname __text\s+segname __TEXT',x))
 address,size,off=[int(re.search(r'\b'+n+r'\s+(\S+)',part)[1],0) for n in ['addr','size','offset']]
 data=exe.read_bytes()[off:off+size]
 return {'addr':hex(address),'size':size,'hash':hashlib.sha256(data).hexdigest()}
roles=['released','encoding','decoding','full','release-errors','release-owned','release-services']
quick=bool(os.environ.get('SMOKE_COMPONENTS'))
if quick:roles=['released','release-services']
dest=repo/'results';dest.mkdir(exist_ok=True)
downstream=work/'downstream'
profile=os.environ.get('CARGO_PROFILE_BENCH_LTO','false')
env=dict(os.environ,CARGO_TARGET_DIR=str(work/'target'),CARGO_PROFILE_RELEASE_LTO=profile,CRITERION_HOME=str(work/'samples'))
sp.run([sys.executable,'verify/consumer.py'],cwd=repo,env=dict(env,STUDY_WORK=str(work),RESULTS=str(dest),RELEASE_FOCUS='1',GENERATE_ONLY='1',PRODUCT_REV=head),check=True)
def run(args,cwd):
    p=sp.run(args,cwd=cwd,env=env,text=True,stdout=sp.PIPE,stderr=sp.PIPE)
    if p.returncode:print(p.stderr[-2000:],flush=True);p.check_returncode()
    return p.stdout
sections={}
cpu=run(['sysctl','-n','machdep.cpu.brand_string'],repo).strip()
(dest/'host.txt').write_text(platform.platform()+'\n'+cpu+'\n'+run(['rustc','-vV'],repo))
for role in roles:
    build_source(role)
    if not (src/'Cargo.lock').exists():run(['cargo','generate-lockfile'],src)
    run(['cargo','clean','--profile','bench','-p','faster-hex'],src)
    records=run(['cargo','bench','--no-run','--locked','--bench','hex','--bench','check','--message-format=json-render-diagnostics'],src)
    folder=work/role;folder.mkdir(exist_ok=True)
    sections[role]={}
    for line in records.splitlines():
        j=json.loads(line)
        if j.get('executable') and 'bench' in j['target']['kind']:
            binary=folder/j['target']['name'];shutil.copy2(j['executable'],binary)
            sections[role][binary.name]=clean_text(binary)
    if not (downstream/'Cargo.lock').exists():run(['cargo','generate-lockfile'],downstream)
    run(['cargo','clean','--release','-p','consumer-timing','-p','faster-hex'],downstream)
    run(['cargo','build','--release','--locked','--bin','encode','--bin','decode'],downstream)
    for binary in ['encode','decode']:
        output=folder/binary;shutil.copy2(work/'target/release'/binary,output)
        sections[role][binary]=clean_text(output)
    assert set(sections[role])=={'hex','check','encode','decode'}
    (dest/'sections.json').write_text(json.dumps(sections,indent=2))
    print('Compiled',role,flush=True)
labels=roles+['control']
def role_of(label):return 'released' if label=='control' else label
criterion_cases={'hex':['encode/faster_hex/32'],'check':['invalid/decode/first/32','invalid/decode/first/4096','invalid/decode/last/4096']}
# The released driver is intact. Each filter selects only faster-hex calls.
rng=random.Random(639135)
estimates={c:{label:[] for label in labels} for cases in criterion_cases.values() for c in cases}
order=[]
for _ in range(1 if quick else 3):
    draw=labels.copy();rng.shuffle(draw);order.extend([draw,draw[::-1]])
for i,draw in enumerate(order):
    for label in draw:
        role=role_of(label);name=label+str(i)
        for binary,cases in criterion_cases.items():
            run([work/role/binary,'--bench','^('+'|'.join(cases)+')$','--warm-up-time','0.1' if quick else '0.20','--measurement-time','0.12' if quick else '0.7','--sample-size','20' if quick else '36','--nresamples','2000','--noplot','--save-baseline',name],work)
            for f in (work/'samples').rglob(name+'/benchmark.json'):
                key=json.loads(f.read_text())['full_id']
                if key not in cases:continue
                v=json.loads(f.with_name('estimates.json').read_text())
                estimates[key][label].append((v['slope'] or v['mean'])['point_estimate'])
    (dest/'measured-criterion.json').write_text(json.dumps(estimates,indent=2))
for key,rows in estimates.items():
    assert all(len(v)==len(order) for v in rows.values()),key
    print(key,{k:round(statistics.median(v),3) for k,v in rows.items()},flush=True)
cases=[('encode',32),('decode',256),('decode',4096)]
rows={}
for binary,n in cases:
    def sample(label,it):
        return float(run([work/role_of(label)/binary,str(n),str(it)],work))
    count=int(max(2000,min(12_000_000,(8_000_000 if quick else 65_000_000)/max(.5,sample('released',10000)))))
    values={label:[] for label in labels}
    for _ in range(2 if quick else 14):
        draw=labels.copy();rng.shuffle(draw)
        pair={label:[] for label in labels}
        for label in draw+draw[::-1]:pair[label].append(sample(label,count))
        for label in labels:values[label].append(statistics.mean(pair[label]))
    key=binary+'/'+str(n);rows[key]=values
    (dest/'measured-callers.json').write_text(json.dumps(rows,indent=2))
    print(key,{k:round(statistics.median(v),3) for k,v in values.items()},flush=True)
