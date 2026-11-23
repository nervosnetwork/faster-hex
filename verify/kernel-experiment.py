from pathlib import Path
import json,os,re,shutil,subprocess as sp
sibling=Path(__file__).with_name('official-paired.py')
exec(compile(sibling.read_text().split('programs={};',1)[0],str(sibling),'exec'))
info=readj(repo/'verify/kernel-experiment.json')
oracle='1e8b6ca027aaa260d4b3a8d806c3bf4eb65c1e7b' if key.startswith('macos-15-intel-') else case_spec['head']
refs={'oracle':oracle,'scoped':info['proposal']}
frozen='25cfd8eb6a4cd8257a96fabaf73771cabcced4b4'
def sections(exe):
 data=exe.read_bytes();ss={}
 if data[:4]==b'\x7fELF':
  table,=struct.unpack_from('<Q',data,40);size,count,strings=struct.unpack_from('<HHH',data,58)
  rows=[struct.unpack_from('<IIQQQQIIQQ',data,table+i*size) for i in range(count)]
  s=rows[strings];names=data[s[4]:s[4]+s[5]]
  for idx,kind,flags,addr,start,n,*other in rows:
   if flags&2:
    name=names[idx:].split(b'\x00',1)[0].decode()
    ss[name]=[addr,n,digest(data[start:start+n]) if kind!=8 else 'zero']
 else:
  assert data[:4]==b'\xcf\xfa\xed\xfe';ptr=32
  for _ in range(struct.unpack_from('<I',data,16)[0]):
   cmd,total=struct.unpack_from('<II',data,ptr)
   if cmd==25:
    for i in range(struct.unpack_from('<I',data,ptr+64)[0]):
     label,seg,addr,n,start=struct.unpack_from('<16s16sQQI',data,ptr+72+i*80)
     name=seg.rstrip(b'\x00').decode()+','+label.rstrip(b'\x00').decode()
     ss[name]=[addr,n,digest(data[start:start+n]) if start else 'zero']
   ptr+=total
 return ss
records={};summary={};lock=None
for driver,revision,benches in [('released',case_spec['base'],['hex','serde']),('introduced',frozen,['hex','format','check'])]:
 records[driver]={};summary[driver]={}
 for label,sha in refs.items():
  snapshot(sha)
  manifest=src/'Cargo.toml'
  assert re.search(r'(?m)^version = "'+re.escape(case_spec['version'])+'"',manifest.read_text())
  shutil.rmtree(src/'benches')
  archive=sp.check_output(['git','archive',revision,'benches'],cwd=repo)
  with tarfile.open(fileobj=io.BytesIO(archive)) as ar:ar.extractall(src,filter='data')
  target=w/'target';options={'CARGO_TARGET_DIR':str(target)}
  if lock is None:
   run(['cargo','generate-lockfile'],src,options);lock=(src/'Cargo.lock').read_bytes()
   assert digest(lock)==info['locks'][key]
  else:(src/'Cargo.lock').write_bytes(lock)
  for directory in (src/'src',src/'benches'):
   for f in directory.rglob('*.rs'):os.utime(f,None)
  os.utime(manifest,None)
  args=sum((['--bench',b] for b in benches),[])
  rows=list(map(json.loads,run(['cargo','bench','--locked','--no-run',*args,'--message-format=json'],src,options).splitlines()))
  built=[x for x in rows if x.get('reason')=='compiler-artifact' and x['target']['name']=='faster_hex' and 'lib' in x['target']['kind']]
  assert built and any(not x['fresh'] for x in built),('library was not recompiled',label,driver)
  row={}
  for x in rows:
   if x.get('reason')=='compiler-artifact' and x['target']['kind']==['bench'] and x.get('executable'):
    bench=x['target']['name'];assert bench in benches and not x['fresh']
    exe=Path(x['executable']);row[bench]={'image':machine(exe),'sections':sections(exe)}
  assert set(row)==set(benches)
  records[driver][label]=row
  save('images-and-sections.json',records);print(driver,label,[k for k in row],flush=True)
  assert (src/'Cargo.lock').read_bytes()==lock
 for bench in benches:
  old,new=(records[driver][l][bench] for l in ('oracle','scoped'))
  altered=[s for s in sorted(set(old['sections'])|set(new['sections'])) if old['sections'].get(s)!=new['sections'].get(s)]
  summary[driver][bench]={'same_file':old['image']['file']==new['image']['file'],'same_text':old['image']['text']==new['image']['text'],'changed_sections':altered}
 save('equivalence.json',summary)
save('environment.json',{'profile':key,'target_specific_oracle':oracle,'candidate':info['proposal'],'release_driver':case_spec['base'],'new_driver':frozen,'lock':digest(lock),'rustc':run(['rustc','-Vv'])})
for fname,args in [('all',['--all-features']),('core',['--no-default-features'])]:
 p=sp.run(['cargo','test','--locked','--release',*args,'--lib','--tests'],cwd=src,env={**env,'CARGO_TARGET_DIR':str(w/'target')},stdout=sp.PIPE,stderr=sp.STDOUT,text=True)
 (out/(fname+'.txt')).write_text(p.stdout);assert p.returncode==0,p.stdout[-1200:]
print('per-image linked equivalence',summary,flush=True)
