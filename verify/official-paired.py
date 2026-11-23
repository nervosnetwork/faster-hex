from pathlib import Path
import hashlib,io,json,math,os,platform,random,re,shutil,statistics,struct,subprocess as sp,sys,tarfile,tempfile
repo=Path.cwd();case_spec=json.loads((repo/'verify/official-selection.json').read_text());key=sys.argv[1];cases=case_spec['matrix'][key];w=Path(tempfile.mkdtemp(prefix='hex-paired-'));src=w/'crate';out=repo/'out';out.mkdir();env={**os.environ,'CARGO_INCREMENTAL':'0','CARGO_TERM_COLOR':'never'}
readj=lambda p:json.loads(p.read_text());save=lambda f,d:(out/f).write_text(json.dumps(d,indent=2)+'\n');digest=lambda data:hashlib.sha256(data).hexdigest()
def run(args,where=repo,extra=None):return sp.check_output(args,cwd=where,env={**env,**(extra or {})},text=True)
def snapshot(sha):
 if src.exists():shutil.rmtree(src)
 src.mkdir();raw=sp.check_output(['git','archive',sha],cwd=repo)
 with tarfile.open(fileobj=io.BytesIO(raw)) as ar:ar.extractall(src,filter='data')
def machine(p):
 data=p.read_bytes();section=None
 if data[:4]==b'\x7fELF':
  off,=struct.unpack_from('<Q',data,40);sz,count,strings=struct.unpack_from('<HHH',data,58);ss=[struct.unpack_from('<IIQQQQIIQQ',data,off+j*sz) for j in range(count)];t=ss[strings];label=data[t[4]:t[4]+t[5]]
  section=next((s[3],s[4],s[5]) for s in ss if label[s[0]:].split(b'\0',1)[0]==b'.text')
 else:
  assert data[:4]==b'\xcf\xfa\xed\xfe';pos=32
  for _ in range(struct.unpack_from('<I',data,16)[0]):
   op,sz=struct.unpack_from('<II',data,pos)
   if op==25:
    for i in range(struct.unpack_from('<I',data,pos+64)[0]):
     x,seg,addr,n,begin=struct.unpack_from('<16s16sQQI',data,pos+72+i*80)
     if x.rstrip(b'\0')==b'__text' and seg.rstrip(b'\0')==b'__TEXT':section=(addr,begin,n)
   pos+=sz
 addr,begin,n=section;return {'file':digest(data),'text':[addr,n,digest(data[begin:begin+n])]}
programs={};metadata={};symbols={};baseref=case_spec['base'];head=case_spec['head'];benches=sorted({'serde' if c.startswith('serde_') else 'hex' for c in cases});args=sum((['--bench',b] for b in benches),[])
for role,sha in [('base',baseref),('head',head)]:
 snapshot(sha);manifest=src/'Cargo.toml';v=manifest.read_text();m=re.search(r'(?m)^version = "([^"\n]+)"',v);assert m and v.count(m.group(0))==1
 manifest.write_text(v[:m.start(1)]+case_spec['version']+v[m.end(1):]);target=w/('target-'+role);opts={'CARGO_TARGET_DIR':str(target)}
 if role=='base':
  shutil.copytree(src/'benches',w/'driver');run(['cargo','generate-lockfile'],src,opts);lock=(src/'Cargo.lock').read_bytes()
 else:
  shutil.rmtree(src/'benches');shutil.copytree(w/'driver',src/'benches');(src/'Cargo.lock').write_bytes(lock)
 assert (src/'Cargo.lock').read_bytes()==lock;records=run(['cargo','bench','--locked','--no-run',*args,'--message-format=json'],src,opts)
 for row in map(json.loads,records.splitlines()):
  if row.get('reason')!='compiler-artifact' or not row.get('executable') or row['target']['name'] not in benches or row['target']['kind']!=['bench']:continue
  b=row['target']['name'];im=w/(role+'-'+b);shutil.copy2(row['executable'],im);programs[role,b]=im;metadata[role+'/'+b]=machine(im)
  sym=run(['nm','-n','-C',str(im)]);symbols[role+'/'+b]=[l for l in sym.splitlines() if 'faster_hex::' in l and ('encode' in l or 'decode' in l) and len(l)<280][:120]
 assert all((role,b) in programs for b in benches);assert (src/'Cargo.lock').read_bytes()==lock
save('images.json',metadata);save('symbols.json',symbols);affinity=None
if hasattr(os,'sched_setaffinity'):
 affinity=min(os.sched_getaffinity(0));os.sched_setaffinity(0,{affinity})
model=run(['lscpu']) if platform.system()=='Linux' else run(['sysctl','-n','machdep.cpu.brand_string']);save('environment.json',{'cpu':model,'affinity':affinity,'rustc':run(['rustc','-Vv']),'lock':digest(lock),'profile':env['CARGO_PROFILE_BENCH_LTO'],'target':key,'cases':cases,'commits':[baseref,head]})
orders=[[0,1,3,2],[1,2,0,3],[2,3,1,0],[3,0,2,1]];rng=random.Random(2190113);role_keys=['base','head','head','base'];reps={c:[] for c in cases};copies={};site=w/'benchmark';seed=0
for group in range(3):
 rpm=list(orders);rng.shuffle(rpm);labels=list(range(4));rng.shuffle(labels)
 for b in benches:
  for idx,role in enumerate(role_keys):
   cp=w/f'run-{group}-{b}-{idx}';shutil.copy2(programs[role,b],cp);copies[b,idx]=cp
 for jordan in rpm:
  shuffled=list(cases);rng.shuffle(shuffled)
  for case in shuffled:
   b='serde' if case.startswith('serde_') else 'hex';row={}
   for idx in [labels[i] for i in jordan]:
    site.unlink(missing_ok=True);os.link(copies[b,idx],site)
    with tempfile.TemporaryDirectory(dir=w) as tmp:
     flags=[str(site),'--bench','^'+re.escape(case)+'$','--warm-up-time','0.15','--measurement-time','0.4','--sample-size','25','--nresamples','2000','--noplot']
     proc=sp.run(flags,cwd=src,env={**env,'CRITERION_HOME':tmp},text=True,stdout=sp.PIPE,stderr=sp.STDOUT);assert proc.returncode==0,proc.stdout[-2500:];files=list(Path(tmp).glob('**/new/estimates.json'));assert len(files)==1,(case,proc.stdout[-1000:]);e=files[0];assert readj(e.parent/'benchmark.json')['full_id']==case;row[idx]=readj(e)['mean']['point_estimate']
   reps[case].append([row[j] for j in range(4)])
 save('samples.json',reps);print('Completed four interleaved measurements per case',group+1,flush=True)
def sign(x):
 signvals=[v for v in x if v!=1];k=sum(v>1 for v in signvals);n=len(signvals);return sum(math.comb(n,j) for j in range(k,n+1))/2**n
def summarize(x):return {'median_pct':100*(statistics.median(x)-1),'half_pct':[100*(statistics.median(v)-1) for v in (x[:6],x[6:])],'slow_p':sign(x),'fast_p':sign([1/v for v in x])}
summary={}
for case,rows in reps.items():
 a=[(b+c)/(x+y) for x,b,c,y in rows];aa=[x/y for x,b,c,y in rows];bb=[b/c for x,b,c,y in rows];summary[case]={'effect':summarize(a),'base_copies':summarize(aa),'head_copies':summarize(bb)}
save('summary.json',summary);print(json.dumps({k:v['effect'] for k,v in summary.items()},indent=2),flush=True)
