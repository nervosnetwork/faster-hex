from pathlib import Path
import json,time
sibling=Path(__file__).parent/'official-paired.py';spec=json.loads((sibling.parent/'kernel-experiment.json').read_text());code=sibling.read_text().split('orders=[[',1)[0];code=code.replace("cases=case_spec['matrix'][key]","cases=spec['cases'][key]").replace("benches=sorted({'serde' if c.startswith('serde_') else 'hex' for c in cases})","benches=['hex','serde'] + (['check'] if any(c.startswith('invalid/') for c in cases) else [])").replace("[('base',baseref),('head',head)]","[('base',baseref),('head',head),('proposal',spec['proposal'])]");exec(compile(code,str(sibling),'exec'))
def bench_for(case):
 return 'check' if case.startswith('invalid/') else 'serde' if case.startswith('serde_') else 'hex'
for b in {bench_for(c) for c in cases}:
 known={s.split(':',1)[0] for s in run([str(programs['head',b]),'--bench','--list'],src).splitlines()}
 assert all(c in known for c in cases if bench_for(c)==b),(b,cases,known)
assert digest(lock)==spec['locks'][key];anchors={role:metadata[role+'/hex']['text']==spec['anchors'][key][role]['text'] for role in ('base','head')};save('anchors.json',anchors);print('original-binary anchors',anchors,flush=True)
roles=['base','head','proposal']*2;seq=[0,1,5,2,4,3];rng=random.Random(745073);records={c:[] for c in cases};site=w/'bench'
for block in range(2):
 labels=list(range(6));rng.shuffle(labels);rows=list(range(6));rng.shuffle(rows);copies={}
 for b in benches:
  for i,role in enumerate(roles):
   dst=w/f'copy-{block}-{b}-{i}';shutil.copy2(programs[role,b],dst);copies[b,i]=dst
 for shift in rows:
  order=[labels[(s+shift)%6] for s in seq];shuffled=list(cases);rng.shuffle(shuffled)
  for case in shuffled:
   b=bench_for(case);row={}
   for i in order:
    site.unlink(missing_ok=True);os.link(copies[b,i],site)
    with tempfile.TemporaryDirectory(dir=w) as tmp:
     p=sp.run([str(site),'--bench','^'+re.escape(case)+'$','--warm-up-time','0.13','--measurement-time','0.4','--sample-size','25','--nresamples','2000','--noplot'],cwd=src,env={**env,'CRITERION_HOME':tmp},stdout=sp.PIPE,stderr=sp.STDOUT,text=True);assert p.returncode==0,p.stdout[-900:];hits=list(Path(tmp).glob('**/new/estimates.json'));assert len(hits)==1 and readj(hits[0].parent/'benchmark.json')['full_id']==case;row[i]=readj(hits[0])['mean']['point_estimate']
   records[case].append([row[k] for k in range(6)])
  save('samples.json',records)
 print('Finished six balanced orders',block+1,flush=True)
def fit(x):
 k=sum(v>1 for v in x);n=len(x);sig=lambda t:sum(math.comb(n,j) for j in range(t,n+1))/2**n
 return {'median':100*(statistics.median(x)-1),'halves':[100*(statistics.median(s)-1) for s in (x[:6],x[6:])],'slow_p':sig(k),'fast_p':sig(n-k)}
report={}
for case,rows in records.items():
 ns=[[(v[i]+v[i+3])/2 for i in range(3)] for v in rows];measures={n:fit([v[b]/v[a] for v in ns]) for n,a,b in [('head_vs_base',0,1),('proposal_vs_base',0,2),('proposal_vs_head',1,2)]};measures['copies']={r:fit([v[i]/v[i+3] for v in rows]) for i,r in enumerate(roles[:3])};report[case]=measures
save('results.json',report);print({n:{k:round(v['median'],3) for k,v in s.items() if k!='copies'} for n,s in report.items()},flush=True)
for label,args in [('all',['--all-features']),('core',['--no-default-features'])]:
 p=sp.run(['cargo','test','--locked','--release',*args,'--lib','--tests'],cwd=src,env={**env,'CARGO_TARGET_DIR':str(w/'target-proposal')},stdout=sp.PIPE,stderr=sp.STDOUT,text=True);(out/(label+'.txt')).write_text(p.stdout);assert p.returncode==0,p.stdout[-1200:]

# Trace a separate, untimed process after all the clean timing trials.
if key=='ubuntu-24.04-arm-lto-thin':
 import bisect
 dbg=shutil.which('gdb')
 audit={}
 for role in ('base','head','proposal'):
  im=programs[role,'hex']
  if not dbg:
   audit[role]={'error':'gdb unavailable'}
   break
  rawlines=run(['nm','-n','--defined-only',str(im)]).splitlines()
  choices=[]
  for line in rawlines:
   m=re.fullmatch(r'([0-9a-f]+)\s+[Tt]\s+(\S*hex_decode_neon_owned\S*)',line)
   if m:choices.append((m[2],int(m[1],16)))
  assert len(choices)==1,choices
  raw,addr=choices[0];trace=w/(role+'-runtime-callers.json')
  gscript=w/(role+'-program-capture.py')
  gscript.write_text("""
import gdb,json
from pathlib import Path
symbol,static_addr,output=%r
absolute=int(gdb.parse_and_eval("(void*)&'"+symbol+"'"))
slide=absolute-static_addr
seen=[];unselected=0
class Inspect(gdb.Breakpoint):
 def stop(self):
  global unselected
  f=gdb.newest_frame()
  n=int(f.read_register('x1')); m=int(f.read_register('x3'))
  if (n,m)!=(8192,4096):return False
  regs={r:int(f.read_register(r)) for r in ('x0','x1','x2','x3','x4')}
  frames=[]
  while f is not None and len(frames)<10:
   frames.append([f.name() or '<unknown>',int(f.pc())-slide])
   f=f.older()
  measured=any('bencher' in name.lower() for name,pc in frames)
  if not measured and unselected<30:
   unselected+=1;return False
  seen.append({'source_offset':regs['x0']%%4096,'dest_offset':regs['x2']%%4096,'measured':measured,'source_len':n,'dest_len':m,'frames':frames})
  Path(output).write_text(json.dumps(seen))
  return len(seen)>=12
b=Inspect('*'+hex(absolute),internal=True)
gdb.execute('continue')
""" % ((raw,addr,str(trace)),))
  args=[dbg,'-q','-nx','-batch','-iex','set debuginfod enabled off','-ex','set pagination off','-ex','set confirm off','-ex','set disable-randomization off','-ex','starti','-x',str(gscript),'--args',str(im),'--bench','^decode_vec/faster_hex/4096$','--profile-time','4','--warm-up-time','0.1','--noplot']
  try:
   proc=sp.run(args,cwd=src,env={**env,'CRITERION_HOME':str(w/'trace-only')},stdout=sp.PIPE,stderr=sp.STDOUT,text=True,timeout=38)
   if not trace.exists():audit[role]={'error':proc.stdout[-2400:],'status':proc.returncode};continue
   seen=readj(trace);audit[role]={'visits':seen}
   lines=run(['nm','-n','-C','--defined-only',str(im)]).splitlines()
   syms=[]
   for l in lines:
    m=re.fullmatch(r'([0-9a-f]+)\s+[TtWw]\s+(.+)',l)
    if m:syms.append((int(m[1],16),m[2]))
   sortedaddrs=sorted({pc for pc,n in syms});names=dict(syms);fns={}
   for sample in seen:
    if not sample['measured']:continue
    for _,pc in sample['frames'][1:4]:
     i=bisect.bisect_right(sortedaddrs,pc)-1
     if 0<=i<len(sortedaddrs)-1:
      lo=sortedaddrs[i];hi=sortedaddrs[i+1]
      fns[lo]=(hi,names[lo])
   log=[]
   for lo,(hi,name) in sorted(fns.items()):
    if hi-lo>18000:continue
    log.append(run(['objdump','--demangle','-d','--start-address='+hex(lo),'--stop-address='+hex(hi),str(im)]))
   (out/(role+'-calling-code.txt')).write_text('\n'.join(log))
  except (sp.TimeoutExpired,OSError) as exc:
   audit[role]={'error':str(exc)}
 save('untimed-caller-trace.json',audit)
