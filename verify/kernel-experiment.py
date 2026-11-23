from pathlib import Path
import json,time
sibling=Path(__file__).parent/'official-paired.py';spec=json.loads((sibling.parent/'kernel-experiment.json').read_text());code=sibling.read_text().split('orders=[[',1)[0];code=code.replace("cases=case_spec['matrix'][key]","cases=spec['cases'][key]").replace("benches=sorted({'serde' if c.startswith('serde_') else 'hex' for c in cases})","benches=['hex','serde']").replace("[('base',baseref),('head',head)]","[('base',baseref),('head',head),('proposal',spec['proposal'])]");exec(compile(code,str(sibling),'exec'))
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
   b='serde' if case.startswith('serde_') else 'hex';row={}
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
