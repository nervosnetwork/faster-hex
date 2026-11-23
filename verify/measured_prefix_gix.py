"""Measure all three package archives in the original public gix callers on one CPU."""
from pathlib import Path
import json,math,random,statistics,sys
v=Path(__file__).resolve().parent
settings=json.loads((v/'gix_public_usage_inputs.json').read_text())
settings['refs']={
 'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4',
 'parent':'d63e0a69bd3fab4d1b3261782f99f10701e1e400',
 'candidate':'324ed440a052944e2516bf79afdda262133e01a7'}
(v/'gix_public_usage_inputs.json').write_text(json.dumps(settings))
source=v/'gix_public_usage.py'
code=source.read_text().split("key=os.environ['HOST_KEY']",1)[0]
ns={'__file__':str(source),'__name__':'__main__'}
exec(compile(code,str(source),'exec'),ns)
out,work,seqs,save,section=map(ns.get,['out','work','cases','save','section'])
from cause_common import measure,pin
import os
key=os.environ['HOST_KEY']
if key in settings['anchors'] and 'pr' in settings['anchors'][key]:
 anchor=settings['anchors'][key]['pr']
 assert {n:section(out/'pr-gix_prefix',n) for n in ('.text','.rodata')}==anchor
info={}
for n in seqs:
 info[n]={role:{'file':ns['hash_bytes']((out/(role+'-'+n)).read_bytes()),'text':section(out/(role+'-'+n))} for role in settings['refs']}
save(out/'public-images.json',info)
pin();roles=['pr','parent','candidate']*2
samples={};results={};temps={};rng=random.Random(703482)
for n,cases in seqs.items():
 if len({x['file'] for x in info[n].values()})==1:
  results[n]={'same_program':True};continue
 for width,mode in cases:
  label=f'{n}/{width}/{mode}'
  paths=[out/(r+'-'+n) for r in roles]
  count=max(800,min(4500000,round(7000000/max(.2,measure(out/'single-launch',paths[1],[width,16000,mode],work/'caller')))))
  rows=[]
  for block in range(2):
   copies=[]
   for i,p in enumerate(paths):
    name=out/f'copy-{n}-{width}-{mode}-{block}-{i}'
    ns['shutil'].copy2(p,name);copies.append(name)
   perms=list(range(6));shifts=list(range(6));rng.shuffle(perms);rng.shuffle(shifts)
   for shift in shifts:
    order=[perms[(i+shift)%6] for i in [0,1,5,2,4,3]]
    values=[[] for _ in roles]
    for i in order+order[::-1]:
     values[i].append(measure(out/'single-launch',copies[i],[width,count,mode],work/'caller'))
    rows.append([statistics.mean(x) for x in values])
   for p in copies:p.unlink()
  def stats(vals):
   n=len(vals);k=sum(v>1 for v in vals)
   sig=lambda k:sum(math.comb(n,i) for i in range(k,n+1))/2**n
   return {'median':100*(statistics.median(vals)-1),'halves':[100*(statistics.median(part)-1) for part in (vals[:6],vals[6:])],'slow_p':sig(k),'fast_p':sig(n-k)}
  labelstats={key:stats([(row[b]+row[b+3])/(row[a]+row[a+3]) for row in rows]) for key,a,b in [('edit_vs_parent',1,2),('edit_vs_pr',0,2),('parent_vs_pr',0,1)]}
  labelstats['copies']={roles[i]:stats([row[i]/row[i+3] for row in rows]) for i in range(3)}
  samples[label]=rows;results[label]=labelstats
  save(out/'public-samples.json',samples);save(out/'public-results.json',results)
  print(label,round(labelstats['edit_vs_parent']['median'],2),round(labelstats['edit_vs_pr']['median'],2),flush=True)
save(out/'public-results.json',results)
