"""Measure the cold-routine position independently of ordinary build comparisons."""
from pathlib import Path
import json, os, random, statistics
from cause_common import ROOT, compare, measure, pin, save
work=ROOT/'real'
root=work/'legacy-sites'
roles=('release','version','scoped')
labels=('native','matching','plus4','plus32')
mode=os.environ.get('CARGO_PROFILE_RELEASE_LTO','default')
for role in roles:
    old=root/role
    if (old/'capture-error.txt').exists():
        raise ValueError((role,(old/'capture-error.txt').read_text()))
    data=json.loads((old/'positions.json').read_text())
    assert set(data)==set(labels) and (old/'native').read_bytes()==(work/'qualification'/mode/(role+'-owned_blocks')).read_bytes()
pin()
rng=random.Random(210419)
images={r+'/'+k:root/r/k for r in roles for k in labels}
images['aa']=images['scoped/native']
pairs=[('scoped/native','aa')]+[('release/'+k,'scoped/'+k) for k in labels]+[('version/'+k,'scoped/'+k) for k in labels]
pairs += [(r+'/matching', r+'/'+k) for r in roles for k in ('plus4','plus32')]
pairs += [(r+'/native', r+'/matching') for r in roles]
for n,kind in ((32,'array-late'),(32,'vec-late'),(32,'array-valid'),(4096,'array-late')):
    run=lambda key,count:measure(work/'owned-position-app',images[key],[n,count,kind],work/'caller')
    count=max(300,min(3_000_000,round(14_000_000/run('scoped/native',3000))))
    rows=[]
    for i in range(32):
        order=list(images);rng.shuffle(order);groups={k:[] for k in order}
        for k in order+order[::-1]:
            groups[k].append(run(k,count))
        rows.append({k:statistics.mean(v) for k,v in groups.items()})
    key=str(n)+'-'+kind
    save(root/(key+'-samples.json'),rows)
    save(root/(key+'-times.json'),{a+' vs '+b:compare(rows,a,b) for a,b in pairs})
