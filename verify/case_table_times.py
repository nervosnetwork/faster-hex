import json, os, random, statistics
from cause_common import ROOT, compare, measure, pin, save
work=ROOT/'real'
root=work/'table-sites'
roles=('release','version','scoped')
mode=os.environ.get('CARGO_PROFILE_RELEASE_LTO','default')
views={}
for r in roles:
    here=root/r
    if (here/'capture-error.txt').exists(): raise RuntimeError((r,(here/'capture-error.txt').read_text()))
    views[r]=json.loads((here/'positions.json').read_text())
    assert (here/'native').read_bytes()==(work/'qualification'/mode/(r+'-owned_blocks')).read_bytes()
labels=sorted(set.intersection(*(set(v) for v in views.values())))
assert {'native','rr','cr','aligned'}<=set(labels)
images={r+'/'+label:root/r/label for r in roles for label in labels};images['aa']=images['scoped/native']
pairs=[('scoped/native','aa')]+[(r+'/'+k,'scoped/'+k) for r in ('release','version') for k in labels]
pairs += [(r+'/'+a,r+'/'+b) for r in roles for a,b in [('rr','cr'),('rr','rc'),('cr','cc'),('rc','cc'),('rr','aligned')] if a in labels and b in labels]
pin(); rng=random.Random(290147)
for n,k in ((32,'array-late'),(32,'vec-late'),(32,'array-valid'),(4096,'array-late')):
    one=lambda role,reps:measure(work/'same-lookup-site',images[role],[n,reps,k],work/'caller')
    count=max(200,min(3_000_000,round(14_000_000/one('scoped/native',2500))))
    rows=[]
    for _ in range(32):
        order=list(images);rng.shuffle(order);vals={r:[] for r in images}
        for role in order+order[::-1]: vals[role].append(one(role,count))
        rows.append({r:statistics.mean(v) for r,v in vals.items()})
    save(root/(str(n)+'-'+k+'-samples.json'),rows)
    save(root/(str(n)+'-'+k+'-times.json'),{a+' vs '+b:compare(rows,a,b) for a,b in pairs})
