"""Cross two intact consumer programs over independently written executable files."""
from pathlib import Path
import hashlib,json,math,os,random,statistics
from cause_common import measure,pin

def sign(xs):
    xs=[x for x in xs if x!=1]
    return sum(math.comb(len(xs),i) for i in range(sum(x>1 for x in xs),len(xs)+1))/2**len(xs)

def crossover(images, site, cwd, out, cases, count_last=False):
    out.mkdir(parents=True,exist_ok=True); pin()
    contents=[img.read_bytes() for img in images]
    assert contents[0]!=contents[1]
    hash_of=lambda v:hashlib.sha256(v).hexdigest()
    hashes=list(map(hash_of,contents))
    slots=[out/f'file-{i:02d}' for i in range(16)]
    for file in slots:
        file.touch(exist_ok=False);file.chmod(0o755)
    inodes=[p.stat().st_ino for p in slots]
    flip=[0,1]*8;random.Random(76019).shuffle(flip)
    assert len(set(inodes))==16
    (out/'design.json').write_text(json.dumps(dict(images=list(map(str,images)),sha256=hashes,inodes=inodes,initial=flip,cases=cases)))
    original=out/'saved-launch-file'
    assert not original.exists()
    if site.exists(): os.link(site,original)
    observations=[]
    try:
        for phase,swap in enumerate([0,1,1,0]):
            kinds=[p^swap for p in flip]
            for i,(slot,kind) in enumerate(zip(slots,kinds)):
                assert slot.stat().st_ino==inodes[i]
                with slot.open('r+b') as f:
                    f.write(contents[kind]);f.truncate();f.flush();os.fsync(f.fileno())
                assert hash_of(slot.read_bytes())==hashes[kind]
            sources={**{str(i):p for i,p in enumerate(slots)},'a':images[0],'b':images[1],'aa':images[0],'bb':images[1]}
            rng=random.Random(241111+phase*7907)
            shuffled=list(cases);rng.shuffle(shuffled)
            data={}
            for n,k in shuffled:
                key=f'{n}/{k}'
                def run(name,count):
                    args=[n,k,count] if count_last else [n,count,k]
                    return measure(site,sources[name],args,cwd)
                count=max(800,min(5000000,round(7000000/max(1,run('a',12000)))))
                trials=[]
                for _ in range(8):
                    order=list(sources);rng.shuffle(order)
                    result={name:[] for name in order}
                    for name in order+order[::-1]: result[name].append(run(name,count))
                    trials.append({name:statistics.mean(a) for name,a in result.items()})
                data[key]=trials
            observations.append(data)
            (out/f'period-{phase}.json').write_text(json.dumps(data))
            print(out.name,'period',phase,'complete',flush=True)
    finally:
        if original.exists():os.replace(original,site)
        else:site.unlink(missing_ok=True)
    rows=[]
    for n,k in cases:
        key=f'{n}/{k}';p=[q[key] for q in observations]
        aa=all(2*min(sign(xs),sign([1/x for x in xs]))>=.05 for q in ('a','b')
               for xs in [[sample[q+q]/sample[q] for block in p for sample in block]])
        original_pct=[100*(statistics.median(s['b']/s['a'] for samples in p[i:i+2] for s in samples)-1) for i in (0,2)]
        slot_effects=[]
        for first in (0,2):
            ratios=[]
            for i in range(len(slots)):
                # Each file serves both complete images. Half see each direction first.
                a,b=(statistics.median(s[str(i)] for s in p[j]) for j in (first,first+1))
                first_kind=flip[i]^(first//2)
                ratios.append(b/a if first_kind==0 else a/b)
            slot_effects.append(ratios)
        deltas=[100*(statistics.median(x)-1) for x in slot_effects]
        rows.append(dict(case=key,controls=aa,original=original_pct,crossed=deltas,
                    signs=[sum(v>1 for v in x) for x in slot_effects],
                    p=max(sign(x) for x in slot_effects),fast_p=max(sign([1/v for v in x]) for x in slot_effects),
                    ratios=slot_effects))
    (out/'summary.json').write_text(json.dumps(rows,indent=2))
    for row in rows:print(row['case'],row['controls'],row['original'],row['crossed'],row['signs'],row['p'],flush=True)
