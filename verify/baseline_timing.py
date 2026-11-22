# The published image appears twice under different measurement labels.
pin()
rng=random.Random(514039)
rng.shuffle(cases)
timings={}
raw={}
for b,n,k in cases:
    args=lambda iters: ([n,k,iters] if b in ('ckb_caller','gix_caller') else [n,iters] if b=='checked' else [n,iters,k])
    def sample(role,iters):
        image=out/(('release' if role=='aa' else role)+'-'+b)
        return measure(out/'same-program',image,args(iters),driver)
    count=max(200,min(7000000,round(28000000/max(1,sample('release',3000)))))
    rows=[]
    for _ in range(22):
        order=['release','aa','repeat','version'];rng.shuffle(order);groups={r:[] for r in order}
        for role in order+order[::-1]:
            groups[role].append(sample(role,count))
        rows.append({r:statistics.mean(series) for r,series in groups.items()})
    key=f'{b}/{n}/{k}'
    timings[key]={name:compare(rows,'release',name) for name in ('aa','repeat','version')}
    raw[key]=rows
    save(out/'times.json',timings);save(out/'samples.json',raw)
    print(key, 'release ns', round(timings[key]['aa']['base_ns'],3), {name:round(100*(v['ratio']-1),2) for name,v in timings[key].items()},flush=True)
