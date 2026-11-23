"""Time a single linked Rust scan loop at controlled offsets on this native CPU."""
import json, os, random, statistics, subprocess as sp
from pathlib import Path
here=Path(__file__).resolve().parent
out=Path(os.environ['RUNNER_TEMP'])/'placement-evidence'
out.mkdir(exist_ok=True)
program=out/'scan'
sp.run(['cc','-O2','-Wall','-Werror','-no-pie',here/'probe.c',here/'scan.S','-o',program],check=True)
sp.run([program],check=True)
cpu=min(os.sched_getaffinity(0));os.sched_setaffinity(0,{cpu})
host=sp.check_output(['lscpu'],text=True);(out/'host.txt').write_text(host)
nm=sp.check_output(['nm','-n',program],text=True)
(out/'symbol-addresses.txt').write_text('\n'.join(line for line in nm.splitlines() if ' loop_' in line)+'\n')
labels=dict(a16=0,a32=1,a48=2,b16=3,b32=4,b48=5,aa=0,bb=5)
rng=random.Random(701695)
cells={}
for n,bad in ((64,63),(64,0),(64,64),(32,31)):
    def measure(v,k):
        return float(sp.check_output([program,str(n),str(bad),str(labels[v]),str(k)],text=True))
    count=min(1700000,max(40000,round(6000000/measure('a16',150000))))
    pairs=[]
    for _ in range(32):
        order=list(labels);rng.shuffle(order);obs={v:[] for v in order}
        for v in order+order[::-1]:obs[v].append(measure(v,count))
        pairs.append({v:statistics.mean(x) for v,x in obs.items()})
    cells[f'{n}/{bad}']=pairs
    print(n,bad,count,{v:round(statistics.median(row[v] for row in pairs),2) for v in labels},flush=True)
(out/'samples.json').write_text(json.dumps(cells))
