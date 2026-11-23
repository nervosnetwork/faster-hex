"""Compare the added APIs with their measured public implementations in real callers."""
import json
import math
import os
from pathlib import Path
import random
import shutil
import statistics
import sys

v = Path(__file__).resolve().parent
sys.path.insert(0, str(v))
import isolated_cases as scope
from cause_common import measure, pin, save

scope.revisions = {'version':'f83d1075a7945c2dfe56ee7b94d9b6b1783cdf93',
                   'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4',
                   'candidate':'5f541e65aae0b854d234b8a51406d1e45767729e'}
scope.pairs = []
scope.cases = [('ckb_caller',32,'plain'), ('ckb_caller',32,'escaped'), ('ckb_caller',4096,'plain'),
               ('gix_caller',20,'parse'), ('gix_caller',32,'parse'),
               ('vec_read_slice',32,'escaped'), ('array_read_slice',32,'escaped'),
               ('vec_round_slice',4096,'plain'), ('array_round_slice',4096,'plain'),
               ('gix_prefix',7,'sha1-adopt'), ('gix_prefix',12,'sha256-adopt'),
               ('gix_prefix',40,'sha1-adopt'), ('gix_prefix',64,'sha256-adopt'),
               ('append_call',32,'valid'), ('append_call',4096,'rollback'),
               ('validate_call',4096,'last')]
scope.cases = [row for row in scope.cases if row[0] not in ('gix_prefix','validate_call')]
driver = v/'isolate_callers.py'
source = driver.read_text().split('\npin();rng=',1)[0]
guard = "    if SCOPE in ('fmt-join','fmt-field','prefix-length','release-audit','prefix-kernel-exchange','prefix-operation') and role in ('release','version'):"
assert source.count(guard)==1
source=source.replace(guard, guard[:-1]+" and 'gix_prefix' in bins:")
ns = {'__name__':'__main__', '__file__':str(driver)}
exec(compile(source, str(driver), 'exec'), ns)
out = ns['out']
work = ns['work']
archives = json.loads((out.parent/'archives.json').read_text())
assert {d['role']:d['sha'] for d in archives} == scope.revisions
cases = scope.cases.copy()
pin()
rng = random.Random(201107)
counts = {}
data = {}
info = {}
def name(b,n,k):
    return f'{b}/{n}/{k}'
def arguments(b,n,k,count):
    return [n,k,count] if b in ('ckb_caller','gix_caller') else [n,count,k]
for b,n,k in cases:
    ref = 'pr' if b in ('gix_prefix','append_call','validate_call') else 'version'
    ref_image = out/(ref+'-'+b)
    image = out/('candidate-'+b)
    key = name(b,n,k)
    data[key] = []
    info[key] = {'reference':ref,'same_file':ref_image.read_bytes()==image.read_bytes(),
                 'same_text':ns['sections'][ref+'/'+b]==ns['sections']['candidate/'+b]}
save(out/'consumer-code.json',info)
for part in range(3):
    copies = {}
    for b in {c[0] for c in cases}:
        ref = 'pr' if b in ('gix_prefix','append_call','validate_call') else 'version'
        for slot,role in enumerate([ref,'candidate']*2):
            path=out/f'copy-{part}-{b}-{slot}'
            shutil.copy2(out/(role+'-'+b),path)
            copies[b,slot]=path
    positions = list(range(4))
    shifts = list(range(4))
    rng.shuffle(positions)
    rng.shuffle(shifts)
    for shift in shifts:
        order=[positions[(i+shift)%4] for i in (0,1,3,2)]
        rng.shuffle(cases)
        for b,n,k in cases:
            key=name(b,n,k)
            if info[key]['same_file']:
                continue
            def bench(slot,count):
                return measure(out/'same-launch',copies[b,slot],arguments(b,n,k,count),work/'caller')
            if key not in counts:
                counts[key]=max(900,min(5000000,round(6500000/max(1,bench(0,6000)))))
            row=[[] for _ in order]
            for slot in order+list(reversed(order)):
                row[slot].append(bench(slot,counts[key]))
            data[key].append([statistics.mean(x) for x in row])
    for file in copies.values():
        file.unlink()
    save(out/'consumer-samples.json',data)
def stats(items):
    x=list(items)
    n=len(x)
    k=sum(v>1 for v in x)
    return {'median':100*(statistics.median(x)-1),
            'halves':[100*(statistics.median(values)-1) for values in (x[:6],x[6:])],
            'slow_p':sum(math.comb(n,i) for i in range(k,n+1))/2**n}
report={}
for key,rows in data.items():
    if rows:
        report[key]={'effect':stats((b+d)/(a+c) for a,b,c,d in rows),
                     'copies':[stats(a/c for a,b,c,d in rows),stats(b/d for a,b,c,d in rows)]}
    else:
        report[key]={'identical':True}
save(out/'consumer-results.json',report)
