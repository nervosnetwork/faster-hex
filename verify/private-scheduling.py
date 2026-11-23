"""Compare one source edit, its immediate parent and the reference for each API."""
from pathlib import Path
import json
import os
import shutil
import subprocess as sp

common = Path(__file__).with_name('official-paired.py')
exec(compile(common.read_text().split('programs={};', 1)[0], str(common), 'exec'))
spec = readj(repo / 'verify/isolated-apis.json')
change = os.environ['CHANGE']
cases = spec['matrix'][change][key]
parent = spec['parent']
proposal = spec['edits'][change]
frozen = spec['frozen']
release = spec['release']
anchors = spec['anchors'][key]

def suite(case):
    if case.startswith('owned_error/'):
        return 'owned_diagnostics', 'verify_owned_errors'
    if case.startswith('prefix/'):
        return 'new', 'format'
    if case.startswith('check_valid/'):
        return 'new', 'check'
    if case.startswith('decode_append/'):
        return 'new', 'hex'
    if case.startswith(('validate_error/', 'append_error/')):
        return 'diagnostics', 'verify_error'
    return 'released', ('serde' if case.startswith('serde_json/') else 'hex')

programs = {}
images = {}
lock = None
version = case_spec['version']
for family in sorted({suite(c)[0] for c in cases}):
    driver = release if family in ('released','owned_diagnostics') else frozen
    benches = sorted({suite(c)[1] for c in cases if suite(c)[0] == family})
    for label, sha in [('baseline', driver), ('parent', parent), ('edit', proposal)]:
        snapshot(sha)
        manifest = src / 'Cargo.toml'
        body = manifest.read_text()
        m = re.search(r'(?m)^version = "([^"\n]+)"', body)
        assert m and body.count(m[0]) == 1
        manifest.write_text(body[:m.start(1)] + version + body[m.end(1):])
        shutil.rmtree(src / 'benches')
        data = sp.check_output(['git', 'archive', driver, 'benches'], cwd=repo)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(src, filter='data')
        if family == 'diagnostics':
            shutil.copy2(repo/'verify/verify_error.rs', src/'benches/verify_error.rs')
            with manifest.open('a') as file:
                file.write('\n[[bench]]\nname = "verify_error"\nharness = false\n')
        if family == 'owned_diagnostics':
            shutil.copy2(repo/'verify/owned-errors.rs', src/'benches/verify_owned_errors.rs')
            with manifest.open('a') as file:
                file.write('\n[[bench]]\nname = "verify_owned_errors"\nharness = false\n')
        options = {'CARGO_TARGET_DIR':str(w/'target')}
        lock = (repo/'verify/caller-input.lock').read_bytes()
        assert digest(lock) == spec['locks'][key]
        (src/'Cargo.lock').write_bytes(lock)
        for tree in (src/'src', src/'benches'):
            for path in tree.rglob('*.rs'):
                os.utime(path, None)
        os.utime(manifest, None)
        args = [part for b in benches for part in ('--bench', b)]
        rows = list(map(json.loads, run(['cargo','bench','--locked','--no-run',*args,'--message-format=json'],src,options).splitlines()))
        assert (src/'Cargo.lock').read_bytes() == lock
        assert any(not row['fresh'] for row in rows if row.get('reason')=='compiler-artifact' and row['target']['name']=='faster_hex' and 'lib' in row['target']['kind'])
        for row in rows:
            if row.get('reason')!='compiler-artifact' or row['target']['kind']!=['bench']:
                continue
            b = row['target']['name']
            assert b in benches and not row['fresh']
            name = f'{family}-{b}-{label}'
            exe = w / name
            shutil.copy2(row['executable'], exe)
            img = machine(exe)
            images[name] = img
            programs[family,b,label] = exe
            if family in ('new','released') and label != 'edit':
                assert img['text'] == anchors[family][label][b], (name,img,anchors[family][label][b])
            ids = {line.split(':',1)[0] for line in run([str(exe),'--bench','--list'],src).splitlines()}
            assert all(c in ids for c in cases if suite(c)==(family,b)), (name,cases)
        save('images.json',images)
        print('Built',family,label,flush=True)
if hasattr(os,'sched_setaffinity'):
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
cpu = run(['lscpu']) if platform.system()=='Linux' else run(['sysctl','-n','machdep.cpu.brand_string'])
save('environment.json',dict(parent=parent,edit=proposal,base_release=release,base_new=frozen,case_ids=cases,
                            cpu=cpu,rustc=run(['rustc','-Vv']),lock=digest(lock),profile=key))
labels=['baseline','parent','edit']*2
records={c:[] for c in cases}
rng=random.Random(349387)
location=w/'bench-executable'
for block in range(2):
    permutation=list(range(6)); rng.shuffle(permutation)
    shifts=list(range(6)); rng.shuffle(shifts)
    copies={}
    for ((fam,b,l),exe) in programs.items():
        for slot in (v for v in range(6) if labels[v]==l):
            cp=w/f'{fam}-{b}-copy-{block}-{slot}'
            shutil.copy2(exe,cp); copies[fam,b,slot]=cp
    for shift in shifts:
        order=[permutation[(i+shift)%6] for i in [0,1,5,2,4,3]]
        order_cases=list(cases);rng.shuffle(order_cases)
        for case in order_cases:
            family,b=suite(case)
            row={}
            for slot in order:
                location.unlink(missing_ok=True)
                os.link(copies[family,b,slot],location)
                with tempfile.TemporaryDirectory(dir=w) as tmp:
                    cmd=[str(location),'--bench','^'+re.escape(case)+'$','--warm-up-time','0.12','--measurement-time','0.35','--sample-size','25','--nresamples','2000','--noplot']
                    p=sp.run(cmd,cwd=src,env={**env,'CRITERION_HOME':tmp},text=True,stdout=sp.PIPE,stderr=sp.STDOUT)
                    assert p.returncode==0,p.stdout[-800:]
                    matches=list(Path(tmp).glob('**/new/estimates.json'))
                    assert len(matches)==1 and readj(matches[0].parent/'benchmark.json')['full_id']==case
                    row[slot]=readj(matches[0])['mean']['point_estimate']
            records[case].append([row[n] for n in range(6)])
        save('samples.json',records)
    print('Completed six balanced orders',block+1,flush=True)
def stats(x):
    vals=[v for v in x if v!=1]
    n=len(vals);k=sum(v>1 for v in vals)
    def sign(k):
        return sum(math.comb(n,j) for j in range(k,n+1))/2**n
    return {'median':100*(statistics.median(x)-1),
            'halves':[100*(statistics.median(group)-1) for group in (x[:6],x[6:])],
            'slow_p':sign(k),'fast_p':sign(n-k)}
summary={}
for case,rows in records.items():
    paired=[[(v[n]+v[n+3])/2 for n in range(3)] for v in rows]
    ratios={name:stats([r[b]/r[a] for r in paired]) for name,a,b in [('parent_vs_baseline',0,1),('edit_vs_baseline',0,2),('edit_vs_parent',1,2)]}
    ratios['copies']={labels[i]:stats([row[i]/row[i+3] for row in rows]) for i in range(3)}
    summary[case]=ratios
save('results.json',summary)
print({k:round(v['edit_vs_parent']['median'],2) for k,v in summary.items()},flush=True)
for name,features in [('all',['--all-features']),('core',['--no-default-features'])]:
    p=sp.run(['cargo','test','--locked','--release',*features,'--lib','--tests'],cwd=src,
             env={**env,'CARGO_TARGET_DIR':str(w/'target')},text=True,stdout=sp.PIPE,stderr=sp.STDOUT)
    (out/(name+'.txt')).write_text(p.stdout)
    assert p.returncode==0,p.stdout[-1500:]
