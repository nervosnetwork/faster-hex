"""Move only serde_json's string writer, then pair the unchanged standalone program bodies."""
from pathlib import Path
import hashlib, json, os, random, re, statistics, subprocess

root = Path.cwd()
work = root / 'consumer-work'
out = root / 'results/placement'
out.mkdir(parents=True, exist_ok=True)
pin = ['taskset', '-c', str(min(os.sched_getaffinity(0)))]
offsets = [0, 16, 32, 48]
roles = ['base', 'head']
cases = ['mixed', 'escapedmixed']
ordinary = json.loads((root/'results/paired/independent-summary.json').read_text())
def output(args):
    return subprocess.check_output(args, text=True)

def symbols(exe):
    match = re.compile(r'^([0-9a-f]+) [TtWw] (.+)$')
    table = {}
    for line in output(['nm', '-nC', '--defined-only', exe]).splitlines():
        m = match.match(line)
        if m:
            table.setdefault(m[2], []).append(int(m[1],16))
    return table

def image(role, case, offset):
    return work / ('link-' + role) / f'{case}-{offset}'

def addresses(exe):
    syms = symbols(exe)
    (writer,) = syms.pop('serde_json::ser::format_escaped_str')
    syms.pop('__jsonbench_start',None)
    code = json.dumps(syms, sort_keys=True).encode()
    return dict(writer=writer, others=len(syms), fingerprint=hashlib.sha256(code).hexdigest())

images = {}
for role in roles:
    for case in cases:
        original = addresses(work/role/case)
        print(role, case, 'ordinary', original, flush=True)
        others = set()
        for offset in offsets:
            result = addresses(image(role, case, offset))
            assert result['writer'] % 64 == offset, (role,case,offset,result)
            others.add(result['fingerprint'])
            images[f'{role}/{case}/{offset}'] = result
        assert len(others) == 1, (role,case,others)
        print(role, case, 'all other code symbols stayed at the same addresses', flush=True)
(out/'symbols.json').write_text(json.dumps(images,indent=2))
rng = random.Random(71289)
groups = {case: [] for case in cases}
for cycle in range(12):
    sequence = [(case, role, offset) for case in cases for role in roles for offset in offsets]
    rng.shuffle(sequence)
    samples = {case:{} for case in cases}
    for case, role, offset in sequence:
        num = int(max(3500, 26_000_000/ordinary[f'{case}/4096']['pair']['a_ns']))
        score = float(output([*pin, image(role,case,offset),'4096',str(num)]))
        samples[case][f'{role}/{offset}'] = score
    for case in cases: groups[case].append(samples[case])
(out/'samples.json').write_text(json.dumps(groups,indent=1))
def bounds(xs):
    draws=sorted(statistics.median(rng.choices(xs,k=len(xs))) for _ in range(5000))
    return [statistics.median(xs), draws[124], draws[4874]]
report={}
for case, rows in groups.items():
    report[case] = {}
    for offset in offsets:
        for role in roles:
            key=f'{role}/{offset}'
            ns = statistics.median(row[key] for row in rows)
            rel=bounds([row[key] / row[role+'/0'] for row in rows])
            report[case][key] = dict(ns=ns,versus_zero=rel)
        report[case][str(offset)] = bounds([row[f'head/{offset}'] / row[f'base/{offset}'] for row in rows])
(out/'summary.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
