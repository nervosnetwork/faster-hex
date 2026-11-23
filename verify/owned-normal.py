"""Identify the source of the preceding Vec caller's size in a normal ThinLTO link."""
from pathlib import Path
import io
import json
import math
import os
import random
import re
import shutil
import statistics
import subprocess as sp
import sys
import tarfile
import tempfile

helper = Path(__file__).with_name('official-paired.py')
exec(compile(helper.read_text().split('programs={};', 1)[0], str(helper), 'exec'))
from bench_caller_link import nm

cfg = readj(repo / 'verify/actual-caller.json')
trial = 'dfa586da5e3166e8e42e95f7e4f4cd223d7ef544'
lock = (repo / 'verify/caller-input.lock').read_bytes()
assert digest(lock) == cfg['lock']
assert 'Neoverse-N2' in run(['lscpu'])
lower = '_ZN9criterion7bencher16Bencher$LT$M$GT$4iter17hee995381bea950d5E'
upper = '_ZN9criterion7bencher16Bencher$LT$M$GT$4iter17h7f085ef7e367153dE'
programs = {}
observed = {}
targets = [('base', cfg['base']), ('head', cfg['head']), ('shared-try', trial),
           ('direct-return', cfg['head']), ('direct-try', trial)]
for tag, ref in targets:
    snapshot(ref)
    manifest = src / 'Cargo.toml'
    if tag == 'base':
        shutil.copytree(src / 'benches', w / 'driver')
        manifest.write_text(manifest.read_text().replace('version = "2.0.0"', 'version = "2.1.0"', 1))
        old_decode = (src / 'src/decode.rs').read_text()
        old_body = old_decode.split('fn decode_owned_large(', 1)[1].split(' {\n', 1)[1].split('\n}', 1)[0]
    else:
        shutil.rmtree(src / 'benches')
        shutil.copytree(w / 'driver', src / 'benches')
    if tag.startswith('direct-'):
        code = src / 'src/decode.rs'
        text = code.read_text()
        before, current = text.split('unsafe fn decode_owned_large(', 1)
        signature, current = current.split(' {\n', 1)
        _, after = current.split('\n}', 1)
        body = old_body
        if tag == 'direct-return':
            assert body.count('decode_diagnosed(src, dst, case)?;') == 1
            body = body.replace('decode_diagnosed(src, dst, case)?;', 'return decode_diagnosed(src, dst, case);')
        code.write_text(before + 'unsafe fn decode_owned_large(' + signature + ' {\n' + body + '\n}' + after)
    (src / 'Cargo.lock').write_bytes(lock)
    for path in [manifest, *(src / 'src').rglob('*.rs'), *(src / 'benches').rglob('*.rs')]:
        os.utime(path, None)
    target = {'CARGO_TARGET_DIR': str(w / 'target')}
    rows = list(map(json.loads, run(['cargo', 'bench', '--locked', '--no-run', '--bench', 'hex',
                                      '--message-format=json'], src, target).splitlines()))
    row, = [r for r in rows if r.get('target', {}).get('kind') == ['bench']]
    assert not row['fresh'] and (src / 'Cargo.lock').read_bytes() == lock
    image = w / tag
    shutil.copy2(row['executable'], image)
    programs[tag] = image
    info = machine(image)
    syms = nm(image)
    if tag in ('base', 'head'):
        assert info['text'] == cfg['anchors'][tag], (tag, info)
    if tag == 'base':
        neighbour, = [s[2] for s in syms if s[0] == 0x1c7ccc and 'Bencher' in s[2]]
    wanted = {s[2]: s[:2] for s in syms if s[2] in (neighbour, lower, upper)}
    assert len(wanted) == 3
    start, size = wanted[neighbour]
    dis = run(['objdump', '-dC', '--start-address='+str(start), '--stop-address='+str(start+size), str(image)])
    assert all(x in dis for x in ('calloc@plt', 'hex_decode_neon_owned', 'decode_diagnosed', 'unwrap_failed'))
    observed[tag] = dict(vec=wanted[neighbour], lower=wanted[lower], upper=wanted[upper], text=info['text'])
    save('source-locations.json', observed)
    print(tag, observed[tag], flush=True)

# Trace the real benchmark case independently of its mangled symbol hash.
addr = observed['base']['vec'][0]
main = next(int(line.split()[0], 16) for line in run(['nm', '-n', str(programs['base'])]).splitlines()
            if line.endswith(' T main'))
gdb = w / 'check-caller.gdb'
gdb.write_text('set pagination off\nset confirm off\nset debuginfod enabled off\nset language c\n'
               'set disable-randomization off\ntbreak main\nrun\n'
               + "python slide = int(gdb.parse_and_eval('(unsigned long)&main')) - " + str(main) + '\n'
               + "python b = gdb.Breakpoint('*'+hex(slide+" + str(addr) + '), temporary=True)\n'
               + "continue\npython print('OWNED_CALLER',hex(int(gdb.parse_and_eval('$pc'))-slide))\n")
argv = ['--bench', '^decode_vec/faster_hex/4096$', '--profile-time', '2', '--noplot']
result = sp.run(['gdb', '-q', '-nx', '--batch', '-x', str(gdb), '--args', str(programs['base']), *argv],
                cwd=src, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
(out / 'actual-caller.txt').write_text(result.stdout[-3000:])
assert 'OWNED_CALLER '+hex(addr) in result.stdout, result.stdout[-1800:]

base = observed['base']
head = observed['head']
assert base['vec'][1] - head['vec'][1] == base['lower'][0] - head['lower'][0] == 72
restored = [k for k in ('shared-try', 'direct-try', 'direct-return')
            if observed[k]['vec'] == base['vec'] and observed[k]['lower'] == base['lower']]
save('verdict.json', {'caller': neighbour, 'normal_links_restored': restored, 'input_lock': digest(lock)})
if not restored:
    sys.exit(0)
selected = restored[0]
labels = ['base', 'head', selected] * 2
cases = ['encode/faster_hex/8', 'encode/faster_hex/32', 'encode/faster_hex_upper/8', 'decode_vec/faster_hex/4096']
rows = {c: [] for c in cases}
os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
rng = random.Random(117211)
site = w / 'caller-measure'
for group in range(2):
    copies = []
    for slot, label in enumerate(labels):
        path = w / f'copy-{group}-{slot}'
        shutil.copy2(programs[label], path)
        copies.append(path)
    permutation = list(range(6))
    shifts = list(range(6))
    rng.shuffle(permutation)
    rng.shuffle(shifts)
    for step in shifts:
        order = [permutation[(i+step)%6] for i in (0, 1, 5, 2, 4, 3)]
        case_order = cases.copy()
        rng.shuffle(case_order)
        for case in case_order:
            times = [None] * 6
            for idx in order:
                site.unlink(missing_ok=True)
                os.link(copies[idx], site)
                with tempfile.TemporaryDirectory(dir=w) as temporary:
                    args = [str(site), '--bench', '^'+re.escape(case)+'$', '--warm-up-time', '0.12',
                            '--measurement-time', '0.35', '--sample-size', '25', '--nresamples', '2000', '--noplot']
                    p = sp.run(args, cwd=src, env={**env, 'CRITERION_HOME':temporary},
                               stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
                    assert p.returncode == 0, p.stdout[-900:]
                    estimate, = Path(temporary).glob('**/new/estimates.json')
                    assert readj(estimate.parent/'benchmark.json')['full_id'] == case
                    times[idx] = readj(estimate)['mean']['point_estimate']
            rows[case].append(times)
        save('samples.json', rows)
def summarize(xs):
    xs = list(xs)
    n = len(xs)
    k = sum(v > 1 for v in xs)
    return {'median':100*(statistics.median(xs)-1),
            'halves':[100*(statistics.median(t)-1) for t in (xs[:6], xs[6:])],
            'slow_p':sum(math.comb(n, i) for i in range(k, n+1))/2**n}
effects = {}
for case, data in rows.items():
    paired = [[(r[i]+r[i+3])/2 for i in range(3)] for r in data]
    effects[case] = {labels[j]+'_vs_'+labels[i]: summarize(r[j]/r[i] for r in paired)
                     for i, j in ((0,1),(0,2),(1,2))}
    effects[case]['copies'] = {labels[i]:summarize(r[i]/r[i+3] for r in data) for i in range(3)}
save('effects.json', effects)
