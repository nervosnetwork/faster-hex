"""Run the candidate workflow's real version-matching step and sample its linked benchmarks."""
from pathlib import Path
import json
import os
import platform
import re
import shutil
import subprocess as sp
import textwrap

common = Path(__file__).with_name('official-paired.py')
exec(compile(common.read_text().split('programs={};', 1)[0], str(common), 'exec'))
config = readj(repo / 'verify/kernel-experiment.json')
target = config['proposal']
release = case_spec['base']
frozen = '25cfd8eb6a4cd8257a96fabaf73771cabcced4b4'
flow = run(['git', 'show', target + ':.github/workflows/rust.yml'])
start = flow.index('      - name: Match the package version and dependencies')
step = textwrap.dedent(flow[start:].split('        run: |\n', 1)[1].split('      - name:', 1)[0])
assert 'cargo fetch --locked' in step
pair = w / 'checkout'
pair.mkdir()
def checkout(sha, folder):
    data = sp.check_output(['git', 'archive', sha], cwd=repo)
    folder.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(folder, filter='data')
def normalize():
    sp.run(['bash', '-euo', 'pipefail', '-c', step], cwd=pair, env=env, check=True)
    lock = (pair / 'baseline/Cargo.lock').read_bytes()
    assert lock == (pair / 'candidate/Cargo.lock').read_bytes()
    return lock
base, cand = (pair / p for p in ('baseline', 'candidate'))
checkout(release, base)
checkout(release, cand)
manifest = cand / 'Cargo.toml'
before = manifest.read_text()
assert before.count('version = "2.0.0"') == 1
manifest.write_text(before.replace('version = "2.0.0"', 'version = "2.1.0"'))
probe = '''
fn main() {
    let n: usize = std::env::args().nth(1).unwrap().parse().unwrap();
    let input: Vec<_> = (0..n).map(|i| i as u8).collect();
    let mut dst = vec![0u8; 2*n];
    println!("{}", faster_hex::hex_encode(std::hint::black_box(&input), &mut dst).unwrap());
}
'''
for root in (base, cand):
    (root / 'src/bin').mkdir()
    (root / 'src/bin/version_probe.rs').write_text(probe)
def small_build(label, path):
    build_env = dict(env, CARGO_TARGET_DIR=str(w / ('target-' + label)),
                     CARGO_PROFILE_RELEASE_LTO=env['CARGO_PROFILE_BENCH_LTO'])
    result = sp.run(['cargo', 'build', '--release', '--no-default-features', '--bin', 'version_probe', '-vv'],
                    cwd=path, env=build_env, capture_output=True, text=True, check=True)
    lines = [line for line in result.stderr.splitlines() if '--crate-name faster_hex ' in line and '--crate-type lib' in line]
    assert len(lines) == 1
    exe = Path(build_env['CARGO_TARGET_DIR']) / 'release/version_probe'
    assert run([str(exe), '32']).strip() == bytes(range(32)).hex()
    return dict(metadata=re.search(r'-C metadata=([0-9a-f]+)', lines[0]).group(1), **machine(exe))
identity = {'release_as_declared': small_build('raw', base), 'version_control': small_build('control', cand)}
lock = normalize()
assert (base / 'Cargo.toml').read_bytes() == manifest.read_bytes()
identity['matched'] = small_build('matched', base)
assert identity['release_as_declared']['metadata'] != identity['matched']['metadata']
assert identity['matched']['metadata'] == identity['version_control']['metadata']
assert identity['matched']['text'] == identity['version_control']['text']
save('version-identity.json', {'builds': identity, 'lock': digest(lock), 'target': target,
                              'identical_full_image': identity['matched']['file'] == identity['version_control']['file']})
print('Version and lock control passed', key, flush=True)

# Use the exact historical driver and binary before interpreting any sampled hotspots.
cases = config['cases'][key]
prof = shutil.which('gprofng') or shutil.which(platform.machine() + '-linux-gnu-gprofng')
assert prof
cpus = os.sched_getaffinity(0)
expected = readj(repo / 'verify/probe-anchors.json')[key]
def driver(case):
    if case.startswith('prefix/'):
        return 'introduced', 'format'
    if case.startswith('check_'):
        return 'introduced', 'check'
    return 'released', 'hex'
traces = {}
for family in sorted({driver(case)[0] for case in cases}):
    driver_ref = frozen if family == 'introduced' else release
    benches = sorted({driver(case)[1] for case in cases if driver(case)[0] == family})
    for label, sha in [('baseline', driver_ref), ('candidate', target)]:
        snapshot(sha)
        if label == 'baseline' and family == 'released':
            # Use the manifest produced by the workflow from the published 2.0.0 source.
            (src / 'Cargo.toml').write_bytes((base / 'Cargo.toml').read_bytes())
        assert re.search(r'(?m)^version = "2\.1\.0"$', (src / 'Cargo.toml').read_text())
        shutil.rmtree(src / 'benches')
        data = sp.check_output(['git', 'archive', driver_ref, 'benches'], cwd=repo)
        with tarfile.open(fileobj=io.BytesIO(data)) as ar:
            ar.extractall(src, filter='data')
        (src / 'Cargo.lock').write_bytes(lock)
        for directory in (src / 'src', src / 'benches'):
            for child in directory.rglob('*.rs'):
                os.utime(child, None)
        os.utime(src / 'Cargo.toml', None)
        args = [v for name in benches for v in ('--bench', name)]
        rows = list(map(json.loads, run(['cargo', 'bench', '--locked', '--no-run', *args, '--message-format=json'],
                                        src, {'CARGO_TARGET_DIR': str(w/'bench-target')}).splitlines()))
        libs = [row for row in rows if row.get('reason')=='compiler-artifact' and row['target']['name']=='faster_hex' and 'lib' in row['target']['kind']]
        assert any(not row['fresh'] for row in libs)
        for row in rows:
            if row.get('reason') != 'compiler-artifact' or row['target']['kind'] != ['bench']:
                continue
            bench = row['target']['name']
            assert bench in benches and not row['fresh']
            exe = Path(row['executable'])
            img = machine(exe)
            assert img['text'] == expected[family][label][bench], (family, label, bench, img, expected[family][label][bench])
            d = run(['objdump', '-d', '-C', str(exe)])
            fullnm = run(['nm', '-nS', '--defined-only', str(exe)])
            demangle = run(['nm', '-nS', '-C', '--defined-only', str(exe)])
            syms = list(zip(fullnm.splitlines(), demangle.splitlines()))
            for case in (c for c in cases if driver(c) == (family, bench)):
                tag = label + '-' + case.replace('/', '-')
                experiment = w / (tag + '.er')
                flags = [str(exe), '--bench', '^' + re.escape(case) + '$', '--profile-time', '3', '--warm-up-time', '0.12', '--noplot']
                os.sched_setaffinity(0, {min(cpus)})
                p = sp.run([prof, 'collect', 'app', '-p', 'hi', '-o', str(experiment), *flags],
                           cwd=src, env=dict(env, CRITERION_HOME=str(w/'crit'), LC_ALL='C'),
                           capture_output=True, text=True, check=True)
                os.sched_setaffinity(0, cpus)
                assert case in p.stdout + p.stderr, (case, p.stdout[-400:], p.stderr[-400:])
                reports = {}
                for view in ('functions', 'pcs'):
                    output = run([prof, 'display', 'text', '-metrics', 'e.totalcpu:name', '-limit', '50',
                                  '-' + view, str(experiment)], extra={'LC_ALL':'C'})
                    assert '<Total>' in output and 'No data' not in output
                    reports[view] = output
                    (out / (tag+'-'+view+'.txt')).write_text(output)
                names = [raw.split(None,3)[-1] for raw, dem in syms
                         if len(raw.split(None,3))==4 and any(s in dem for s in
                         ('faster_hex::decode::', 'faster_hex::encode::', 'faster_hex::format::', 'Bencher<',
                          'Bencher::', 'LeadingDigits'))]
                active = [name for name in names if name in reports['pcs'] or name in reports['functions']]
                # Also keep candidate Bencher bodies if the sampling tool demangles them differently.
                assembly = []
                for block in d.split('\n\n'):
                    h = block.splitlines()[:1]
                    if h and ('faster_hex::' in h[0] or 'Bencher' in h[0]):
                        assembly.append(block)
                (out/(tag+'-assembly.txt')).write_text('\n\n'.join(assembly))
                traces[tag] = {'revision':sha, 'driver':driver_ref, 'image':img,
                               'same_text_as_previous_measured_image':True, 'matched_symbols':active[:14]}
                save('profiled.json', traces)
                print('Profiled measured image', tag, flush=True)
save('host.json',{'cell':key, 'lock':digest(lock), 'cpu':run(['lscpu']), 'rustc':run(['rustc','-Vv'])})
