"""Check the performance of the actual sampled Apple x86 code under matched layout."""
from pathlib import Path
import os, re, shutil, subprocess as sp, sys
sibling = Path(__file__).parent/'official-paired.py'
common = sibling.read_text().split('programs={};',1)[0]
exec(compile(common,str(sibling),'exec'))
spec = readj(repo/'verify/mac-order.json')
cases = spec['cases'][key]
refs={'base':case_spec['base'],'head':case_spec['head']}
images={}; metadata={}; checks={}; selected={}; identities={}
linker=repo/'verify/order-atoms.py'
wrap=w/'compiler'
wrap.write_text("""#!/usr/bin/env python3
import json,os,sys
args=sys.argv[2:]
if '--crate-name' in args and any(a.startswith('--emit=') for a in args):
    name=args[args.index('--crate-name')+1]
    bench=any(a.endswith('benches/hex.rs') for a in args)
    if name=='faster_hex' or bench:
        with open(os.environ['HEX_CRATE_IDS'],'a') as f:
            ids=[args[i+1] for i,a in enumerate(args[:-1]) if a=='-C' and args[i+1].startswith(('metadata=','extra-filename='))]
            f.write(json.dumps([name,ids])+'\\n')
    if bench: args+=['-C','linker='+os.environ['HEX_ORDER_LINKER']]
os.execvp(sys.argv[1],[sys.argv[1],*args])
""")
wrap.chmod(0o755)
for role,sha in refs.items():
    snapshot(sha)
    manifest=src/'Cargo.toml'
    original=manifest.read_text()
    match=re.search(r'(?m)^version = "([^"\n]+)"',original)
    assert match and original.count(match.group())==1
    manifest.write_text(original[:match.start(1)]+case_spec['version']+original[match.end(1):])
    dest=w/(role+'-relink')
    ids=w/(role+'.ids')
    opts={'RUSTC_WRAPPER':str(wrap),'CARGO_TARGET_DIR':str(w/('target-'+role)),
          'HEX_REAL_CC':shutil.which('cc'),'HEX_ORDER_LINKER':str(linker),
          'HEX_ORDER_OUTPUT':str(dest),'HEX_CRATE_IDS':str(ids),
          'HEX_SAMPLED_ADDRS':json.dumps(spec['active'][key][role])}
    if role=='base':
        shutil.copytree(src/'benches',w/'driver')
        run(['cargo','generate-lockfile'],src,opts)
        lock=(src/'Cargo.lock').read_bytes()
        assert digest(lock)==spec['locks'][key]
    else:
        shutil.rmtree(src/'benches');shutil.copytree(w/'driver',src/'benches')
        (src/'Cargo.lock').write_bytes(lock)
    compile_cmd=['cargo','bench','--locked','--no-run','--bench','hex','--bench','serde','--message-format=json']
    try:
        built=run(compile_cmd,src,opts)
    except sp.CalledProcessError as err:
        for line in err.output.splitlines():
            value=json.loads(line)
            if value.get('reason')=='compiler-message' and value['message'].get('level')=='error':
                msg=value['message']
                notes=[c.get('message','') for c in msg.get('children',[])]
                diag='\n'.join([msg['message'],*notes])
                (out/(role+'-link-error.txt')).write_text(diag[-16000:])
                print(diag[-2600:],flush=True)
        raise
    hits=[x for x in map(json.loads,built.splitlines()) if x.get('reason')=='compiler-artifact' and x.get('executable') and x['target']['name']=='hex' and x['target']['kind']==['bench']]
    assert len(hits)==1 and machine(Path(hits[0]['executable']))['text']==machine(dest/'native')['text']
    assert (src/'Cargo.lock').read_bytes()==lock
    identities[role]=sorted(json.loads(line) for line in ids.read_text().splitlines())
    assert len(identities[role])==2
    selected[role]=readj(dest/'selection.json')
    for variant in ('native','placed'):
        label=role if variant=='native' else role+'_placed'
        im=w/(label+'-hex');shutil.copy2(dest/variant,im);images[label]=im
        metadata[label]=machine(im)
    checks[role]=metadata[role]['text']==spec['anchor'][key][role]
    save('images.json',metadata);save('selected-positions.json',selected);save('original-anchors.json',checks);save('package-ids.json',identities)
    print(role,checks[role],[(n,hex(v['native']),hex(v['placed'])) for n,v in selected[role]['symbols'].items()],flush=True)
assert identities['base']==identities['head'] and all(checks.values()),(identities,checks)
roots=selected['base']['symbols'];changes=selected['head']['symbols']
matches={f:roots[f]['placed']==changes[f]['placed'] for f in roots}
save('address-matches.json',matches)
assert all(matches.values()) and all(roots[f]['placed']!=roots[f]['native'] for f in roots),matches
save('environment.json',{'cpu':run(['sysctl','-n','machdep.cpu.brand_string']),'rustc':run(['rustc','-Vv']),'lock':digest(lock),'cases':cases,'sources':refs})
# Reuse the exact sampled/timed benchmark mechanism of the previous native run.
measurement=(repo/'verify/layout-probe.py').read_text()
begin=measurement.index('if is_mac:\n for role,im in images.items():')
import time
is_mac=True
exec(compile(measurement[begin:],str(repo/'verify/layout-probe.py'),'exec'))
