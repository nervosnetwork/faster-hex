"""Attribute native changes to fixed milestones of the public PR."""
import hashlib
import json
import os
from pathlib import Path
import random
import re
import statistics
import subprocess as sp
import sys

v=Path(__file__).resolve().parent
root=v.parent
sys.path.insert(0,str(v))
from cause_common import compare, measure, pin, section
import isolated_cases as scope
spec=json.loads((v/'pr_history_inputs.json').read_text())
revisions=spec['revisions']
chain=['version','early','prefix','core','scoped','bounds','pr']
roles=['release',*chain]
key=os.environ['HOST_KEY']
profile=os.environ['PROFILE']
if 'arm' in key:
    fixed=[('qualified_decode',4096,'valid'),('ckb_caller',32,'plain'),('full_format',4096,'display')]
    fixed.extend((op,n,kind) for op in ['vec_read_slice','vec_round_slice'] for n in (32,4096) for kind in ('plain','escaped'))
    fixed.append(('vec_write',4096,'plain'))
else:
    fixed=[('qualified_decode',n,'valid') for n in (32,4096)]
assert len(set(fixed))==len(fixed)
scope.revisions={r:revisions[r]['package'] for r in roles}
scope.cases=list(fixed)
scope.pairs=[]
source=v/'isolate_callers.py'
driver,sep,_=source.read_text().partition('\npin();rng=')
assert sep
old="    if SCOPE in ('fmt-join','fmt-field','prefix-length','release-audit','prefix-kernel-exchange','prefix-operation') and role in ('release','version'):"
assert driver.count(old)==1
# These historical calls predate prefix formatting. The probe isn't built.
driver=driver.replace(old,old[:-1]+" and 'gix_prefix' in bins:")
exec(compile(driver,str(source),'exec'),{'__name__':'__main__','__file__':str(source)})
work=root/'real'
out=work/'qualification'/profile
read=lambda f:json.loads(f.read_text())
def save(p,x):p.write_text(json.dumps(x,indent=2))
records=read(out.parent/'archives.json')
assert {x['role']:x['sha'] for x in records}==scope.revisions
assert next(x for x in records if x['role']=='release')['checksum']=='e4ede54fe330383a5de28c0a1f06668ff9dbf06c8094e1c5150c39488a5e911d'
actual=read(out/'sections.json')
frozen=spec['anchors'][key]
bins=sorted({item[0] for item in fixed})
anchors={role+'/'+op:actual[role+'/'+op]==frozen[role+'/'+op] for role in ('release','version','pr') for op in bins}
save(out/'anchor-check.json',anchors)
assert all(anchors.values()),('original native caller changed',[k for k,x in anchors.items() if not x])
fingerprints={r+'/'+op:{s:section(out/(r+'-'+op),s) for s in ('.text','.rodata')} for r in roles for op in bins}
save(out/'fingerprints.json',fingerprints)
# Capture only the normal checked decode path of the native caller, so an
# apparent change can be checked against the emitted instructions and addresses.
if 'arm' not in key:
    symbols={}
    for r in roles:
        p=out/(r+'-qualified_decode')
        nm=sp.check_output(['nm','-S','--defined-only','-C',p],text=True).splitlines()
        symbols[r]=[]
        for line in nm:
            entry=re.match(r'^([0-9a-f]+) ([0-9a-f]+) [tT] (.+)$',line)
            if not entry:continue
            a,n,label=entry.groups();a=int(a,16);n=int(n,16)
            if label!='run_sample' and not any(t in label for t in ('hex_decode_avx2_checked','hex_decode_sse41_checked','hex_decode_avx512_checked','vectorization_support','decode_diagnosed')):continue
            listing=sp.check_output(['objdump','-d','-w','-C','--start-address='+str(a),'--stop-address='+str(a+n),p],text=True)
            symbols[r].append(dict(symbol=label,address=a,size=n,disassembly=listing))
        assert any(l['symbol']=='run_sample' for l in symbols[r])
    save(out/'native-decoder.json',symbols)
pin()
contrast=list(dict.fromkeys([('release','version'),('release','pr'),('version','pr'),*zip(chain,chain[1:]),*((r,'pr') for r in chain[1:-1])]))
# Each role has a direct same-file control. Replication starts from a separate
# ordering after every case in the previous trial has completed.
for trial,seed in enumerate((2729173,1929671),1):
    rng=random.Random(seed)
    sequence=list(fixed);rng.shuffle(sequence)
    all_samples={};summary={}
    for op,n,k in sequence:
        def sample(name,count):
            cmd=[n,k,count] if op=='ckb_caller' else [n,count,k]
            return measure(out/'fixed-program',out/(name.removesuffix('_control')+'-'+op),cmd,work/'caller')
        count=max(200,min(5000000,round(12000000/max(1,sample('pr',3000)))))
        times=[]
        for _ in range(32):
            order=[name for r in roles for name in (r,r+'_control')]
            rng.shuffle(order);vals={r:[] for r in order}
            for r in order+order[::-1]:vals[r].append(sample(r,count))
            times.append({r:statistics.mean(vs) for r,vs in vals.items()})
        case=f'{op}/{n}/{k}'
        all_samples[case]=times
        summary[case]={b+'/'+c:compare(times,b,c) for b,c in [*contrast,*((r,r+'_control') for r in roles)]}
        print('completed',key,trial,case,flush=True)
        save(out/f'trial-{trial}-samples.json',all_samples)
        save(out/f'trial-{trial}-times.json',summary)
