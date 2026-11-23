"""Separate three source changes and adjacent public commits in frozen callers."""
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import struct
import sys

v=Path(__file__).resolve().parent
sys.path.insert(0,str(v))
import isolated_cases as scope
from cause_common import measure, pin, save, section

def load_image(path):
    # Keep every bit of every loaded segment, including its address and access
    # permissions. Only the GNU build ID is masked; its value is not used by the caller.
    data=bytearray(path.read_bytes())
    assert data[:6]==b'\x7fELF\x02\x01'
    shoff=struct.unpack_from('<Q',data,40)[0]
    shsize,nsh,strings=struct.unpack_from('<HHH',data,58)
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*shsize) for i in range(nsh)]
    start,length=rows[strings][4:6]
    names=data[start:start+length]
    for name,typ,flags,vma,off,length,*_ in rows:
        if names[name:].split(b'\0',1)[0]==b'.note.gnu.build-id':
            n,d,t=struct.unpack_from('<III',data,off)
            assert t==3 and data[off+12:off+12+n]==b'GNU\0' and d>0
            off+=12+(n+3)//4*4
            data[off:off+d]=bytes(d)
    phoff=struct.unpack_from('<Q',data,32)[0]
    size,count=struct.unpack_from('<HH',data,54)
    result=[]
    for i in range(count):
        entry=struct.unpack_from('<IIQQQQQQ',data,phoff+i*size)
        typ,flags,off,vma,pma,length,mem,align=entry
        if typ==1: result.append([list(entry),hashlib.sha256(data[off:off+length]).hexdigest()])
    assert result
    return result

spec=json.loads((v/'pr_component_inputs.json').read_text())
refs=spec['refs']
key=os.environ['HOST_KEY']
profile=os.environ['PROFILE']
fixed=[('qualified_decode',n,'valid') for n in (32,4096)]
if 'arm' in key:
    fixed=[('qualified_decode',4096,'valid'),('ckb_caller',32,'plain'),('full_format',4096,'display')]
    fixed += [(op,n,kind) for op in ('vec_read_slice','vec_round_slice') for n in (32,4096) for kind in ('plain','escaped')]
    fixed.append(('vec_write',4096,'plain'))
scope.revisions=refs
scope.cases=list(fixed)
scope.pairs=[]
source=v/'isolate_callers.py'
driver,sep,_=source.read_text().partition('\npin();rng=')
assert sep
guard="    if SCOPE in ('fmt-join','fmt-field','prefix-length','release-audit','prefix-kernel-exchange','prefix-operation') and role in ('release','version'):"
assert driver.count(guard)==1
driver=driver.replace(guard,guard[:-1]+" and 'gix_prefix' in bins:")
exec(compile(driver,str(source),'exec'),{'__name__':'__main__','__file__':str(source)})
work=v.parent/'real'
out=work/'qualification'/profile
read=lambda p:json.loads(p.read_text())
archives=read(out.parent/'archives.json')
assert {a['role']:a['sha'] for a in archives}==refs
assert next(a['checksum'] for a in archives if a['role']=='release')=='e4ede54fe330383a5de28c0a1f06668ff9dbf06c8094e1c5150c39488a5e911d'
bins=sorted({op for op,_,_ in fixed})
fingerprints={r+'/'+op:{name:section(out/(r+'-'+op),name) for name in ('.text','.rodata')} for r in refs for op in bins}
save(out/'fingerprints.json',fingerprints)
checks={k:fingerprints[k]==expected for k,expected in spec['anchors'][key].items()}
save(out/'anchor-check.json',checks)
assert all(checks.values()),[k for k,x in checks.items() if not x]
images={role+'/'+op:load_image(out/(role+'-'+op)) for op in bins for role in refs}
save(out/'load-images.json',images)
classes={}
for op in bins:
    first={}
    classes[op]={}
    for role in refs:
        value=json.dumps(images[role+'/'+op])
        classes[op][role]=first.setdefault(value,role)
save(out/'classes.json',classes)
print('Unique loaded programs per caller',[(b,len(set(classes[b].values()))) for b in bins],flush=True)
pin()
for trial,seed in enumerate((119713,521303),1):
    rng=random.Random(seed)
    order=list(fixed);rng.shuffle(order)
    samples={}
    for op,n,kind in order:
        reps=list(dict.fromkeys(classes[op].values()))
        def sample(role,count):
            image=out/(role.removesuffix('_control')+'-'+op)
            args=[n,kind,count] if op=='ckb_caller' else [n,count,kind]
            return measure(out/'fixed-program',image,args,work/'caller')
        count=max(200,min(5000000,round(12000000/max(1,sample('pr',3000)))))
        pairings=[]
        for _ in range(32):
            roles=[r for p in reps for r in (p,p+'_control')]
            rng.shuffle(roles)
            values={r:[] for r in roles}
            for role in roles+roles[::-1]:
                values[role].append(sample(role,count))
            pairings.append({r:statistics.mean(val) for r,val in values.items()})
        case=f'{op}/{n}/{kind}'
        samples[case]=pairings
        save(out/f'trial-{trial}-samples.json',samples)
        print('Completed',key,trial,case,flush=True)
