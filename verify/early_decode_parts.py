"""Attribute the original decode change and qualify the distinct public Vec change."""
from pathlib import Path
import json,os,random,statistics,sys

v=Path(__file__).resolve().parent;sys.path.insert(0,str(v))
from cause_common import measure,pin,save
spec=json.loads((v/'early_decode_inputs.json').read_text())
fixed=[(ty+'_'+op,n,k) for ty in ('array','vec') for n in (32,4096)
       for op,k in [('read_slice','plain'),('read_slice','escaped'),('read_reader','reader'),('round_slice','plain'),('round_slice','escaped'),('round_reader','reader'),('write','plain')]]
fixed += [('ckb_caller',32,'plain'),('qualified_decode',4096,'valid'),('full_format',4096,'display')]
assert len(fixed)==31 and len(set(fixed))==31
shared=v/'pr_components.py'
code,sep,_=shared.read_text().partition('\npin()\n');assert sep
code=code.replace("v/'pr_component_inputs.json'","v/'early_decode_inputs.json'")
a=code.index("fixed=[('qualified_decode'");b=code.index('scope.revisions=',a)
code=code[:a]+'fixed=list(all_cases)\n'+code[b:]
ns={'__file__':str(shared),'__name__':'__main__','all_cases':fixed}
exec(compile(code,str(shared),'exec'),ns)
work,out,classes=ns['work'],ns['out'],ns['classes']
fingerprints,refs,key=ns['fingerprints'],ns['refs'],ns['key']
more={k:fingerprints[k]['.text']==val for k,val in spec['release_sections'][key].items()}
save(out/'full-text-anchor-check.json',more)
assert all(more.values()),[k for k,x in more.items() if not x]
def attribution(op,n,k):
    return op in ('ckb_caller','qualified_decode','full_format') or op in ('vec_read_slice','vec_round_slice') and (n==32 or op=='vec_round_slice') or op=='vec_write' and n==4096
pin()
for trial,seed in enumerate((792401,1367791),1):
    seq=list(fixed);rng=random.Random(seed);rng.shuffle(seq);results={}
    for op,n,k in seq:
        requested=list(refs) if attribution(op,n,k) else ['release','version','pr','own_vec']
        roles=list(dict.fromkeys(classes[op][i] for i in requested))
        def sample(role,count):
            binary=out/(role.removesuffix('_control')+'-'+op)
            args=[n,k,count] if op=='ckb_caller' else [n,count,k]
            return measure(out/'fixed-program',binary,args,work/'caller')
        count=max(200,min(5000000,round(8000000/max(1,sample('pr',3000)))))
        rows=[]
        for _ in range(32):
            order=[q for role in roles for q in (role,role+'_control')];rng.shuffle(order)
            times={q:[] for q in order}
            for q in order+order[::-1]:times[q].append(sample(q,count))
            rows.append({q:statistics.mean(xs) for q,xs in times.items()})
        case=f'{op}/{n}/{k}';results[case]=rows
        save(out/f'trial-{trial}-samples.json',results)
        print(key,trial,case,flush=True)
