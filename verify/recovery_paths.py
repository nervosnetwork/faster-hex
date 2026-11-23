"""Controlled diagnosis in the original downstream binaries."""
from pathlib import Path
import json,os,random,statistics,sys
v=Path(__file__).resolve().parent;sys.path.insert(0,str(v))
from cause_common import measure,pin,save
from cross_file_copies import crossover
spec=json.loads((v/'recovery_paths_inputs.json').read_text())
fixed=[(ty+'_'+op,n,k) for ty in ('array','vec') for n in (32,4096)
       for op,k in [('read_slice','plain'),('read_slice','escaped'),('read_reader','reader'),('round_slice','plain'),('round_slice','escaped'),('round_reader','reader'),('write','plain')]]
fixed += [('ckb_caller',32,'plain'),('qualified_decode',4096,'valid'),('full_format',4096,'display')]
assert len(fixed)==31
shared=v/'pr_components.py'
code,sep,_=shared.read_text().partition('\npin()\n');assert sep
code=code.replace("v/'pr_component_inputs.json'","v/'recovery_paths_inputs.json'")
a=code.index("fixed=[('qualified_decode'");b=code.index('scope.revisions=',a)
code=code[:a]+'fixed=list(all_cases)\n'+code[b:]
ns={'__file__':str(shared),'__name__':'__main__','all_cases':fixed}
exec(compile(code,str(shared),'exec'),ns)
work,out,classes=ns['work'],ns['out'],ns['classes']
fingerprints,refs,key=ns['fingerprints'],ns['refs'],ns['key']
assert set(refs)==set(spec['refs'])
pin()
focus={'vec_round_slice/4096/plain','vec_round_slice/4096/escaped','vec_round_slice/32/plain','vec_read_slice/32/plain','array_write/4096/plain','vec_write/4096/plain','qualified_decode/4096/valid'}
for trial,seed in enumerate((530197,671353),1):
    rng=random.Random(seed);seq=list(fixed);rng.shuffle(seq);results={}
    for op,n,k in seq:
        case=f'{op}/{n}/{k}'
        req=list(refs) if case in focus else ['release','version','pr','old_recovery','block_error']
        roles=list(dict.fromkeys(classes[op][role] for role in req))
        def sample(role,count):
            image=out/(role.removesuffix('_control')+'-'+op)
            return measure(out/'fixed-program',image,[n,k,count] if op=='ckb_caller' else [n,count,k],work/'caller')
        count=max(200,min(5000000,round(7500000/max(1,sample('pr',3000)))))
        rows=[]
        for _ in range(32):
            seq2=[r for role in roles for r in (role,role+'_control')];rng.shuffle(seq2)
            times={r:[] for r in seq2}
            for role in seq2+seq2[::-1]:times[role].append(sample(role,count))
            rows.append({r:statistics.mean(xs) for r,xs in times.items()})
        results[case]=rows;save(out/f'trial-{trial}-samples.json',results)
        print(key,trial,case,flush=True)
# Independent files: both programs occupy each of 16 physical files in turn.
# Recheck the five fresh warnings as well as the former 9% ARM ThinLTO alert.
for op,n,k in spec['copy_checks'].get(key,[]):
    crossover([out/('release-'+op),out/('pr-'+op)],out/'fixed-program',work/'caller',
              out/('release-pr-'+op+'-'+str(n)+'-'+k),[(n,k)])
