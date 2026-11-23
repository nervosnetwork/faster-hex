from pathlib import Path
import json,os,sys
v=Path(__file__).resolve().parent;sys.path.insert(0,str(v))
from cross_file_copies import crossover
spec=json.loads((v/'registered_n2_inputs.json').read_text());host=os.environ['HOST_KEY']
fixed=[(ref.rsplit('/',1)[1],n,k) for ref,seq in spec['cases'][host].items() for n,k in seq]
shared=v/'pr_components.py';code,sep,_=shared.read_text().partition('\npin()\n');assert sep
code=code.replace("v/'pr_component_inputs.json'","v/'registered_n2_inputs.json'")
a=code.index("fixed=[('qualified_decode'");b=code.index('scope.revisions=',a)
code=code[:a]+'fixed=list(selected)\n'+code[b:]
ns={'__file__':str(shared),'__name__':'__main__','selected':fixed}
exec(compile(code,str(shared),'exec'),ns)
out,work=ns['out'],ns['work'];assert all(ns['checks'].values())
assert 'Neoverse-N2' in json.loads((out/'host.json').read_text())['cpu']
for ref,seq in spec['cases'][host].items():
    base,cand,op=ref.split('/')
    crossover([out/(base+'-'+op),out/(cand+'-'+op)],out/'fixed-program',work/'caller',out/(base+'-vs-'+cand+'-'+op),seq,count_last=op=='ckb_caller')
