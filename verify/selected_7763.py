from pathlib import Path
import json,re,sys
v=Path(__file__).resolve().parent;sys.path.insert(0,str(v))
from cross_file_copies import crossover
shared=v/'pr_components.py'
source,sep,_=shared.read_text().partition('\npin()\n');assert sep
source=source.replace("v/'pr_component_inputs.json'","v/'selected_7763_inputs.json'")
ns={'__name__':'__main__','__file__':str(shared)}
exec(compile(source,str(shared),'exec'),ns)
out,work=ns['out'],ns['work'];op='qualified_decode'
cpu=json.loads((out/'host.json').read_text())['cpu']
assert re.search(r'^Model name:\s*AMD EPYC 7763 64-Core Processor\s*$',cpu,re.M)
assert all(ns['checks'].values())
for other in ('pr','released_decode','append_grouped'):
    crossover([out/('release-'+op),out/(other+'-'+op)],out/'fixed-program',work/'caller',out/('release-vs-'+other),[(32,'valid'),(4096,'valid')])
