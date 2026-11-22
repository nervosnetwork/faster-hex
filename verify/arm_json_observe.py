from pathlib import Path
import json, os, random, shutil, statistics, subprocess as sp
from cause_common import ROOT, compare, measure, pin, save
work=ROOT/'real'
driver=work/'caller'
base=ROOT/'verify/packaged_calls.py'
s=base.read_text().replace('c2858276c1485881c1da8854c5fe1741d9df7cd9','a6f1c464b2390d2aa82ed062389ffe100fd08ff9')
s=s.replace('bins=sorted({b for b,_,_ in cases})','cases=[("vec_round_slice",n,"plain") for n in (32,4096)]\nbins=["vec_round_slice"]')
s=s.replace('build_env=dict(os.environ', 'build_env=dict(os.environ')
s=s.replace('    cargo=["cargo",*config]', '    build_env["JSON_LINK_WORK"]=str(work/"link-observe"/role)\n    cargo=["cargo",*config]')
s=s.replace('"--offline","--bins","--quiet"','"--offline","--bin","vec_round_slice","--quiet"')
s=s[:s.index('pin()\nrng=')]
wrap=work/'cc-probe';wrap.mkdir(exist_ok=True)
os.environ['JSON_REAL_CC']=shutil.which('cc')
shutil.copy2(ROOT/'verify/arm_json_link.py',wrap/'cc');(wrap/'cc').chmod(0o755)
os.environ['PATH']=str(wrap)+os.pathsep+os.environ['PATH']
exec(compile(s,str(base),'exec'),{'__name__':'__main__'})
links=work/'link-observe'; report=work/'json-report';report.mkdir(exist_ok=True)
images={};sections={}
for role in ('release','version','pr','prepared'):
 fold=links/role;sections[role]=json.loads((fold/'sections.json').read_text())
 shutil.copy2(fold/'native.map',report/(role+'-native.map'))
 for part in ('native','shift64'):
  img=fold/part
  if img.exists():
   images[role+'/'+part]=img
   records=sp.check_output(['nm','-nS','--demangle',str(img)],text=True)
   kept=[l for l in records.splitlines() if any(x in l for x in ['run_sample','vec_round_slice','_ZN15serde_json','serde_json::ser','write_escaped_str','faster_hex::decode'])]
   (report/(role+'-'+part+'-symbols.txt')).write_text('\n'.join(kept)+'\n')
save(report/'sections.json',sections)
save(report/'host.json',{'cpu':sp.check_output(['lscpu'],text=True)})
pin();rng=random.Random(1257184)
for n in [32,4096]:
 def run(name,count):return measure(links/'entry',images['version/native' if name=='aa' else name],[n,count,'plain'],driver)
 count=max(300,min(500000,round(16000000/max(1,run('version/native',7000)))))
 rows=[]
 for i in range(26):
  seq=[*images,'aa'];rng.shuffle(seq);pair={r:[] for r in seq}
  for role in seq+seq[::-1]:pair[role].append(run(role,count))
  rows.append({r:statistics.mean(x) for r,x in pair.items()})
 pairs=[('version/native','aa'),('release/native','version/native'),('version/native','prepared/native'),('release/native','prepared/native')]
 pairs += [(r+'/native',r+'/shift64') for r in ('release','version','prepared') if r+'/shift64' in images]
 if 'version/shift64' in images:pairs.append(('version/shift64','prepared/native'))
 save(report/(str(n)+'-samples.json'),rows)
 stats={a+' vs '+b:compare(rows,a,b) for a,b in pairs}
 save(report/(str(n)+'-times.json'),stats)
 print(n,{p:round(100*(v['ratio']-1),2) for p,v in stats.items()},flush=True)
