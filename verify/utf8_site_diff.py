import json,os,random,shutil,statistics,subprocess as sp
from pathlib import Path
from cause_common import ROOT,compare,measure,pin,save,section
w=ROOT/'real';cwd=w/'caller';report=w/'utf8-result'; report.mkdir(exist_ok=True,parents=True)
script=ROOT/'verify/isolate_callers.py';s=script.read_text()
s=s.replace("for role,ref in revisions.items():","revisions={'release':RELEASE,'version':'f83d1075a7945c2dfe56ee7b94d9b6b1783cdf93'}\nfor role,ref in revisions.items():")
s=s.replace("bins=sorted({b for b,_,_ in cases})","bins=['vec_round_slice']")
s=s.replace("if SCOPE in ('surface','buffer','format'):\n        if role","if False:\n        if role")
s=s.replace('    cargo=["cargo",*config]', '    build_env["PLACEMENT_DIR"]=str(work/"utf8-binaries"/role)\n    cargo=["cargo",*config]')
s=s[:s.index('pin();rng=random.Random')]
wrap=w/'cc-wrapper';wrap.mkdir(exist_ok=True)
os.environ['ISOLATE']='surface';os.environ['ORIGINAL_CC']=shutil.which('cc')
shutil.copy2(ROOT/'verify/utf8_site_link.py',wrap/'cc');(wrap/'cc').chmod(0o755);os.environ['PATH']=str(wrap)+os.pathsep+os.environ['PATH']
exec(compile(s,str(script),'exec'),{'__name__':'__main__'})
images={};secs={};sites={}
for role in ('release','version'):
    loc=w/'utf8-binaries'/role; sites[role]=json.loads((loc/'site.json').read_text())
    for variant in sites[role]:
        label=role+'/'+variant;images[label]=loc/variant
        secs[label]={k:section(loc/variant,k)[:2] for k in ('.text','.rodata','.got','.data.rel.ro')}
    assert len({str(secs[role+'/'+part]) for part in sites[role] if part!='native'})==1
save(report/'sites.json',sites);save(report/'sections.json',secs)
pin();rng=random.Random(91333)
pairs=[(r+'/at-068',r+'/at-f64') for r in sites]+[(r+'/at-068',r+'/at-064') for r in sites]+[('release/'+v,'version/'+v) for v in sites['release']]+[('release/native','aa')]
for n in (32,4096):
    rows=[]
    def sample(role,count):return measure(w/'same-executable',images['release/native' if role=='aa' else role],[n,count,'plain'],cwd)
    count=max(400,min(2000000,round(27000000/sample('release/native',4000))))
    for _ in range(36):
        order=[*images,'aa'];rng.shuffle(order);groups={x:[] for x in order}
        for key in order+order[::-1]:groups[key].append(sample(key,count))
        rows.append({k:statistics.mean(v) for k,v in groups.items()})
    save(report/(str(n)+'-times.json'),{a+' vs '+b:compare(rows,a,b) for a,b in pairs});save(report/(str(n)+'-samples.json'),rows)
# Record only our own benchmark process, without changing any host setting.
if shutil.which('perf') and shutil.which('sudo'):
    cp=next(iter(os.sched_getaffinity(0)))
    for r in ('release','version'):
        data=w/(r+'.perf');cmd=['sudo','-n','perf','record','-q','-F','997','-e','cycles:u','-o',str(data),'--','taskset','-c',str(cp),str(images[r+'/native']),'4096','2400000','plain']
        res=sp.run(cmd,capture_output=True,text=True,timeout=100)
        if res.returncode:
            (report/'profiling.txt').write_text(res.stderr);break
        text=sp.check_output(['sudo','-n','perf','report','-i',str(data),'--stdio','--no-children','-n','--percent-limit','0.1'],text=True)
        (report/(r+'-cycles.txt')).write_text(text)
