from pathlib import Path
import difflib
import json
import os
import random
import re
import shutil
import statistics
import struct
import subprocess as sp
import sys
from cause_common import ROOT, compare, measure, pin, save

work=ROOT/'real'
driver=work/'caller'
script=ROOT/'verify/isolate_callers.py'
s=script.read_text()
a="for role,ref in revisions.items():"
s=s.replace(a,"revisions={'release':RELEASE,'version':'f83d1075a7945c2dfe56ee7b94d9b6b1783cdf93','owned':'b6967d9c519b1a0c3e47ea435f678b2b2d601058','fixed':'cc708c2c0bf91275ad2685b71b5d4ee254b78d49'}\n"+a)
s=s.replace("bins=sorted({b for b,_,_ in cases})","bins=['vec_round_slice']")
s=s[:s.index("pin();rng=random.Random")]
s=s.replace("if SCOPE=='surface':\n        if role", "if False:\n        if role")
os.environ['ISOLATE']='surface'
exec(compile(s,str(script),'exec'),{'__name__':'__main__'})
profile=os.environ.get('CARGO_PROFILE_RELEASE_LTO','default')
base=work/'qualification'/profile
report=work/'attribution';report.mkdir(exist_ok=True)
roles=['release','version','fixed','owned']
images={r:base/(r+'-vec_round_slice') for r in roles}
def contents(path):
    raw=path.read_bytes();off,=struct.unpack_from('<Q',raw,40);step,count,idx=struct.unpack_from('<HHH',raw,58)
    rows=[struct.unpack_from('<IIQQQQIIQQ',raw,off+i*step) for i in range(count)]
    names=raw[rows[idx][4]:rows[idx][4]+rows[idx][5]]
    return {names[row[0]:].split(b'\0',1)[0].decode():(row[3],raw[row[4]:row[4]+row[5]]) for row in rows if row[1] in (1,4,6,7)}
def symbols(path):
    syms={}
    for line in sp.check_output(['nm','-nS','-C','--defined-only',str(path)],text=True).splitlines():
        m=re.match(r'([a-fA-F0-9]+) ([a-fA-F0-9]+) ([tTWw]) (.*)',line)
        if m:syms[int(m[1],16)]=(int(m[2],16),m[4])
    return syms
def summarize(left,right):
    tables={r:contents(images[r]) for r in (left,right)}
    syms=[symbols(images[r]) for r in (left,right)]
    sections={k:[len(y[1]),len(tables[right][k][1]),sum(a!=b for a,b in zip(y[1],tables[right][k][1])),y[0],tables[right][k][0]] for k,y in tables[left].items() if k in tables[right] and k in ('.text','.rodata','.data.rel.ro','.data','.got','.plt','.eh_frame','.rela.dyn')}
    changed=[]; same=[]; special={}
    for addr,(sz,name) in syms[0].items():
        if addr not in syms[1] or syms[1][addr]!=(sz,name): continue
        chunks=[]
        for r in (left,right):
            start,body=tables[r]['.text'];chunks.append(body[addr-start:addr-start+sz])
        if len(chunks[0])!=sz or len(chunks[1])!=sz:continue
        diffs=[addr+i for i,(a,b) in enumerate(zip(*chunks)) if a!=b]
        if diffs:changed.append([name,addr,sz,len(diffs)])
        else:same.append([name,addr,sz])
        if ('vec_round_slice::measure' in name or 'faster_hex::' in name or 'format_escaped_str' in name or 'serde_json::read::' in name or '::parse_str' in name) and diffs:
            dumps=[]
            for r in (left,right):
                lines=sp.check_output(['objdump','-d','-C','--no-show-raw-insn','--start-address='+str(addr),'--stop-address='+str(addr+sz),str(images[r])],text=True).splitlines()
                dumps.append([line+'\n' for line in lines if re.match(r'^\s*[a-f0-9]+:',line)])
            special[name]=''.join(difflib.unified_diff(*dumps,fromfile=left,tofile=right,n=2))
    save(report/(left+'-'+right+'-functions.json'),{'sections':sections,'matched_symbols':len(same)+len(changed),'different_body':changed,'identical_body':same})
    save(report/(left+'-'+right+'-instructions.json'),special)
for left,right in [('release','version'),('version','fixed'),('version','owned')]: summarize(left,right)
# Independently copied executables separate a package effect from physical pages assigned to one file.
original=images.copy()
for role,path in original.items():
    for i in (1,2):
        dest=base/(role+'-copy'+str(i));shutil.copyfile(path,dest);dest.chmod(0o755);assert path.read_bytes()==dest.read_bytes();images[role+str(i)]=dest
pin();rng=random.Random(89314)
for n in (32,4096):
    rows=[]
    def sample(img,count):return measure(base/'same-program',images[img],[n,count,'plain'],driver)
    count=max(1000,min(1000000,round(33000000/sample('release',4000))))
    for i in range(36):
        order=list(images);rng.shuffle(order);groups={r:[] for r in order}
        for role in order+order[::-1]:groups[role].append(sample(role,count))
        row={r:statistics.mean(s) for r,s in groups.items()}
        for r in original:row[r+'-copies']=statistics.median(row[x] for x in (r,r+'1',r+'2'))
        rows.append(row)
    pairs=[('release-copies','version-copies'),('release-copies','fixed-copies'),('version-copies','fixed-copies'),('version-copies','owned-copies')]+[(r,r+str(i)) for r in original for i in (1,2)]+[('release'+str(i),'version'+str(i)) for i in (1,2)]+[('release','version')]
    save(report/(str(n)+'-times.json'),{a+'/'+b:compare(rows,a,b) for a,b in pairs})
    save(report/(str(n)+'-samples.json'),rows)
# When the host permits user-level sampling, collect the full process without instrumenting the measured loops.
for role in ('release','version','owned'):
    if not shutil.which('perf'):break
    data=report/(role+'.data')
    try:
        run=sp.run(['perf','record','-q','-F','397','-e','cycles:u','-o',str(data),'--',str(original[role]),'4096','700000','plain'],cwd=driver,capture_output=True,text=True,timeout=80)
        if run.returncode:
            (report/'perf-unavailable.txt').write_text(run.stderr);break
        output=sp.check_output(['perf','report','-i',str(data),'--stdio','-n','--no-children','--percent-limit','0.1'],text=True)
        (report/(role+'-perf.txt')).write_text(output)
    except (OSError,sp.SubprocessError) as e:(report/'perf-unavailable.txt').write_text(str(e));break
