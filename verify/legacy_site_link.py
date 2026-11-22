#!/usr/bin/env python3
"""Relink the exact owned-array/Vec caller with its cold recovery at controlled positions."""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess as sp
import sys
from pathlib import Path

cc=os.environ['LEGACY_REAL_CC']
args=sys.argv[1:]
flat=[s for a in args for s in (shlex.split(Path(a[1:]).read_text()) if a.startswith('@') else [a])]
if '-o' not in flat or not Path(flat[flat.index('-o')+1]).name.startswith('owned_blocks-'):
    os.execv(cc,[cc,*args])
exe=Path(flat[flat.index('-o')+1])
out=Path(os.environ['LEGACY_WORK'])
out.mkdir(parents=True,exist_ok=True)
def cmd(*argv):
    return sp.check_output(list(argv),text=True)
def sites(path):
    symbols=[]
    target='faster_hex::decode::decode_diagnosed'
    for line in cmd('nm','-anS','-C','--defined-only',path).splitlines():
        m=re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) ([a-zA-Z]) (.+)',line)
        if m:
            symbols.append((int(m[1],16),int(m[2],16),m[3],m[4]))
    ws=[(a,n) for a,n,ty,name in symbols if name==target]
    if len(ws)!=1:
        raise ValueError(('missing unique cold routine',ws))
    start,length=ws[0]
    seen=cmd('objdump','-d','-C','--start-address='+str(start),'--stop-address='+str(start+length),path)
    insns=[]
    for line in seen.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)',line)
        if m:
            insns.append([int(m[1],16)-start,m[2],m[3]])
    assert insns
    tables={name:[a,n] for a,n,t,name in symbols if re.fullmatch(r'faster_hex::decode::UNHEX(?:_UPPER|_LOWER|4)?',name)}
    callers=sorted((name,a,n) for a,n,t,name in symbols if name.startswith('owned_blocks::') and t in 'tT')
    headers=re.findall(r'^\s*\d+\s+(\.\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)',cmd('objdump','-h',path),re.M)
    return {'routine':[start,length], 'callers':callers, 'tables':tables, 'instructions':insns,
            'sections':{name:[int(a,16),int(n,16)] for name,n,a in headers if name in ('.text','.rodata','.data.rel.ro','.got','.plt')}}
sp.run([cc,*args,'-Wl,-Map,'+str(out/'native.map')],check=True)
shutil.copy2(exe,out/'native')
try:
    native=sites(exe)
    (out/'native-summary.json').write_text(json.dumps(native))
    records={'native':native}
    start,size=native['routine']
    matches=re.findall(r'^ (\.text\.\S*decode_diagnosed\S*)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)',(out/'native.map').read_text(),re.M)
    sections=[name for name,a,n in matches if int(a,16)==start and int(n,16)>=size]
    assert len(sections)==1, (native['routine'],matches)
    base=json.loads((out.parent/'release/native-summary.json').read_text())['routine'][0] % 4096
    for label,offset in [('matching',base),('plus4',(base+4)%4096),('plus32',(base+32)%4096)]:
        script=out/(label+'.ld')
        script.write_text('SECTIONS { .diagnostic_probe ALIGN(4096) : { . = '+str(offset)+'; KEEP(*('+sections[0]+')) . = 8192; } } INSERT BEFORE .text;\n')
        sp.run([cc,*args,'-Wl,-T,'+str(script)],check=True)
        shutil.copy2(exe,out/label)
        records[label]=sites(exe)
        assert records[label]['routine'][0]%4096==offset
    for variant in ('plus4','plus32'):
        for key in ('callers','tables','sections'):
            assert records[variant][key]==records['matching'][key], (variant,key)
    (out/'positions.json').write_text(json.dumps(records))
except (AssertionError,ValueError,FileNotFoundError,sp.CalledProcessError) as err:
    (out/'capture-error.txt').write_text(repr(err))
finally:
    sp.run([cc,*args],check=True)
    assert hashlib.sha256(exe.read_bytes()).digest()==hashlib.sha256((out/'native').read_bytes()).digest()
