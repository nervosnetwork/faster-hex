#!/usr/bin/env python3
"""Vary only the input sections holding the digit table and the case selector."""
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
key='faster_hex::decode::UNHEX'
def selector(data):
    ins={at:s for at,_,s in data['instructions']}
    assert 'ldr\tx10, [x10, x9, lsl #3]' in ins[20],ins[20]
    return int(re.search(r'x10, ([0-9a-f]+)',ins[12])[1],16)+int(re.search(r'#0x([0-9a-f]+)',ins[16])[1],16)
def confirm_switch(path, data):
    site=selector(data)
    labels=[key,'faster_hex::decode::UNHEX_LOWER','faster_hex::decode::UNHEX_UPPER']
    relocs={}
    for line in cmd('readelf','-Wr',path).splitlines():
        cols=line.split()
        if len(cols)>=4 and cols[2].endswith('_RELATIVE') and re.fullmatch(r'[0-9a-f]+',cols[0]):
            relocs[int(cols[0],16)]=int(cols[-1],16)
    assert [relocs[site+8*i] for i in range(3)]==[data['tables'][k][0] for k in labels]
    return site
try:
    native=sites(exe)
    native_switch=confirm_switch(exe,native)
    native['selector']=native_switch
    records={'native':native}
    (out/'native-summary.json').write_text(json.dumps(native))
    rows=[(n,int(a,16),int(z,16)) for n,a,z in re.findall(r'^ (\.\S+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)',(out/'native.map').read_text(),re.M)]
    digit,=[n for n,a,z in rows if n.startswith('.rodata.') and 'UNHEX' in n and (a,z)==tuple(native['tables'][key])]
    case_sections=[n for n,a,z in rows if n.startswith('.data.rel.ro') and a==native_switch and z==24]
    if len(case_sections)>1:
        raise ValueError(('ambiguous case table',case_sections))
    thin=os.environ.get('CARGO_PROFILE_RELEASE_LTO')=='thin'
    old_digit,new_digit,old_case,new_case=(0xce1,0xcd8,0xe68,0xe38) if thin else (0xbb5,0xb5c,0x930,0x900)
    if out.name=='release':
        assert (native['tables'][key][0]%4096,native_switch%4096)==(old_digit,old_case)
    if out.name=='scoped':
        assert (native['tables'][key][0]%4096,native_switch%4096)==(new_digit,new_case)
    variants={'rr':(old_digit,old_case),'cr':(new_digit,old_case),'aligned':(0,old_case)}
    if case_sections:
        variants.update({'rc':(old_digit,new_case),'cc':(new_digit,new_case)})
    for label,(offset,selected) in variants.items():
        script=out/(label+'.ld')
        inp='SECTIONS { .digit_probe ALIGN(4096) : { . = '+str(offset)+'; KEEP(*('+digit+')) . = 8192; } } INSERT BEFORE .rodata;\n'
        if case_sections:
            inp+='SECTIONS { .selector_probe ALIGN(4096) : { . = '+str(selected)+'; KEEP(*('+case_sections[0]+')) . = 8192; } } INSERT BEFORE .data.rel.ro;\n'
        script.write_text(inp)
        sp.run([cc,*args,'-Wl,-T,'+str(script)],check=True)
        shutil.copy2(exe,out/label)
        m=records[label]=sites(exe); m['selector']=confirm_switch(exe,m)
        assert m['tables'][key][0]%4096==offset
        if case_sections: assert m['selector']%4096==selected
        for attr in ('routine','callers'):
            assert m[attr]==native[attr],(label,attr)
    ref=records['rr']
    for name in variants:
        m=records[name]
        assert m['sections']==ref['sections']
        assert {k:v for k,v in m['tables'].items() if k!=key}=={k:v for k,v in ref['tables'].items() if k!=key}
    (out/'positions.json').write_text(json.dumps(records))
except (AssertionError,ValueError,KeyError,FileNotFoundError,sp.CalledProcessError) as err:
    (out/'capture-error.txt').write_text(repr(err))
finally:
    sp.run([cc,*args], check=True)
    assert exe.read_bytes()==(out/'native').read_bytes()
