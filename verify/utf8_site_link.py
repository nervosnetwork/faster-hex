#!/usr/bin/env python3
import json,os,re,shlex,shutil,subprocess as sp,sys
from pathlib import Path

args=sys.argv[1:];cc=os.environ['ORIGINAL_CC']
flat=[x for a in args for x in (shlex.split(Path(a[1:]).read_text()) if a.startswith('@') else [a])]
if '-o' not in flat or not Path(flat[flat.index('-o')+1]).name.startswith('vec_round_slice-'):
    os.execv(cc,[cc,*args])
dest=Path(flat[flat.index('-o')+1]);out=Path(os.environ['PLACEMENT_DIR']);out.mkdir(parents=True,exist_ok=True)
def syms(img):
    return {k:int(a,16) for a,k in re.findall(r'^([0-9a-f]+) [0-9a-f]+ [tT] (core::str::converts::from_utf8|vec_round_slice::measure|serde_json::ser::format_escaped_str)$',sp.check_output(['nm','-nS','-C',img],text=True),re.M)}
sp.run([cc,*args,'-Wl,-Map,'+str(out/'native.map')],check=True)
shutil.copy2(dest,out/'native')
native=syms(dest)
assert set(native)=={'core::str::converts::from_utf8','vec_round_slice::measure','serde_json::ser::format_escaped_str'},native
m=re.findall(r'^ (\.text\.\S*converts9from_utf8)\s+0x[0-9a-f]+\s+0x([0-9a-f]+)',(out/'native.map').read_text(),re.M)
assert len(m)==1 and int(m[0][1],16)<1024,m
data={'native':native}
for offset in (0x068,0xf64,0x064):
    script=out/('utf8-'+str(offset)+'.ld')
    script.write_text('SECTIONS { .utf8_probe ALIGN(4096) : { . = '+str(offset)+'; KEEP(*('+m[0][0]+')) . = 8192; } } INSERT BEFORE .text;\n')
    sp.run([cc,*args,'-Wl,-T,'+str(script)],check=True)
    name=f'at-{offset:03x}';shutil.copy2(dest,out/name);s=syms(dest);data[name]=s
    assert s['core::str::converts::from_utf8']%4096==offset,s
assert len({s['vec_round_slice::measure'] for r,s in data.items() if r!='native'})==1
assert len({s['serde_json::ser::format_escaped_str'] for r,s in data.items() if r!='native'})==1
(out/'site.json').write_text(json.dumps(data,indent=2))
sp.run([cc,*args],check=True)
assert dest.read_bytes()==(out/'native').read_bytes()
