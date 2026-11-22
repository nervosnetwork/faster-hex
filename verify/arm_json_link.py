#!/usr/bin/env python3
import json, os, re, shlex, shutil, subprocess as sp, sys
from pathlib import Path

args=sys.argv[1:]; cc=os.environ['JSON_REAL_CC']
flat=[x for arg in args for x in (shlex.split(Path(arg[1:]).read_text()) if arg.startswith('@') else [arg])]
if '-o' not in flat or not Path(flat[flat.index('-o')+1]).name.startswith('vec_round_slice-'):
 os.execv(cc,[cc,*args])
exe=Path(flat[flat.index('-o')+1])
out=Path(os.environ['JSON_LINK_WORK']);out.mkdir(parents=True,exist_ok=True)
sp.run([cc,*args,'-Wl,-Map,'+str(out/'native.map')],check=True)
shutil.copy2(exe,out/'native')
def stats(p):
 rows=sp.check_output(['objdump','-h',p],text=True)
 taken=re.findall(r'^\s*\d+\s+(\.\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)',rows,re.M)
 return {name:[int(addr,16),int(length,16)] for name,length,addr in taken}
results={'native':stats(exe)}
for padding in ((64,128) if os.environ.get('SHORT_JSON_LAYOUT')=='1' else (64,)):
 script=out/('diagnostic-'+str(padding)+'.ld')
 script.write_text('SECTIONS { .layout_diagnostic : { '+('QUAD(0); '*(padding//8))+' } } INSERT BEFORE .text;\n')
 sp.run([cc,*args,'-Wl,-T,'+str(script)],check=True)
 label='shift'+str(padding);shutil.copy2(exe,out/label)
 results[label]=stats(exe)
if os.environ.get('SHORT_JSON_LAYOUT')=='1':
 script=out/'data-only.ld'
 script.write_text('SECTIONS { .layout_diagnostic : { '+('QUAD(0); '*8)+' } } INSERT AFTER .text;\n')
 sp.run([cc,*args,'-Wl,-T,'+str(script)],check=True)
 shutil.copy2(exe,out/'after64')
 results['after64']=stats(exe)
sp.run([cc,*args],check=True)
assert exe.read_bytes()==(out/'native').read_bytes()
(out/'sections.json').write_text(json.dumps(results))
