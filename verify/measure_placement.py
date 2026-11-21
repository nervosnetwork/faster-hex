from pathlib import Path
import json, os, random, re, shutil, statistics, subprocess as sp
root=Path.cwd();work=Path(os.environ.get('STUDY_WORK','consumer-work')).resolve()
out=Path(os.environ.get('RESULTS','results')).resolve()
codec=work/'codec';driver=work/'downstream';cache=work/'target';ld=work/'align-json.ld'
base='25cfd8eb6a4cd8257a96fabaf73771cabcced4b4'; head=os.environ['PRODUCT_REV']
kinds=['mixed','escapedmixed']; offsets=[0,16,32,48]
env=dict(os.environ,CARGO_TARGET_DIR=str(cache),CARGO_PROFILE_RELEASE_LTO='thin')
bins={};placement={}
for role,rev in [('base',base),('head',head)]:
 sp.run(['git','archive','-o',work/'source.tar',rev],cwd=root,check=True)
 sp.run(['tar','-xf',work/'source.tar','-C',codec],check=True)
 sp.run(['cargo','clean','--release','-p','faster-hex','-p','consumer-timing'],cwd=driver,env=env,check=True)
 for offset in offsets:
  # Give the third-party JSON loop the same instruction address modulo 64 in each binary.
  ldfile=work/('json-'+str(offset)+'.ld')
  ldfile.write_text(f'SECTIONS {{ .json_scan ALIGN(4096) : {{ . += {offset}; KEEP(*(.text.*format_escaped_str17h*)) }} }} INSERT BEFORE .text;\n')
  for kind in kinds:
   sp.run(['cargo','rustc','--release','--bin',kind,'--','-C','link-arg=-Wl,-T,'+str(ldfile)],cwd=driver,env=env,check=True,stdout=sp.DEVNULL)
   dest=work/f'{kind}-{role}-{offset}';shutil.copy2(cache/'release'/kind,dest);key=(role,kind,offset);bins[key]=dest
   symbols=sp.check_output(['nm','-n','-C',dest],text=True).splitlines()
   vals=[int(x.split()[0],16) for x in symbols if x.endswith(' serde_json::ser::format_escaped_str')]
   assert len(vals)==1 and vals[0]%64==offset,(key,vals)
   placement['/'.join(map(str,key))]=hex(vals[0])
pairs={};cpu=str(min(os.sched_getaffinity(0)));rng=random.Random(373);jobs=[]
for off in offsets:
 for kind in kinds:
  for size in [256,4096]:
   for rep in range(16):
    jobs.append((off,kind,size,rep))
rng.shuffle(jobs)
def timed(bin,size):
 return float(sp.check_output(['taskset','-c',cpu,bin,str(size),str(4000 if size==4096 else 50000)],text=True))
for off,kind,size,rep in jobs:
 roles=['base','head'] if rep%2==0 else ['head','base']
 v={r:timed(bins[r,kind,off],size) for r in roles}
 pairs.setdefault(f'{off}/{kind}/{size}',[]).append([v['base'],v['head']])
summary={}
for k,rows in sorted(pairs.items()):
 ratios=[b/a for a,b in rows];boot=sorted(statistics.median(rng.choices(ratios,k=len(ratios))) for _ in range(5000))
 summary[k]=[statistics.median(a for a,_ in rows),statistics.median(b for _,b in rows),statistics.median(ratios),boot[125],boot[4874]]
(out/'placement.json').write_text(json.dumps(dict(placement=placement,summary=summary,pairs=pairs),indent=2))
print('Same alignment for the JSON escape loop on both sides, percent changes by size and placement:',{k:round(100*(v[2]-1),1) for k,v in summary.items()},flush=True)
