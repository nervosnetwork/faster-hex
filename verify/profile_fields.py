"""Sample the same unmodified field executables used for ordinary timings."""
from pathlib import Path
import bisect, collections, json, os, subprocess as sp

root=Path.cwd(); work=(root/'consumer-work'); out=root/'results'
lib=work/'field-sample.so'
sp.run(['cc','-O2','-shared','-fPIC','-o',lib,root/'verify/sample_caller.c','-ldl'],check=True)
cpu=str(min(os.sched_getaffinity(0))); rows={}
for role in ['base','head']:
 for case in ['array','array_ref','borrowed','borrowed_ref','transient','transient_ref']:
  exe=work/role/case; report=work/'field-samples.txt'
  symbols={}
  for line in sp.check_output(['nm','-n','-C','--defined-only',exe],text=True).splitlines():
   fields=line.split(maxsplit=2)
   if len(fields)==3 and fields[1] in ['t','T','W','w']:
    symbols[int(fields[0],16)]=fields[2]
  addresses=sorted(symbols)
  env=dict(os.environ,LD_PRELOAD=str(lib),COUNTS_FILE=str(report))
  ns=float(sp.check_output(['taskset','-c',cpu,exe,'4096','1500000'],env=env,text=True))
  ticks=collections.Counter()
  for line in report.read_text().splitlines():
   ip,n=line.split(); n=int(n)
   if ip=='outside': name='outside executable'
   else:
    i=bisect.bisect_right(addresses,int(ip,16))-1
    name=symbols[addresses[i]] if i>=0 else 'unresolved'
   ticks[name]+=n
  total=sum(ticks.values())
  rows[role+'/'+case]={'ns':ns,'ticks':total,'time':{k:round(ns*v/total,2) for k,v in ticks.most_common(8)}}
(out/'field-profile.json').write_text(json.dumps(rows,indent=2))
for name,row in rows.items():
  print(name,round(row['ns'],1),list(row['time'].items())[:4],flush=True)
