from pathlib import Path
import bisect, collections, json, os, re, shutil, subprocess, sys
root=Path.cwd()
work=Path(os.environ.get('STUDY_WORK','consumer-work')).resolve()
out=Path(os.environ.get('RESULTS','results')).resolve()
out.mkdir(parents=True,exist_ok=True)
lib=work/'caller-sample.so'
subprocess.run(['cc','-O2','-shared','-fPIC','-o',lib,root/'verify/sample_caller.c','-ldl'],check=True)
result={}
cpu=str(min(os.sched_getaffinity(0)))
for kind in ['mixed','escapedmixed','serialize']:
 for label in ['base','head']:
  exe=work/label/kind; report=work/'distribution.txt'
  env=dict(os.environ,LD_PRELOAD=str(lib),COUNTS_FILE=str(report))
  ns=float(subprocess.check_output(['taskset','-c',cpu,exe,'4096','900000'],env=env,text=True))
  addrs={};counts=collections.Counter(); pcs=collections.defaultdict(list)
  for line in subprocess.check_output(['nm','-n','-C','--defined-only',exe],text=True).splitlines():
   m=re.match(r'([0-9a-f]+) [tTwW] (.+)$',line)
   if m:addrs[int(m[1],16)]=m[2]
  starts=sorted(addrs)
  for line in report.read_text().splitlines():
   a,num=line.split();num=int(num)
   if a=='outside':
    counts['shared libraries and kernel']+=num;continue
   n=int(a,16);at=bisect.bisect_right(starts,n)-1
   if at<0:continue
   fn=addrs[starts[at]]
   counts[fn]+=num;pcs[fn].append((num,n))
  total=sum(counts.values());details=[]
  for fn,count in counts.most_common(7):
   desc={'function':fn,'ns':round(ns*count/total,1)}
   dis=[]
   for score,pc in sorted(pcs[fn],reverse=True)[:3]:
    ins=subprocess.check_output(['objdump','-dC','--start-address='+str(max(0,pc-20)),'--stop-address='+str(pc+24),exe],text=True)
    dis.append({'ticks':score,'pc':hex(pc),'instructions':ins.split('>:\n')[-1].strip()})
   desc['samples']=dis;details.append(desc)
  result[label+'/'+kind]={'ns':ns,'total':total,'top':details}
  print(label,kind,round(ns,1),[(d['function'][:180],d['ns']) for d in details[:5]],flush=True)
(out/'profile.json').write_text(json.dumps(result,indent=2))
