"""Rebuild the measured Criterion programs, sample the active kernel, and vary only code placement."""
from pathlib import Path
import subprocess as sp,sys,json,re,os,shutil,random,statistics,math,tempfile,time
sibling=Path(__file__).parent/'official-paired.py';common=sibling.read_text().split('programs={};',1)[0];exec(compile(common,str(sibling),'exec'))
spec=json.loads((repo/'verify/layout-probe.json').read_text());cpu=platform.system();is_mac=cpu=='Darwin';cases=spec['cases'][key];reference=spec['anchors'][key];src_refs={'base':case_spec['base'],'head':case_spec['head']};map_path=w/'bench.map'
def g(*args):return run(['git',*args])
def info(file):return json.loads(file.read_text())
def controls(role):return role.split('_')[0]
ld_file=w/'owned.ld';ld_file.write_text('SECTIONS { .text_owned ALIGN(4096) : { *(.text.*hex_decode_neon_owned*) } } INSERT BEFORE .text;\n');wrap=w/'rust-compiler-wrapper';wrap.write_text('''#!/usr/bin/env python3
import sys,os,json
args=sys.argv[2:];mode=os.environ['HEX_LAYOUT_MODE'];mac=sys.platform=='darwin'
if '--crate-name' in args and any(a.startswith('--emit=') for a in args):
 name=args[args.index('--crate-name')+1];bench=any(a.endswith('benches/hex.rs') for a in args);data=[(a,args[i+1]) for i,a in enumerate(args[:-1]) if a=='-C' and args[i+1].startswith(('metadata=','extra-filename='))]
 if name=='faster_hex' or bench:
  with open(os.environ['HEX_RUST_IDS'],'a') as f:f.write(json.dumps([name,data])+'\\n')
 if mac and mode=='placed':args+=['-C','llvm-args=-x86-align-branch-boundary=32','-C','llvm-args=-x86-align-branch=jcc+fused']
 if bench:
  args+=['-C','link-arg=-Wl,'+('-map,' if mac else '-Map,')+os.environ['HEX_LINK_MAP']]
  if not mac and mode=='placed':args+=['-C','link-arg=-Wl,-T,'+os.environ['HEX_PLACEMENT_SCRIPT']]
os.execvp(sys.argv[1],[sys.argv[1],*args])
''');wrap.chmod(0o755)
images={};record={};runopts={};sections={};ids={};shas=[]
if hasattr(os,'sched_getaffinity'):available=sorted(os.sched_getaffinity(0))
roles=['base','head','base_placed','head_placed'];benches=['hex','serde'];args=sum((['--bench',n] for n in benches),[])
for role in roles:
 original=controls(role);mode='placed' if role.endswith('_placed') else 'default';revision=src_refs[original];snapshot(revision);manifest=src/'Cargo.toml';m=manifest.read_text();v=re.search(r'(?m)^version = "([^"\n]+)"',m);assert v;manifest.write_text(m[:v.start(1)]+case_spec['version']+m[v.end(1):]);target=w/('target-'+role);rid=w/(role+'.identities');rid.touch();opts={'CARGO_TARGET_DIR':str(target),'RUSTC_WRAPPER':str(wrap),'HEX_LAYOUT_MODE':mode,'HEX_LINK_MAP':str(map_path),'HEX_RUST_IDS':str(rid),'HEX_PLACEMENT_SCRIPT':str(ld_file)}
 if role=='base':
  shutil.copytree(src/'benches',w/'driver');run(['cargo','generate-lockfile'],src,opts);lock=(src/'Cargo.lock').read_bytes();assert digest(lock)==spec['locks'][key],digest(lock)
 else:
  shutil.rmtree(src/'benches');shutil.copytree(w/'driver',src/'benches');(src/'Cargo.lock').write_bytes(lock)
 inputs=run(['cargo','bench','--locked','--no-run',*args,'--message-format=json'],src,opts);bs=[j for j in map(json.loads,inputs.splitlines()) if j.get('reason')=='compiler-artifact' and j['target']['kind']==['bench'] and j['target']['name']=='hex' and j.get('executable')];assert len(bs)==1;im=w/(role+'-hex');shutil.copy2(bs[0]['executable'],im);images[role]=im;record[role]=machine(im);ids[role]=sorted([json.loads(l) for l in rid.read_text().splitlines()]);assert ids[role] and len(ids[role])==2,ids[role];assert all(ids[role]==other for other in ids.values()),ids;assert (src/'Cargo.lock').read_bytes()==lock
 print('built',role,record[role]['text'],flush=True);save('images.json',record);save('package-ids.json',ids)
 syms=[]
 for line in run(['nm','-n','-C',str(im)]).splitlines():
  m=re.match(r'^\s*([0-9A-Fa-f]+)\s+([tTwW])\s+(.+)$',line)
  if m:syms.append((int(m[1],16),m[3]))
 filtered=[];maps=[x for x in map_path.read_text(errors='replace').splitlines() if any(n in x for n in ('hex_decode_avx2_checked','hex_decode_neon_owned','hex_encode_avx2','hex_decode_avx2','hex_check_avx2'))];(out/(role+'-link-map.txt')).write_text('\n'.join(maps)+'\n')
 obj=['xcrun','llvm-objdump','--demangle','-d'] if is_mac else ['objdump','--demangle','-d'];programs=sorted(set(x[0] for x in syms));disasm=w/(role+'-listing');log=[]
 for addr,name in syms:
  if 'faster_hex::' not in name or not any(re.search(r'::'+n+r'(?:::h[0-9a-f]+)?$',name) for n in ('hex_decode_avx2_checked','hex_decode_avx2','hex_check_avx2_with_case','hex_encode_avx2','hex_decode_neon_owned','hex_decode_bounded_neon','hex_encode_neon')):continue
  following=next((n for n in programs if n>addr),addr+2048);end=min(following,addr+8192);listing=run([*obj,'--start-address='+hex(addr),'--stop-address='+hex(end),str(im)]);log.append(listing);filtered.append({'name':name,'addr':addr,'end':end,'line64':addr%64,'page':addr%4096})
 sections[role]=filtered;(out/(role+'-disassembly.txt')).write_text('\n'.join(log));save('selected-symbols.json',sections)
 if not is_mac and mode=='placed':
  owned=[s for s in filtered if '::hex_decode_neon_owned' in s['name']];assert len(owned)==1 and owned[0]['page']==0,owned
checks={k:reference[k]['text']==record[k]['text'] for k in ('base','head')};save('previous-text-matches.json',checks);print('previous text matches',checks,flush=True)
model=run(['sysctl','-n','machdep.cpu.brand_string']) if is_mac else run(['lscpu']);save('environment.json',{'cpu':model,'rustc':run(['rustc','-Vv']),'cases':cases,'source':src_refs,'lock':digest(lock),'flags':'x86-align-branch-boundary=32, jcc+fused' if is_mac else ld_file.read_text()})
if is_mac:
 for role,im in images.items():
  f=w/(role+'-sample');target=cases[0];flags=[str(im),'--bench','^'+re.escape(target)+'$','--profile-time','4','--warm-up-time','0.1','--noplot'];proc=sp.Popen(flags,cwd=src,env={**env,'CRITERION_HOME':str(w/'profile')},stdout=sp.DEVNULL,stderr=sp.DEVNULL)
  try:
   time.sleep(.65);res=sp.run(['/usr/bin/sample',str(proc.pid),'1','1','-file',str(f)],stdout=sp.PIPE,stderr=sp.STDOUT,text=True,timeout=12)
   if not f.exists() and proc.poll() is None:res=sp.run(['sudo','-n','/usr/bin/sample',str(proc.pid),'1','1','-file',str(f)],stdout=sp.PIPE,stderr=sp.STDOUT,text=True,timeout=12)
   if f.exists():
    seen=[a for a in f.read_text(errors='replace').splitlines() if ('faster_hex' in a or 'Bencher' in a or role+'-hex' in a or 'Image Load Address' in a) and len(a)<600];(out/(role+'-samples.txt')).write_text('\n'.join(seen[:400])+'\n')
   else:(out/(role+'-samples.txt')).write_text(res.stdout[:1000])
  finally:proc.wait(timeout=15)
else:os.sched_setaffinity(0,{available[0]})
rng=random.Random(116227);site=w/'measurement';seq=[0,1,7,2,6,3,5,4];labels=['base','head','base_placed','head_placed']*2;records={c:[] for c in cases}
for group in range(2):
 mutable=list(range(8));rng.shuffle(mutable);rows=list(range(8));rng.shuffle(rows);copies=[]
 for j,role in enumerate(labels):
  dest=w/f'copy-{group}-{j}';shutil.copy2(images[role],dest);copies.append(dest)
 for shift in rows:
  order=[mutable[(i+shift)%8] for i in seq];shuffled=list(cases);rng.shuffle(shuffled)
  for case in shuffled:
   timings={}
   for j in order:
    site.unlink(missing_ok=True);os.link(copies[j],site)
    with tempfile.TemporaryDirectory(dir=w) as tmp:
     p=sp.run([str(site),'--bench','^'+re.escape(case)+'$','--warm-up-time','0.12','--measurement-time','0.35','--sample-size','25','--nresamples','2000','--noplot'],cwd=src,env={**env,'CRITERION_HOME':tmp},stdout=sp.PIPE,stderr=sp.STDOUT,text=True);p.check_returncode();hits=list(Path(tmp).glob('**/new/estimates.json'));assert len(hits)==1 and readj(hits[0].parent/'benchmark.json')['full_id']==case;timings[j]=readj(hits[0])['mean']['point_estimate']
   records[case].append([timings[j] for j in range(8)])
  save('measurements.json',records)
 print('balanced eight-run block',group+1,flush=True)
def summary(vals):
 k=sum(v>1 for v in vals);n=len(vals);p=sum(math.comb(n,i) for i in range(k,n+1))/2**n;q=sum(math.comb(n,i) for i in range(n-k,n+1))/2**n
 return {'median':100*(statistics.median(vals)-1),'halves':[100*(statistics.median(s)-1) for s in (vals[:8],vals[8:])],'slow_p':p,'fast_p':q}
report={}
for c,rows in records.items():
 vectors=[[ (r[i]+r[i+4])/2 for i in range(4)] for r in rows];pairs={'original':(1,0),'placed':(3,2),'base_placement':(2,0),'head_placement':(3,1),'correction_vs_base':(3,0)};contrasts={n:summary([v[i]/v[j] for v in vectors]) for n,(i,j) in pairs.items()};contrasts['change_in_ratio']=summary([(v[3]/v[2])/(v[1]/v[0]) for v in vectors]);contrasts['copies']={labels[i]:summary([r[i]/r[i+4] for r in rows]) for i in range(4)};report[c]=contrasts
save('result.json',report);print(json.dumps({k:{n:round(v['median'],3) for n,v in vals.items() if n!='copies'} for k,vals in report.items()}))
