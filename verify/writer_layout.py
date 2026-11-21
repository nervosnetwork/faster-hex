from pathlib import Path
import hashlib, json, os, re, statistics, subprocess, sys
work=Path(os.environ.get('STUDY_WORK','writer-layout-work')).resolve()
out=Path(os.environ.get('RESULTS','results')).resolve()
out.mkdir(parents=True,exist_ok=True)
base='25cfd8eb6a4cd8257a96fabaf73771cabcced4b4'
head=os.environ['PRODUCT_REV']
layout={}
timings={}
def mapped(exe):
 image=exe.read_bytes(); result={}
 for line in subprocess.check_output(['readelf','-SW',exe],text=True).splitlines():
  m=re.match(r'\s*\[\s*\d+\]\s+(\.\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+(\S+)\s+',line)
  if m and 'A' in m[6]:
   name,kind,addr,start,n,_=m.groups();start,n=int(start,16),int(n,16)
   data=b'' if kind=='NOBITS' else image[start:start+n]
   result[name]=[addr,n,hashlib.sha256(data).hexdigest()]
 assert '.text' in result and '.rodata' in result
 return result
for label,left,right in [('AA',base,base),('AB',base,head),('BA',head,base)]:
 folder=out/label
 env=dict(os.environ,OWNED_WRITER='1',WRITER_LAYOUT='1',WRITER_BASE=left,PRODUCT_REV=right,RESULTS=str(folder),STUDY_WORK=str(work))
 if label=='BA':env['WRITER_BUILD_ONLY']='1'
 subprocess.run([sys.executable,'verify/shared_writer.py'],env=env,check=True)
 layout[label]=mapped(work/'target/release/shared-field-writer')
 if label!='BA':
  results=json.loads((folder/'shared-writer.json').read_text())
  timings[label]={n:round(100*(statistics.median(v['ratio'][0] for k,v in results.items() if k.split('/')[0]==n)-1),2) for n in ['10','32','65','256','4096']}
changed={label:[k for k in layout['AA'].keys()|v.keys() if layout['AA'].get(k)!=v.get(k)] for label,v in layout.items() if label!='AA'}
(out/'writer-layout.json').write_text(json.dumps(dict(sections=layout,changed=changed,timings=timings),indent=2))
text=f'Two fixed caller types use the same input vector and output buffer. Compared with both copies at {base}, changing the crate in either slot to {head} changed these mapped sections: {changed}. B/A timing at each input size for same-source AA and revision-mixed AB builds (percent): {timings}.'
print(text,flush=True)
if path:=os.environ.get('GITHUB_STEP_SUMMARY'):
 with open(path,'a') as f:f.write(text+'\n')
