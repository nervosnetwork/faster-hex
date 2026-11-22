from pathlib import Path
import os
import platform
import random
import shutil
import statistics
import subprocess as sp
import tarfile
from cause_common import ROOT, compare, measure, pin, save, section

w=Path(os.environ.get('APPEND_WORK',ROOT/'append-work')).resolve()
w.mkdir(parents=True,exist_ok=True);out=w/'results';out.mkdir(exist_ok=True)
driver=w/'downstream';shutil.copytree(ROOT/'verify/retained',driver,dirs_exist_ok=True)
lock=(driver/'Cargo.lock').read_text()
base='976abc9503a22c1b24beb54182add19af097f098'
roles={'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','fixed':base,'offset':'a6f1c464b2390d2aa82ed062389ffe100fd08ff9','specialized':'c2858276c1485881c1da8854c5fe1741d9df7cd9','release':'6d84260fe321669e7f93ecfb8aecb4db0f582f14'}
bins=['append_call','raw_vec','decode','array32','first','last']
for role,ref in roles.items():
    selected=[b for b in bins if b!='append_call' or role!='release']
    if all((w/(role+'-'+b)).exists() for b in selected) and (w/('source-'+role)).is_dir():
        continue
    codec=w/'codec';codec.mkdir()
    with sp.Popen(['git','archive',ref],cwd=ROOT,stdout=sp.PIPE) as proc:
        with tarfile.open(fileobj=proc.stdout,mode='r|') as arch:arch.extractall(codec,filter='data')
        assert not proc.wait()
    patch=ROOT/'verify/append-fixes'/(role+'.patch')
    if patch.exists():sp.run(['patch','-p1','-i',str(patch)],cwd=codec,check=True)
    append_bin=driver/'src/bin/append_call.rs'
    if role=='release':append_bin.unlink(missing_ok=True)
    else:shutil.copyfile(ROOT/'verify/append_call.rs',append_bin)
    version='2.0.0' if role=='release' else '2.1.0'
    (driver/'Cargo.lock').write_text(lock.replace('name = "faster-hex"\nversion = "2.1.0"','name = "faster-hex"\nversion = "'+version+'"'))
    env=dict(os.environ,CARGO_TARGET_DIR=str(w/('target-'+role)))
    if os.getenv('PROFILE')=='thin':env['CARGO_PROFILE_RELEASE_LTO']='thin'
    sp.run(['cargo','build','--release','--locked','--bins','--quiet'],cwd=driver,env=env,check=True)
    for b in selected:shutil.copy2(w/('target-'+role)/'release'/b,w/(role+'-'+b))
    codec.rename(w/('source-'+role))
segments={}
for role in roles:
    for b in bins:
        exe=w/(role+'-'+b)
        if exe.exists():
            segments[role+'/'+b]={'text':section(exe)}
            if platform.system()=='Linux':segments[role+'/'+b]['rodata']=section(exe,'.rodata')
save(out/'segments.json',segments)
pin()
host=['sysctl','-n','machdep.cpu.brand_string'] if platform.system()=='Darwin' else ['lscpu']
identity=sp.run(host,capture_output=True,text=True)
save(out/'host.json',{'cpu':identity.stdout.strip() or platform.machine(),'rust':sp.check_output(['rustc','-vV'],text=True)})
cases=[('append_call',n,k) for n in (32,4096) for k in ('valid','first','middle','rollback')]
cases+= [('decode',n,'codec') for n in (16,32)]+[('raw_vec',n,'codec') for n in (32,1025,4096)]+[('array32',32,'codec')]+[(b,n,'codec') for b in ('first','last') for n in (32,4096)]
rng=random.Random(79432);rng.shuffle(cases);data={};raw={}
for b,n,k in cases:
    reference='pr' if b=='append_call' else 'release'
    relevant=[r for r in roles if r!='release' or b!='append_call']
    def sample(role,loops):
        return measure(w/'entry',w/((reference if role=='aa' else role)+'-'+b),[n,loops]+([] if k=='codec' else [k]),driver)
    loops=max(500,min(5000000,round(12000000/max(.5,sample('pr',5000)))))
    rows=[]
    for _ in range(17):
        order=relevant+['aa'];rng.shuffle(order);v={role:[] for role in order}
        for role in order+order[::-1]: v[role].append(sample(role,loops))
        rows.append({role:statistics.mean(vals) for role,vals in v.items()})
    key=f'{b}/{n}/{k}';raw[key]=rows
    data[key]={a+'/'+z:compare(rows,a,z) for a,z in [(reference,'aa'),('pr','fixed'),('pr','offset'),('pr','specialized'),('fixed','offset'),('fixed','specialized'),('specialized','offset')]+([(reference,'fixed'),(reference,'offset'),(reference,'specialized')] if reference!='pr' else [])}
    save(out/'times.json',data);save(out/'samples.json',raw)
    print(key,{pair:round((r['ratio']-1)*100,2) for pair,r in data[key].items()},flush=True)
