from pathlib import Path
import os, platform, random, shutil, statistics, subprocess as sp, tarfile
from cause_common import ROOT, BASE, section, measure, save, pin, compare

work=Path(os.getenv('CONTROL_WORK',ROOT/'controls')).resolve(); work.mkdir(parents=True,exist_ok=True)
out=work/'results';out.mkdir(exist_ok=True); driver=work/'downstream';shutil.copytree(ROOT/'verify/retained',driver,dirs_exist_ok=True)
lock=(driver/'Cargo.lock').read_text()
roles={'release':'6d84260fe321669e7f93ecfb8aecb4db0f582f14', 'version':'f83d1075a7945c2dfe56ee7b94d9b6b1783cdf93','at20':'976abc9503a22c1b24beb54182add19af097f098','pr':BASE,'scoped':'4a915966374e2fcab6bb4691e0ab8cc51e423aa0','fixed':'976abc9503a22c1b24beb54182add19af097f098','owned':'8039290','preflight':'26b8c18','inline_prefix':'c9a3e3b','separate_prefix':'73a648e'}
# The first four builds compare code at fixed version, then version at fixed code.
sections={}
for role,ref in roles.items():
    codec=work/'codec';codec.mkdir()
    with sp.Popen(['git','archive',ref],cwd=ROOT,stdout=sp.PIPE) as proc:
        with tarfile.open(fileobj=proc.stdout,mode='r|') as t:t.extractall(codec,filter='data')
        assert proc.wait()==0
    if role=='at20':
        p=codec/'Cargo.toml';s=p.read_text();assert s.count('version = "2.1.0"')==1;p.write_text(s.replace('version = "2.1.0"','version = "2.0.0"'))
    version='2.0.0' if role in ('release','at20') else '2.1.0'
    (driver/'Cargo.lock').write_text(lock.replace('name = "faster-hex"\nversion = "2.1.0"',f'name = "faster-hex"\nversion = "{version}"'))
    target=work/('target-'+role);env=dict(os.environ,CARGO_TARGET_DIR=str(target))
    sp.run(['cargo','build','--release','--locked','--bins','--quiet'],cwd=driver,env=env,check=True)
    binaries=['decode','encode','raw_vec']; extras=['full_format']
    if role not in ['release','version','at20','inline_prefix','separate_prefix']: extras+=['append_call']
    if role in ['pr','scoped','fixed','inline_prefix','separate_prefix']:extras+=['prefix_format']
    for name in extras:
        src=driver/'src/bin'/(name+'.rs');shutil.copy2(ROOT/'verify'/(name+'.rs'),src)
        sp.run(['cargo','build','--release','--locked','--bin',name,'--quiet'],cwd=driver,env=env,check=True);src.unlink()
    for name in binaries+extras:
        dest=work/(role+'-'+name);shutil.copy2(target/'release'/name,dest);sections[role+'/'+name]=section(dest)
        if os.getenv('SAVE_CONTROL_IMAGES') and role in ['release','version','at20','fixed'] and name in ['decode','encode','full_format']:
            shutil.copy2(dest,out/dest.name)
    codec.rename(work/('source-'+role))
save(out/'sections.json',sections)
hostcmd=['sysctl','-n','machdep.cpu.brand_string'] if platform.system()=='Darwin' else ['lscpu'];cpu=os.getenv('VERIFIED_CPU_NAME') or sp.check_output(hostcmd,text=True); save(out/'host.json',{'cpu':cpu,'rustc':sp.check_output(['rustc','-Vv'],text=True)})
cases=[]
controls=['release','version','at20','fixed']; views=controls+['inline_prefix','separate_prefix'];appends=['pr','scoped','fixed','owned','preflight']
for name,ns in [('decode',[16,32,256]),('encode',[8,32,33]),('raw_vec',[32])]:
    for n in ns:cases.append((name,n,'codec',controls))
for n,k in [(0,'display'),(32,'display'),(32,'alternate'),(513,'padded')]:cases.append(('full_format',n,k,views))
for n in [7,12]:cases.append(('prefix_format',n,'display',['pr','fixed','inline_prefix','separate_prefix']))
for n in [32,4096]:
    for k in ['valid','first','middle','rollback']:cases.append(('append_call',n,k,appends))
pin();rng=random.Random(551063);rng.shuffle(cases);raw={};summary={}
for name,n,kind,variants in cases:
    def sample(role,count):return measure(work/'same-executable', work/((variants[0] if role=='aa' else role)+'-'+name),[n,count]+([] if kind=='codec' else [kind]),driver)
    rounds=max(500,min(5000000,round(18000000/max(.5,sample(variants[0],6000)))))
    rows=[]
    for _ in range(19):
        order=variants+['aa'];rng.shuffle(order);groups={role:[] for role in order}
        for role in order+order[::-1]:groups[role].append(sample(role,rounds))
        rows.append({role:statistics.mean(vals) for role,vals in groups.items()})
    pairs=[(variants[0],v) for v in variants[1:]+['aa']]
    if 'version' in variants:pairs+=[('version','fixed'),('at20','fixed')]
    if 'scoped' in variants:pairs+=[('scoped','fixed')]
    if 'inline_prefix' in variants:pairs += [('fixed','inline_prefix'),('fixed','separate_prefix')]
    key=f'{name}/{n}/{kind}';raw[key]=rows;summary[key]={a+'/'+b:compare(rows,a,b) for a,b in pairs}
    save(out/'times.json',summary);save(out/'samples.json',raw)
    print(key,{k:round(100*(v['ratio']-1),2) for k,v in summary[key].items()},flush=True)
