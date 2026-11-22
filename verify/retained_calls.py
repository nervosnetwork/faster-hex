from pathlib import Path
import os, shutil, subprocess as sp, sys, tarfile, random, statistics
from cause_common import BASE, ROOT, section, pin, save, measure, compare
work=Path(os.getenv('RETAINED_WORK',ROOT/'retained-work')).resolve()
work.mkdir(exist_ok=True,parents=True)
driver=work/'downstream'
shutil.copytree(ROOT/'verify/retained',driver,dirs_exist_ok=True)
lock=(driver/'Cargo.lock').read_text()
out=work/'results';out.mkdir(exist_ok=True)
roles={'release':'6d84260fe321669e7f93ecfb8aecb4db0f582f14','version':'f83d1075a7945c2dfe56ee7b94d9b6b1783cdf93','pr':BASE,'prepared':'c2858276c1485881c1da8854c5fe1741d9df7cd9'}
codec=work/'codec'; sections={}
for role,ref in roles.items():
    if codec.exists():
        codec.rename(work/('source-before-'+role))
    codec.mkdir()
    with sp.Popen(['git','archive',ref],cwd=ROOT,stdout=sp.PIPE) as proc:
        with tarfile.open(fileobj=proc.stdout,mode='r|') as t:t.extractall(codec,filter='data')
        assert proc.wait()==0
    v='2.0.0' if role=='release' else '2.1.0'
    (driver/'Cargo.lock').write_text(lock.replace('name = "faster-hex"\nversion = "2.1.0"',f'name = "faster-hex"\nversion = "{v}"'))
    target=work/('target-'+role)
    env=dict(os.environ,CARGO_TARGET_DIR=str(target))
    sp.run(['cargo','build','--release','--locked','--bins','--quiet'],cwd=driver,env=env,check=True)
    for file in (driver/'src/bin').glob('*.rs'):
        dest=work/(role+'-'+file.stem)
        shutil.copy2(target/'release'/file.stem,dest)
        sections[role+'/'+file.stem]=section(dest)
    for name,fixture in [('full_format','full_format'),('append_call','append_call')]:
        if name=='append_call' and role in ('version','release'):continue
        src=driver/'src/bin'/(name+'.rs');shutil.copy2(ROOT/'verify'/(fixture+'.rs'),src)
        sp.run(['cargo','build','--release','--locked','--bin',name,'--quiet'],cwd=driver,env=env,check=True)
        src.unlink();dest=work/(role+'-'+name);shutil.copy2(target/'release'/name,dest);sections[role+'/'+name]=section(dest)
save(out/'sections.json',sections)
pin();rng=random.Random(88241)
cases=[('encode',n) for n in [4,8,16,20,32,33,65,256,4096]]
cases += [('decode',n) for n in [4,16,20,32,96,256,1024,4096]]
cases += [('raw_vec',n) for n in [32,1025,4096]]+[('array32',32)]
cases += [(b,n) for b in ['first','last'] for n in [32,4096]]
cases=[(b,n,"codec") for b,n in cases]+[("full_format",n,k) for n in (0,32,513,4096) for k in ("display","alternate","padded")]+[("append_call",n,k) for n in (32,4096) for k in ("valid","rollback")]
rng.shuffle(cases)
summary={};raw={}
for b,n,kind in cases:
    def sample(role,count): return measure(work/'same-executable',work/(('pr' if role=='aa' else role)+'-'+b),[n,count]+([] if kind=="codec" else [kind]),driver)
    loops=max(200,min(5000000,round(18000000/max(.5,sample('pr',5000)))))
    rows=[]
    for _ in range(20):
        order=(['pr','prepared'] if b=='append_call' else list(roles))+['aa'];rng.shuffle(order);groups={k:[] for k in order}
        for k in order+order[::-1]:groups[k].append(sample(k,loops))
        rows.append({k:statistics.mean(v) for k,v in groups.items()})
    key=f'{b}/{n}' if kind=='codec' else f'{b}/{n}/{kind}';raw[key]=rows
    summary[key]={x+'/'+y:compare(rows,x,y) for x,y in [('release','version'),('version','prepared'),('release','pr'),('release','prepared'),('pr','prepared'),('pr','aa')] if x in rows[0] and y in rows[0]}
    print(key,{p:round(100*(v['ratio']-1),2) for p,v in summary[key].items()},flush=True)
    save(out/'times.json',summary);save(out/'samples.json',raw)
