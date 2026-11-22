"""Compare production release builds for ordinary fields, the transient reader, and pinned consumers."""
from pathlib import Path
import os, random, shutil, statistics, subprocess as sp, sys, tarfile
from cause_common import BASE, ROOT, section, measure, compare, pin, save
mode=os.environ['CARGO_PROFILE_RELEASE_LTO']
real=sys.argv[1]=='consumer'
work=ROOT/('real' if real else 'field-cause-work')
out=ROOT/'short-results';out.mkdir(exist_ok=True)
if real:
    driver=work/'caller'
    shutil.copytree(ROOT/'verify/downstream/caller',driver,dirs_exist_ok=True)
    lock=(driver/'Cargo.lock').read_text()
    cases=[('ckb_caller',n,k) for n in (32,4096) for k in ('plain','escaped')]
    cases += [('gix_caller',n,'parse') for n in (20,32)]
    roles=['release','pr','candidate']
else:
    sp.run([sys.executable,'verify/which_field_slows.py'],cwd=ROOT,check=True,env=dict(os.environ,FIELD_DRIVERS_ONLY='1'))
    driver=work/'downstream'
    for b in ['mixed','upper','lower']:
        shutil.copyfile(ROOT/f'verify/{b}_decode.rs',driver/f'src/bin/{b}.rs')
    shutil.copyfile(ROOT/'verify/field_allocations.rs',driver/'src/bin/allocated.rs')
    cases=[(b,n,k) for b in ['array_read_slice','vec_read_slice','array_round_slice','vec_round_slice'] for n in [32,4096] for k in ['plain','escaped']]
    cases += [(b,n,'reader') for b in ['array_read_reader','vec_read_reader'] for n in [32,4096]]
    cases += [(b,n,'plain') for b in ['optarray_read_slice','optvec_read_slice'] for n in [32,4096]]
    cases += [(b,n,'core') for b in ['mixed','upper','lower'] for n in [8,16,20,32,4096]]
    roles=['pr','candidate']
codec=work/'codec';codec.mkdir(exist_ok=True)
bins=sorted({c[0] for c in cases}|(set() if real else {'ownership','allocated'}))
sections={}
for role in roles:
    ref={'release':'v2.0.0','pr':BASE,'candidate':'HEAD'}[role]; version='2.0.0' if role=='release' else '2.1.0'
    with sp.Popen(['git','archive',ref],cwd=ROOT,stdout=sp.PIPE) as proc:
        with tarfile.open(fileobj=proc.stdout,mode='r|') as tar:tar.extractall(codec,filter='data')
        assert proc.wait()==0
    target=work/('target' if real else 'target-'+role)
    env=dict(os.environ,CARGO_TARGET_DIR=str(target))
    if real:
        (driver/'Cargo.lock').write_text(lock.replace('name = "faster-hex"\nversion = "2.1.0"','name = "faster-hex"\nversion = "'+version+'"').replace('"faster-hex 2.1.0"','"faster-hex '+version+'"'))
        graph=sp.check_output(['cargo','tree','--locked','-i','faster-hex@'+version],cwd=driver,env=env,text=True)
        assert str(codec) in graph and 'ckb-jsonrpc-types ' in graph and 'gix-hash ' in graph
        if target.exists():sp.run(['cargo','clean','--release','-p','faster-hex@'+version,'-p','real-hex-consumers'],env=env,cwd=driver,check=True)
    sp.run(['cargo','build','--quiet','--release',*(['--locked'] if real or (driver/'Cargo.lock').exists() else []),*[a for b in bins for a in ('--bin',b)]],cwd=driver,env=env,check=True)
    for b in bins:
        image=work/(role+'-'+b);shutil.copy2(target/'release'/b,image)
        sections[role+'/'+b]=section(image)
    if not real:
        sp.run([work/(role+'-ownership')],check=True)
        (out/(role+'-allocations.txt')).write_bytes(sp.check_output([work/(role+'-allocated')]))
save(out/'sections.json',sections)
(out/'host.txt').write_text(sp.check_output(['lscpu'] if sys.platform=='linux' else ['sysctl','-n','machdep.cpu.brand_string'],text=True))
pin();summary={};raw={};rng=random.Random(35426);rng.shuffle(cases)
for b,n,k in cases:
    def sample(role,count):
        args=[n,k,count] if real else [n,count]+([] if k=='core' else [k])
        return measure(work/'same-program',work/(('pr' if role=='aa' else role)+'-'+b),args,driver)
    loops=max(350,min(5000000,round((22000000 if real else 14000000)/max(.4,sample('pr',7000)))))
    rows=[]
    for _ in range(24 if real else 18):
        order=roles+['aa'];rng.shuffle(order);v={r:[] for r in order}
        for r in order+order[::-1]:v[r].append(sample(r,loops))
        rows.append({r:statistics.mean(w) for r,w in v.items()})
    key=f'{b}/{n}/{k}';raw[key]=rows
    pairs=[('pr','candidate'),('pr','aa')]+([('release','candidate'),('release','pr')] if real else [])
    summary[key]={x+'/'+y:compare(rows,x,y) for x,y in pairs}
    print(key,{p:tuple(round(100*(v[q]-1),2) for q in ['ratio','lo','hi']) for p,v in summary[key].items()},flush=True)
    save(out/'short.json',summary);save(out/'samples.json',raw)
