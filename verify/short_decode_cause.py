from pathlib import Path
import json
import os
import platform
import random
import shutil
import statistics
import subprocess as sp
import tarfile
from cause_common import ROOT, pin, save, section, compare, measure

BASE = '6d84260fe321669e7f93ecfb8aecb4db0f582f14'
VERSION = 'f83d1075a7945c2dfe56ee7b94d9b6b1783cdf93'
SCOPED = '4a915966374e2fcab6bb4691e0ab8cc51e423aa0'
work = ROOT/'retained-work'
out = ROOT/'results'
out.mkdir()
work.mkdir()
driver = work/'downstream'
shutil.copytree(ROOT/'verify/retained', driver)
lock = (driver/'Cargo.lock').read_text()

def at_ref(ref, path):
    return sp.check_output(['git', 'show', f'{ref}:{path}'], cwd=ROOT).decode()

def replace(path, before, after):
    value=path.read_text()
    assert value.count(before)==1, (path,before)
    path.write_text(value.replace(before, after))

roles={'release':BASE,'version':VERSION,'scoped':SCOPED,'inline_append':SCOPED,'base_format':SCOPED,'base_decode':SCOPED}
info={}
for role,ref in roles.items():
    codec=work/'codec'; codec.mkdir()
    with sp.Popen(['git','archive',ref],cwd=ROOT,stdout=sp.PIPE) as proc:
        with tarfile.open(fileobj=proc.stdout,mode='r|') as t:t.extractall(codec,filter='data')
        assert proc.wait()==0
    if role=='inline_append':
        replace(codec/'src/decode.rs',"pub fn hex_decode_append<'a>","#[inline]\npub fn hex_decode_append<'a>")
    if role=='base_format':
        (codec/'src/format.rs').write_text(at_ref(BASE,'src/format.rs'))
        replace(codec/'src/lib.rs','pub use crate::format::{Hex, LeadingDigits};','pub use crate::format::Hex;')
    if role=='base_decode':
        for p in ['src/decode.rs','src/decode/x86.rs','src/decode/aarch64.rs']:
            (codec/p).write_text(at_ref(BASE,p))
        replace(codec/'src/lib.rs','hex_decode_with_case, hex_validate, CheckCase,','hex_decode_with_case, CheckCase,')
        replace(codec/'src/lib.rs','{hex_decode_append, hex_decode_vec, hex_decode_vec_with_case}','{hex_decode_vec, hex_decode_vec_with_case}')
    version='2.0.0' if role=='release' else '2.1.0'
    (driver/'Cargo.lock').write_text(lock.replace('name = "faster-hex"\nversion = "2.1.0"',f'name = "faster-hex"\nversion = "{version}"'))
    # Identical source path and flags as the two previous comparisons.
    target=work/('target-'+role)
    env=dict(os.environ,CARGO_TARGET_DIR=str(target))
    sp.run(['cargo','build','--release','--locked','--bins','--quiet'],cwd=driver,env=env,check=True)
    for name in ['decode','array32','first','raw_vec','encode']:
        image=work/(role+'-'+name)
        shutil.copy2(target/'release'/name,image)
        info[role+'/'+name]=section(image)
        if name=='decode':shutil.copy2(image,out/image.name)
    codec.rename(work/('source-'+role))
    print(role,info[role+'/decode'],flush=True)
save(out/'sections.json',info)
save(out/'host.json',{'system':platform.platform(),'cpu':sp.check_output(['lscpu'],text=True),'rustc':sp.check_output(['rustc','-Vv'],text=True)})
pin(); rng=random.Random(129583)
raw={}; summary={}
for name,n in [('decode',32),('decode',16),('decode',20),('array32',32),('encode',32),('first',32),('decode',256),('raw_vec',32)]:
    def sample(role,iters):return measure(work/'same-executable',work/(('release' if role=='aa' else role)+'-'+name),[n,iters],driver)
    iters=max(500,min(6000000,round(15000000/max(.5,sample('release',6000)))))
    rows=[]
    for _ in range(18):
        order=list(roles)+['aa'];rng.shuffle(order);times={k:[] for k in order}
        for role in order+order[::-1]:times[role].append(sample(role,iters))
        rows.append({k:statistics.mean(vals) for k,vals in times.items()})
    key=f'{name}/{n}';raw[key]=rows
    summary[key]={role:compare(rows,'release',role) for role in [*list(roles)[1:],'aa']}
    print(key, {k:round(100*(v['ratio']-1),2) for k,v in summary[key].items()},flush=True)
    save(out/'times.json',summary);save(out/'samples.json',raw)
