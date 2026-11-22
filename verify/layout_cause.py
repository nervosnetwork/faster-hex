from pathlib import Path
import collections
import hashlib
import json
import os
import platform
import random
import re
import shutil
import statistics
import subprocess as sp
import tarfile
from cause_common import ROOT, compare, measure, pin, save, section


def symbols(exe):
    table = {}
    for line in sp.check_output(['nm', '-nS', exe], text=True).splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        address, length, _, symbol = parts
        for name in ('run_sample', 'hex_decode_avx2_checked', 'hex_decode_avx512_checked', 'hex_decode_sse41_checked'):
            if name == symbol or ('hex_decode_' in name and name in symbol):
                insns = sp.check_output(['objdump', '-d', '--no-show-raw-insn', '--disassemble='+symbol, exe], text=True)
                ops = re.findall(r'^\s*[a-f0-9]+:\s+(\S+)', insns, flags=re.M)
                assert ops, symbol
                table[name] = [int(address,16), int(length,16), hashlib.sha256(' '.join(ops).encode()).hexdigest()]
    assert len(table)==4, (exe,table)
    return table


def prepare():
    cwd = Path.cwd()
    w = cwd/'layout-work'; w.mkdir()
    report = w/'results'; report.mkdir()
    wrapper = w/'bin'; wrapper.mkdir()
    link = wrapper/'cc'; shutil.copy2(ROOT/'verify/layout_link.py', link); link.chmod(0o755)
    cc = shutil.which('cc')
    driver=w/'downstream'; shutil.copytree(ROOT/'verify/retained',driver)
    lock=(driver/'Cargo.lock').read_text()
    codec=w/'codec'
    variants={}
    stats={}
    for role,ref in [('release','6d84260fe321669e7f93ecfb8aecb4db0f582f14'),('version','f83d1075a7945c2dfe56ee7b94d9b6b1783cdf93')]:
        codec.mkdir()
        with sp.Popen(['git','archive',ref],cwd=ROOT,stdout=sp.PIPE) as proc:
            with tarfile.open(fileobj=proc.stdout,mode='r|') as arch: arch.extractall(codec,filter='data')
            assert not proc.wait()
        version='2.0.0' if role=='release' else '2.1.0'
        (driver/'Cargo.lock').write_text(lock.replace('name = "faster-hex"\nversion = "2.1.0"','name = "faster-hex"\nversion = "'+version+'"'))
        out=w/role;out.mkdir()
        env=dict(os.environ,PATH=str(wrapper)+':'+os.environ['PATH'],LAYOUT_REAL_CC=cc,LAYOUT_IMAGES=str(out),
                 CARGO_TARGET_DIR=str(w/('target-'+role)),CARGO_PROFILE_RELEASE_LTO='thin')
        sp.run(['cargo','build','--locked','--release','--bin','decode','-j','1'],cwd=driver,env=env,check=True)
        for f in sorted(out.iterdir()):
            if f.name in ('anchors.json','link.map'):
                shutil.copy2(f,report/(role+'-'+f.name))
                continue
            name=role+'/'+f.name; variants[name]=f
            stats[name]={'text':section(f), 'rodata':section(f,'.rodata'), 'symbols':symbols(f)}
        assert len([v for v in variants if v.startswith(role+'/')])==17
        save(report/'layout.json',stats)
        base=stats[role+'/native']['symbols']
        diff={}
        for name, row in stats.items():
            if not name.startswith(role+'/') or name.endswith('/native'): continue
            delta=[row['symbols'][s][0]-base[s][0] for s in ['hex_decode_avx2_checked','run_sample']]
            diff[name]=delta
            assert all(row['symbols'][s][1:]==base[s][1:] for s in base), (name,'instruction sequence changed')
            assert row['rodata'][:2]==stats[role+'/native']['rodata'][:2]
        print(role,'measured address changes',diff,flush=True)
        codec.rename(w/('source-'+role))
    return w,driver,variants,stats


w,driver,variants,stats=prepare()
out=w/'results'
cpu=sp.check_output(['lscpu'],text=True); save(out/'host.json',{'cpu':cpu,'rust':sp.check_output(['rustc','-vV'],text=True)})
pin()
rng=random.Random(82073)
for n in (16,32,96):
    names=list(variants)+['aa']
    def sample(name,loops):
        return measure(w/'entry', variants['release/native' if name=='aa' else name],[n,loops],driver)
    loops=max(150000,min(5000000,round(10000000/max(.5,sample('release/native',100000)))))
    collected=[]
    for _ in range(15):
        rng.shuffle(names); pair=collections.defaultdict(list)
        for name in names+names[::-1]: pair[name].append(sample(name,loops))
        collected.append({name:statistics.mean(vals) for name,vals in pair.items()})
    save(out/f'samples-{n}.json',collected)
    data={name:compare(collected,'release/native',name) for name in names}
    save(out/f'times-{n}.json',data)
    print(n,'originals',data['version/native'], 'A/A',data['aa'],flush=True)
    for role in ('release','version'):
        positions=collections.defaultdict(list)
        for name,row in stats.items():
            if name.startswith(role+'/') and not name.endswith('/native'):
                key=tuple(row['symbols'][s][0]%64 for s in ('hex_decode_avx2_checked','run_sample'))
                positions[key].append(round(100*(data[name]['ratio']-1),2))
        print(role,'AVX2/caller residues and percentage against release',dict(positions),flush=True)
