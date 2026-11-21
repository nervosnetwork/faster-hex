from pathlib import Path
import csv, os, platform, statistics, subprocess as sp, sys, json, shutil, random
here=Path.cwd(); lab=Path(os.environ.get('STUDY_WORK','writer-work')).resolve();lab.mkdir(parents=True,exist_ok=True)
out=Path(os.environ.get('RESULTS','results')).resolve();out.mkdir(parents=True,exist_ok=True)
src=lab/'src';src.mkdir(exist_ok=True)
shutil.copy(here/'verify'/('owned-writer.rs' if os.environ.get('OWNED_WRITER') else 'shared-writer.rs'),src/'main.rs')
roles=[('a',os.environ.get('WRITER_BASE','25cfd8eb6a4cd8257a96fabaf73771cabcced4b4')),('b',os.environ['PRODUCT_REV'])]
if os.environ.get('REVERSE_WRITER'):roles=[('a',roles[1][1]),('b',roles[0][1])]
for slot,ref in roles:
    codec=lab/slot;codec.mkdir(exist_ok=True)
    tar=lab/(slot+'.tar')
    sp.run(['git','archive','-o',tar,ref],cwd=here,check=True)
    sp.run(['tar','-xf',tar],cwd=codec,check=True)
    manifest=codec/'Cargo.toml'
    manifest.write_text(manifest.read_text().replace('name = "faster-hex"',f'name = "codec-{slot}"',1))
(lab/'Cargo.toml').write_text('[package]\nname="shared-field-writer"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nserde={version="1",features=["derive"]}\nserde_json="1"\ncodec-a={path="a"}\ncodec-b={path="b"}\n[workspace]\n')
env=dict(os.environ,CARGO_TARGET_DIR=str(lab/'target'),CARGO_PROFILE_RELEASE_LTO=os.environ.get('CARGO_PROFILE_BENCH_LTO','thin'))
if os.environ.get('WRITER_LAYOUT') and (lab/'target/release/shared-field-writer').exists():
    sp.run(['cargo','clean','--release','-p','codec-a','-p','codec-b','-p','shared-field-writer'],cwd=lab,env=env,check=True)
sp.run(['cargo','build','--release'],cwd=lab,env=env,check=True,stdout=sp.DEVNULL)
if os.environ.get('WRITER_BUILD_ONLY'):sys.exit(0)
pin=['taskset','-c',str(min(os.sched_getaffinity(0)))] if sys.platform=='linux' else []
with (out/'shared-writer.csv').open('w') as f:
    timed=sp.run(pin+[str(lab/'target/release/shared-field-writer')],cwd=lab,stdout=f,stderr=sp.PIPE,text=True,check=True)
groups={}
for row in csv.DictReader((out/'shared-writer.csv').open()):
    key='/'.join(row[k] for k in ('len','source_offset','output_offset'))
    groups.setdefault(key,[]).append([float(row[k]) for k in ['base','head','base_control','head_control']])
def summarize(x):
    med=statistics.median;rng=random.Random(193); boot=sorted(med(rng.choices(x,k=len(x))) for _ in range(4000))
    return [med(x),boot[99],boot[3899]]
result={}
for key,v in groups.items():
    m=statistics.median
    result[key]={'ns':[m([row[i] for row in v]) for i in [0,1]],'ratio':summarize([(b+bb)/(a+aa) for a,b,aa,bb in v]), 'aa':summarize([aa/a for a,b,aa,bb in v]),'bb':summarize([bb/b for a,b,aa,bb in v])}
(out/'shared-writer.json').write_text(json.dumps(result,indent=2))
print(timed.stderr.strip(),flush=True)
print('At the same source and output addresses, median change across offset pairs for each input length:',{n:round(100*(statistics.median(v['ratio'][0] for k,v in result.items() if k.split('/')[0]==n)-1),2) for n in ['10','32','65','256','4096']},flush=True)
(out/'host.txt').write_text(platform.platform()+'\n'+sp.check_output(['lscpu'] if sys.platform=='linux' else ['sysctl','-n','machdep.cpu.brand_string'],text=True)+'\n'+str(roles)+'\n'+timed.stderr)
