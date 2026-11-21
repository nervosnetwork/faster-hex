"""Repeat the released 32-byte Criterion driver with ordinary separate builds."""
from pathlib import Path
import json, os, shutil, statistics, subprocess as sp, sys
repo=Path.cwd(); work=repo/'release32-work'; result=repo/'results'
work.mkdir(exist_ok=True);result.mkdir(exist_ok=True)
source=work/'codec'; target=work/'target'; samples=work/'samples'
env=dict(os.environ,CARGO_TARGET_DIR=str(target),CRITERION_HOME=str(samples))
def run(args,at,**options):
    return sp.run(args,cwd=at,env=env,check=True,**options)
base=os.environ['REFERENCE_REV'];head=os.environ['PRODUCT_REV']
driver=work/'reference-driver.tar'
run(['git','archive','-o',driver,base,'benches'],repo)
exes={}
for label,rev in [('base',base),('head',head)]:
    if source.exists():shutil.rmtree(source)
    source.mkdir()
    archive=work/'source.tar'
    run(['git','archive','-o',archive,rev],repo)
    run(['tar','-xf',archive],source)
    run(['tar','-xf',driver],source)
    if label=='base':
        run(['cargo','generate-lockfile'],source)
        locked=(source/'Cargo.lock').read_text()
    else:
        entry='name = "faster-hex"\nversion = "2.0.0"'
        assert locked.count(entry)==1
        (source/'Cargo.lock').write_text(locked.replace(entry,entry.replace('2.0.0','2.1.0')))
        run(['cargo','clean','--profile','bench','-p','faster-hex'],source)
    built=run(['cargo','bench','--locked','--no-run','--bench','hex','--message-format=json-render-diagnostics'],source,stdout=sp.PIPE,text=True)
    executable=next(j['executable'] for line in built.stdout.splitlines() if (j:=json.loads(line)).get('executable') and 'bench' in j['target']['kind'])
    exes[label]=work/(label+'-hex');shutil.copy2(executable,exes[label])
pin=['taskset','-c',str(min(os.sched_getaffinity(0)))] if sys.platform=='linux' else []
measurements={}
case='encode/faster_hex/32'
for label in ['base1','head1','head2','base2','head3','base3','base4','head4']:
    role=label[:-1]
    run(pin+[str(exes[role]),'--bench','^'+case+'$','--warm-up-time','0.3','--measurement-time','1.0','--sample-size','40','--nresamples','10000','--noplot','--save-baseline',label],work,stdout=sp.DEVNULL)
    row=next(f for f in samples.rglob(label+'/benchmark.json') if json.loads(f.read_text())['full_id']==case)
    estimate=json.loads(row.with_name('estimates.json').read_text())
    data=estimate['slope'] or estimate['mean']; ci=data['confidence_interval']
    measurements[label]=[data['point_estimate'],ci['lower_bound'],ci['upper_bound']]
(result/'release32.json').write_text(json.dumps(measurements,indent=2))
print(case,measurements,flush=True)
