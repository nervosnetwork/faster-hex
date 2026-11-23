"""Check the feature-selector and digit-class changes on their respective architectures."""
from pathlib import Path
import hashlib, io, json, os, shutil, subprocess, sys, tarfile

v=Path(__file__).resolve().parent
sys.path.insert(0,str(v))
from cause_common import pin,save,section
from cross_file_copies import crossover
import isolated_cases as scope

key=os.environ['HOST_KEY'];arm='-arm-' in key
spec=json.loads((v/'platform_contract_inputs.json').read_text())
refs=spec['refs']
scope.revisions={'release':refs['release'],'parent':refs['bulk_base' if arm else 'retained'],'candidate':refs['bulk' if arm else 'framing']}
cases=({'legacy_check':[(32,'valid'),(128,'valid'),(4096,'valid')],
        'qualified_decode':[(32,'valid'),(4096,'valid')],'validate_call':[(32,'first'),(4096,'last'),(4096,'valid')],
        'vec_read_slice':[(32,'escaped'),(4096,'plain')],'vec_round_slice':[(4096,'plain')]} if arm else
       {'qualified_decode':[(32,'valid'),(4096,'valid')],'full_buffer':[(32,'buffer'),(65,'buffer')],
        'gix_prefix':[(7,'sha1-adopt')],'append_call':[(32,'rollback'),(4096,'valid')],
        'vec_round_slice':[(4096,'plain')],'ckb_caller':[(32,'plain')]})
scope.cases=[(op,n,mode) for op,seq in cases.items() for n,mode in seq];scope.pairs=[]
driver=v/'isolate_callers.py';source,sep,_=driver.read_text().partition('\npin();rng=');assert sep
guard="    if SCOPE in ('fmt-join','fmt-field','prefix-length','release-audit','prefix-kernel-exchange','prefix-operation') and role in ('release','version'):"
assert source.count(guard)==1
source=source.replace(guard,guard[:-1]+" and 'gix_prefix' in bins:")
ns={'__name__':'__main__','__file__':str(driver)}
exec(compile(source,str(driver),'exec'),ns)
out=ns['out'];work=ns['work']
metadata=json.loads((out.parent/'archives.json').read_text())
assert {p['role']:p['sha'] for p in metadata}==scope.revisions
assert next(p['checksum'] for p in metadata if p['role']=='release')==ns['PUBLISHED']
load_ns={'__file__':str(v/'pr_components.py')}
exec(compile((v/'pr_components.py').read_text().split('spec=json.loads',1)[0],str(v/'pr_components.py'),'exec'),load_ns)
loaded=load_ns['load_image']
images={};signatures={}
for role in scope.revisions:
    for op in cases:
        exe=out/(role+'-'+op)
        if role=='release' and op in ('validate_call','append_call'):
            assert not exe.exists();continue
        tag=role+'/'+op
        images[tag]=loaded(exe)
        signatures[tag]={k:section(exe,k) for k in ('.text','.rodata')}
checks={k:all(signatures[k][p]==v for p,v in expected.items()) for k,expected in spec['anchors'][key].items() if k in signatures}
save(out/'anchors.json',checks)
assert all(checks.values()),[q for q,b in checks.items() if not b]
save(out/'fingerprints.json',signatures)
qa=work/'contract-qa';qa.mkdir()
sha=scope.revisions['candidate']
with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['git','archive',sha],cwd=v.parent))) as t:
    t.extractall(qa,filter='data')
env=dict(os.environ,CARGO_TARGET_DIR=str(work/'contracts-target'));env.pop('CARGO_PROFILE_RELEASE_LTO',None)
if arm:shutil.copy2(v/'classify_digit_lanes.rs',qa/'tests/classify_digit_lanes.rs')
tests=[(['--lib','--tests'],'all-feature-release')]
if arm:
    tests.append((['--test','classify_digit_lanes','--','--nocapture'],'byte-positions-and-cases'))
else:
    tests.extend([(['--lib','missing_cpu_or_os_support_forces_a_fallback','--','--nocapture'],'mandatory-downgrade'),
                  (['--test','allocations','a_rejected_borrowed_option_does_not_allocate_its_decoded_bytes'],'rejected-borrowed-option')])
for args,label in tests:
    result=subprocess.run(['cargo','test','--release','--all-features',*args],cwd=qa,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/(label+'.log')).write_text(result.stdout)
    assert result.returncode==0,result.stdout[-3000:]
    if label=='byte-positions-and-cases':assert '1090560 byte, policy and position checks passed' in result.stdout
    if label in ('mandatory-downgrade','rejected-borrowed-option'):assert '1 passed' in result.stdout
pin();summary={}
for op,seq in cases.items():
    for role in ('parent','release'):
        if role=='release' and (op in ('validate_call','append_call','gix_prefix') or not arm and op!='qualified_decode'):continue
        tag=role+'-vs-candidate-'+op
        same=images[role+'/'+op]==images['candidate/'+op]
        summary[tag]=dict(cases=seq,identical_loaded_image=same)
        save(out/'comparisons.json',summary)
        if not same:
            crossover([out/(role+'-'+op),out/('candidate-'+op)],out/'compare-program',work/'caller',out/tag,seq,count_last=(op=='ckb_caller'))
