"""Change just the old call site in the pinned Git prefix caller."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess
import sys

v=Path(__file__).resolve().parent
sys.path.insert(0,str(v))
import isolated_cases as scope
from cause_common import pin, save, section
from cross_file_copies import crossover

spec=json.loads((v/'gix_caller_shape_inputs.json').read_text())
scope.revisions=spec['refs']
cases=[(7,'sha1-adopt'),(0,'sha256-adopt')]
scope.cases=[('gix_prefix',n,k) for n,k in cases]
scope.pairs=[]

def build_shapes(role,driver,out,cargo,env):
    caller=driver/'src/bin/gix_prefix.rs'
    original=caller.read_text()
    assert original==(v/'gix_prefix.rs').read_text()
    call='run(&prefixes, &expected, n, Prefix::hex_to_buf)'
    assert original.count(call)==1
    signature="fn selected<'a>"
    assert original.count(signature)==1
    boundary="#[inline(never)]\nfn existing<'a>(prefix: &Prefix, dst: &'a mut [u8]) -> &'a mut str { prefix.hex_to_buf(dst) }\n\n"
    texts={
        'new_only':original.replace(call,'run(&prefixes, &expected, n, selected)'),
        'old_outlined':original.replace(call,'run(&prefixes, &expected, n, existing)').replace(signature,boundary+signature),
    }
    try:
        for name,text in texts.items():
            caller.write_text(text)
            subprocess.run([*cargo,'build','--release','--locked','--offline','--quiet','--bin','gix_prefix'],cwd=driver,env=env,check=True)
            image=out/(role+'-'+name)
            shutil.copy2(Path(env['CARGO_TARGET_DIR'])/'release/gix_prefix',image)
            for mode in ('sha1-adopt','sha256-adopt','sha1-legacy','sha256-legacy'):
                subprocess.run([image,'7','1200',mode],stdout=subprocess.DEVNULL,check=True)
            if name=='old_outlined':
                symbols=subprocess.check_output(['nm','-C',str(image)],text=True)
                assert re.search(r'\b[gG]ix_prefix::existing\b',symbols)
    finally:
        caller.write_text(original)

driver=v/'isolate_callers.py'
source,sep,_=driver.read_text().partition('\npin();rng=')
assert sep
after='    if transient is not None: transient.cleanup()'
assert source.count(after)==1
source=source.replace(after,'    build_shapes(role,driver,out,cargo,build_env)\n'+after)
ns={'__name__':'__main__','__file__':str(driver),'build_shapes':build_shapes}
exec(compile(source,str(driver),'exec'),ns)
out=ns['out']; work=ns['work']
metadata=json.loads((out.parent/'archives.json').read_text())
assert {p['role']:p['sha'] for p in metadata}==spec['refs']
load_ns={'__file__':str(v/'pr_components.py')}
exec(compile((v/'pr_components.py').read_text().split('spec=json.loads',1)[0],str(v/'pr_components.py'),'exec'),load_ns)
loaded=load_ns['load_image']
anchors={role:{k:section(out/(role+'-gix_prefix'),k) for k in expected}==expected for role,expected in spec['anchors'].items()}
save(out/'anchors.json',anchors)
assert all(anchors.values()),anchors
pin()
results={}
for shape in ('gix_prefix','new_only','old_outlined'):
    images=[out/(role+'-'+shape) for role in ('pr','retained')]
    both=[f.read_bytes() for f in images]
    same_loaded=loaded(images[0])==loaded(images[1])
    results[shape]=dict(identical_file=both[0]==both[1],identical_loaded_image=same_loaded,
        sha256=[hashlib.sha256(b).hexdigest() for b in both],
        text=[section(f,'.text') for f in images],
        rodata=[section(f,'.rodata') for f in images])
    save(out/'programs.json',results)
    if not same_loaded:
        crossover(images,out/'fixed-program',work/'caller',out/('pr-vs-retained-'+shape),cases)
