"""Check whether the public release differences follow the program across files."""
import json,os,struct,sys
from pathlib import Path

v=Path(__file__).resolve().parent
sys.path.insert(0,str(v))
from cross_file_copies import crossover
from cause_common import save
shared=v/'pr_components.py'
build,sep,_=shared.read_text().partition('\npin()\n')
assert sep
old="refs=spec['refs']"
assert build.count(old)==1
build=build.replace(old,"roles=('release','pr') if 'arm' in os.environ['HOST_KEY'] else ('release','version','pr','pr_plain')\nrefs={r:spec['refs'][r] for r in roles}")
old="for k,expected in spec['anchors'][key].items()"
assert build.count(old)==1
build=build.replace(old,old+" if k.split('/')[0] in refs")
ns={'__name__':'__main__','__file__':str(shared)}
exec(compile(build,str(shared),'exec'),ns)
out,work=ns['out'],ns['work']
host=os.environ['HOST_KEY']
anchors=json.loads((v/'copy_control_fingerprints.json').read_text())[host]
assert ns['fingerprints']==anchors
def sections(path):
    blob=path.read_bytes();shoff=struct.unpack_from('<Q',blob,40)[0]
    size,n,stridx=struct.unpack_from('<HHH',blob,58)
    rows=[struct.unpack_from('<IIQQQQIIQQ',blob,shoff+i*size) for i in range(n)]
    off,length=rows[stridx][4:6];names=blob[off:off+length];result={}
    for label,typ,flags,addr,off,n,*_ in rows:
        name=names[label:].split(b'\0',1)[0].decode()
        if flags&2 and typ!=8:
            result[name]=(addr,blob[off:off+n])
    return result
def compare_data(a,b):
    a,b=sections(a),sections(b)
    assert a.keys()==b.keys()
    found={}
    for name,(addr,x) in a.items():
        loc,y=b[name];assert len(x)==len(y) and loc==addr,(name,addr,loc,len(x),len(y))
        differences=[(i,x[i],y[i]) for i in range(len(x)) if x[i]!=y[i]]
        if differences: found[name]={'address':addr,'bytes':len(x),'differences':differences}
    return found
def run(a,b,op,cases):
    name=a+'-vs-'+b+'-'+op
    dest=out/name
    crossover([out/(a+'-'+op),out/(b+'-'+op)],out/'fixed-program',work/'caller',dest,cases,count_last=op=='ckb_caller')
    assert (dest/'summary.json').exists()
    for f in dest.glob('file-*'):f.unlink()
if 'arm' not in host:
    left=out/'version-qualified_decode';right=out/'pr_plain-qualified_decode'
    assert ns['fingerprints']['version/qualified_decode']==ns['fingerprints']['pr_plain/qualified_decode']
    save(out/'allocated-differences.json',compare_data(left,right))
    run('release','pr','qualified_decode',[(32,'valid'),(4096,'valid')])
    run('version','pr_plain','qualified_decode',[(32,'valid'),(4096,'valid')])
elif os.environ['PROFILE']=='default':
    run('release','pr','ckb_caller',[(32,'plain')])
    run('release','pr','vec_read_slice',[(32,'escaped')])
    run('release','pr','vec_round_slice',[(4096,'plain'),(4096,'escaped')])
else:
    run('release','pr','full_format',[(4096,'display')])
    run('release','pr','vec_read_slice',[(32,'plain')])
    run('release','pr','vec_round_slice',[(32,'plain'),(32,'escaped')])
