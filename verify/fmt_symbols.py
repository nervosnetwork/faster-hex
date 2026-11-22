"""Record actual linked formatter bodies and their sizes, counting folded aliases once."""
from pathlib import Path
from collections import defaultdict
from hashlib import sha256
import json,os,re,subprocess as sp,sys
work=Path(os.environ.get('PACKAGED_WORK',Path(__file__).resolve().parents[1]/'real')).resolve()
mode=os.environ.get('CARGO_PROFILE_RELEASE_LTO','default')
out=work/'qualification'/mode
def inspect(path):
    raw=sp.check_output(['nm','-n','-C',path],text=True)
    names=defaultdict(list)
    for row in raw.splitlines():
        m=re.match(r'^([\da-fA-F]+)\s+[Tt]\s+(.+)$',row)
        if m:names[int(m[1],16)].append(m[2])
    data={}
    starts=sorted(names)
    for a,z in zip(starts,starts[1:]):
        selected=[s for s in names[a] if 'faster_hex::format::' in s or 'faster_hex..format..' in s]
        if not selected:continue
        cmd=['xcrun','llvm-objdump','-d','--demangle','--no-show-raw-insn'] if sys.platform=='darwin' else ['objdump','-d','-C','--no-show-raw-insn']
        dump=sp.check_output([*cmd,'--start-address='+str(a),'--stop-address='+str(z),path],text=True)
        body=[m[1] for line in dump.splitlines() if (m:=re.match(r'^\s*[\da-fA-F]+:\s+(\S.+)',line))]
        assert body,(path,selected)
        data[hex(a)]={'names':selected,'extent':z-a,'instructions':len(body),'listing_digest':sha256('\n'.join(body).encode()).hexdigest(),'entry':body[:32]}
    return dict(symbols=data,text_extent=sum(v['extent'] for v in data.values()))
roles=('release','version','narrow','pr','scoped','coalesced','separate','plain','typed')
result={}
for role in roles:
    for bin in ('full_format','fmt_sink','prefix_format'):
        path=out/(role+'-'+bin)
        if path.is_file():result[role+'/'+bin]=inspect(path)
assert all(result[r+'/full_format']['text_extent']>0 for r in roles)
(out/'fmt-symbols.json').write_text(json.dumps(result,indent=2))
