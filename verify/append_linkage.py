"""Record linked call boundaries independently of elapsed time."""
import json,os,re,subprocess as sp,sys
from pathlib import Path

work=Path(os.environ.get('PACKAGED_WORK',Path(__file__).resolve().parents[1]/'real')).resolve()
mode=os.environ.get('CARGO_PROFILE_RELEASE_LTO','default')
out=work/'qualification'/mode
def run(*args):return sp.check_output(args,text=True)
def record(img):
    syms=[]
    for row in run('nm','-n','-C',img).splitlines():
        m=re.match(r'^([\da-fA-F]+)\s+[Tt]\s+(.+)$',row)
        if m:syms.append((int(m[1],16),m[2]))
    lookup=dict(syms);reloc={};stubs={}
    if sys.platform=='darwin':
        for row in run('otool','-Iv',img).splitlines():
            m=re.match(r'^0x([\da-fA-F]+)\s+\d+\s+(\S+)',row)
            if m:stubs[int(m[1],16)]=m[2]
    else:
        for row in run('readelf','-Wr',img).splitlines():
            m=re.match(r'^\s*([\da-fA-F]+)\s+[\da-fA-F]+\s+R_\w+_RELATIVE\s+([\da-fA-F]+)\s*$',row)
            if m:reloc[int(m[1],16)]=int(m[2],16)
    selected={}
    for i,(a,label) in enumerate(syms[:-1]):
        if not any(s in label for s in ('append_call::main','append_callsite::sample','append_callsite::caller_boundary','faster_hex::decode::hex_decode_append')):continue
        z=next((v for v,_ in syms[i+1:] if v>a),None)
        if z is None:continue
        args=['xcrun','llvm-objdump','-d','--demangle','--no-show-raw-insn'] if sys.platform=='darwin' else ['objdump','-d','-C','--no-show-raw-insn']
        code=run(*args,'--start-address='+str(a),'--stop-address='+str(z),img)
        edges=[];indirect=[]
        for line in code.splitlines():
            m=re.match(r'^\s*([\da-fA-F]+):\s+(callq?|bl|blr|jmpq?|b)\s+(.+)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2];operand=m[3];target=None
            t=re.match(r'(?:0x)?([\da-fA-F]+)\b',operand)
            if t and op!='blr':
                dest=int(t[1],16)
                if a<=dest<z:continue
                target=lookup.get(dest,stubs.get(dest,operand))
            else:
                # On x86 PIC, follow the GOT relocation to the actual library symbol.
                slot=re.search(r'#\s*(?:0x)?([\da-fA-F]+)\b',operand)
                if slot:target=lookup.get(reloc.get(int(slot[1],16)))
                if target is None:indirect.append([pc,operand])
            if target and any(s in target for s in ('hex_decode','hex_check','diagnos','reserve','memset','memcpy','bzero','caller_boundary','append_callsite::sample')):
                edges.append([pc,op,target])
        selected[label+'@'+hex(a)]={'bytes':z-a,'edges':edges,'unresolved_indirect':indirect}
    assert selected,img
    return selected
data={}
for role in ('pr','pr_inline','scoped','ordinary','extend','grouped','staged','array'):
    for b in ('append_call','append_callsite'):
        data[role+'/'+b]=record(out/(role+'-'+b))
(out/'append-linkage.json').write_text(json.dumps(data,indent=2))
