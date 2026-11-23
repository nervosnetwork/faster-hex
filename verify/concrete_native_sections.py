"""Record the loaded bytes and addresses of the selected codec and downstream functions."""
from pathlib import Path
import hashlib,json,re,struct,subprocess as sp,sys
def inspect(path):
 blob=path.read_bytes();assert blob[:6]==b'\x7fELF\x02\x01'
 off,=struct.unpack_from('<Q',blob,40);step,count,names=struct.unpack_from('<HHH',blob,58)
 sections=[struct.unpack_from('<IIQQQQIIQQ',blob,off+i*step) for i in range(count)]
 row=sections[names];tab=blob[row[4]:row[4]+row[5]]
 regions=[]
 for s in sections:
    if s[2]&2 and s[1]!=8:regions.append((s[3],s[3]+s[5],s[4],tab[s[0]:].split(b'\0',1)[0].decode()))
 found={}
 for l in sp.check_output(['nm','-n','-S','--defined-only',path],text=True).splitlines():
    m=re.match(r'^([0-9a-f]+)\s+([0-9a-f]+)\s+\w\s+(\S+)$',l)
    if not m:continue
    addr,size=int(m[1],16),int(m[2],16);sym=m[3]
    if not size or not any(k in sym for k in ('decode_diagnosed','decode_appended_error','UNHEX17h','UNHEX_LOWER17h','UNHEX_UPPER17h','UNHEX417h','write_escaped_str','validate_utf8','read4char')):continue
    limits=[region for region in regions if region[0]<=addr and addr+size<=region[1]];assert len(limits)==1,(path,sym,addr,size)
    begin,_,pos,sec=limits[0];raw=blob[pos+addr-begin:pos+addr-begin+size];assert len(raw)==size
    found[sym]=dict(addr=addr,size=size,section=sec,sha=hashlib.sha256(raw).hexdigest())
 return found
def record(folder,images):
 if not sys.platform.startswith('linux'):return
 target=Path(folder)
 ops={'qualified_decode','vec_read_slice','array_read_slice','vec_round_slice','owned_blocks','validate_call','append_call'}
 result={key:inspect(target/key.replace('/','-')) for key in images if key.split('/')[1] in ops}
 (target/'recovery-codegen.json').write_text(json.dumps(result,sort_keys=True))


def owned_calls(folder, images):
 if not sys.platform.startswith('linux'):return
 # Capture the timed consumer itself, including inlined code for fixed-size arrays.
 target=Path(folder);result={}
 for role in ('release','version','pr','scoped','concrete','entries','boundary'):
    key=role+'/owned_blocks';assert key in images
    path=target/key.replace('/','-');symbols=[]
    for line in sp.check_output(['nm','-n','-S','-C','--defined-only',path],text=True).splitlines():
        match=re.match(r'^([0-9a-f]+)\s+([0-9a-f]+)\s+[tT]\s+(owned_blocks::.+)$',line)
        if not match:continue
        address,size=int(match[1],16),int(match[2],16)
        listing=sp.check_output(['objdump','-d','-w','-C','--start-address='+str(address),'--stop-address='+str(address+size),path],text=True)
        symbols.append(dict(symbol=match[3],address=address,size=size,disassembly=listing.split('Disassembly of section .text:',1)[-1].strip()))
    assert symbols,key
    result[role]=symbols
 (target/'owned-caller-instructions.json').write_text(json.dumps(result,sort_keys=True))
