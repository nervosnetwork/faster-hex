#!/usr/bin/env python3
"""Relink the same object files with the sampled lowercase caller in a fixed-size slot."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess as sp
import sys

def nm(image):
    rows=[]
    for line in sp.check_output(["nm","-nS","--defined-only",image],text=True).splitlines():
        m=re.match(r"^([0-9a-f]+) ([0-9a-f]+) ([tTwW]) (.+)$",line)
        if m:rows.append((int(m[1],16),int(m[2],16),m[4]))
    return rows

def file_bytes(image,addr,length):
    data=image.read_bytes()
    assert data[:6]==b"\x7fELF\x02\x01"
    hdr=struct.unpack_from("<Q",data,32)[0]
    size,count=struct.unpack_from("<HH",data,54)
    for i in range(count):
        kind,flags,off,start,_,n,*_=struct.unpack_from("<IIQQQQQQ",data,hdr+i*size)
        if kind==1 and start<=addr and addr+length<=start+n:
            return data[off+addr-start:off+addr-start+length]
    raise ValueError((addr,length))

def ascii_callers(path,role):
    expected=[0x1bd234,0x1ce64c if role=="base" else 0x1ce604]
    result={}
    symbols=nm(path)
    for address in expected:
        sym,=[x for x in symbols if x[0]==address and 'Bencher' in x[2]]
        dis=sp.check_output(["objdump","-d","--start-address="+str(address+0x64),
                             "--stop-address="+str(address+0x78),path],text=True)
        pg=int(re.search(r"adrp\s+x8,\s*([0-9a-f]+)",dis)[1],16)
        imm=int(re.search(r"ldr\s+q4,\s*\[x8,\s*#(0x[0-9a-f]+|[0-9]+)\]",dis)[1],0)
        table=file_bytes(path,pg+imm,16).decode("ascii")
        assert table in ("0123456789abcdef","0123456789ABCDEF") and table not in result,table
        result[table]={"symbol":sym[2],"address":address,"length":sym[1],"table_address":pg+imm}
    assert len(result)==2
    return result

def main():
    cc=os.environ["ORIGINAL_CC"];original=sys.argv[1:]
    args=[x for arg in original for x in (shlex.split(Path(arg[1:]).read_text()) if arg.startswith("@") else [arg])]
    if "-o" not in args or not re.fullmatch(r"hex-[0-9a-f]+",Path(args[args.index("-o")+1]).name):
        os.execv(cc,[cc,*original])
    out=Path(os.environ["CALLER_OUTPUT"]);role=os.environ["CALLER_ROLE"]
    out.mkdir(parents=True,exist_ok=True)
    ex=Path(args[args.index("-o")+1]);mapp=out/'native.map'
    sp.run([cc,*original,"-Wl,-Map,"+str(mapp)],check=True)
    shutil.copy2(ex,out/'native')
    tables=ascii_callers(out/'native',role)
    routine=tables['0123456789abcdef']
    name=routine['symbol']
    # These are the two original instruction addresses of one lowercase/uppercase pair.
    # If the sampled lowercase caller already has one address, the second site only tests sensitivity.
    if routine['address'] in [0x1ce64c,0x1ce604]:
        sites={"old":0x1ce64c,"new":0x1ce604}
        shared=False
    else:
        assert routine['address']==0x1bd234
        sites={"old":0x1bd234,"new":0x1bd234+72}
        shared=True
    normals=nm(out/'native')
    other_symbols=[]
    for key,target in sites.items():
        pg=target & ~4095;off=target-pg
        assert off+routine["length"]<=4096
        ld=out/(key+".ld")
        ld.write_text(f"SECTIONS {{ .fxcaller {pg:#x} : {{ . = {off:#x}; KEEP(*(.text.{name} .text.{name}.*)) . = 0x1000; }} }} INSERT BEFORE .text;\n")
        sp.run([cc,*original,"-Wl,-T,"+str(ld)],check=True)
        im=out/key;shutil.copy2(ex,im)
        symbols=nm(im)
        matched,=[x for x in symbols if x[2]==name]
        assert matched[:2]==(target,routine["length"]),(matched,target,name)
        other_symbols.append(Counter(x for x in symbols if x[2]!=name and not x[2].startswith(('$x','$d'))))
    assert other_symbols[0]==other_symbols[1],list((other_symbols[0]-other_symbols[1]).elements())[:12]
    data={"tables":tables,"sites":sites,"original_sites_already_match":shared,
          "other_function_addresses_checked":sum(other_symbols[0].values())}
    (out/'layout.json').write_text(json.dumps(data,indent=2)+'\n')
    sp.run([cc,*original],check=True)
    assert ex.read_bytes()==(out/'native').read_bytes()
if __name__=="__main__":main()
