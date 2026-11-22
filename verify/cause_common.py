from pathlib import Path
import hashlib
import json
import os
import random
import statistics
import struct
import subprocess as sp
import sys

ROOT = Path(__file__).resolve().parent.parent
BASE = "25cfd8eb6a4cd8257a96fabaf73771cabcced4b4"
HEAD = "9fa6d71209957bd5e03c8f6ff39bb3fd59ac8685"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def save(path, obj):
    path.parent.mkdir(exist_ok=True, parents=True)
    path.write_text(json.dumps(obj, indent=2))

def section(exe, name=".text"):
    data = exe.read_bytes()
    if data[:4] == b"\x7fELF":
        assert data[4:6] == b"\x02\x01"
        off, = struct.unpack_from("<Q",data,40)
        size,count,strings=struct.unpack_from("<HHH",data,58)
        rows=[struct.unpack_from("<IIQQQQIIQQ",data,off+i*size) for i in range(count)]
        stringtab=data[rows[strings][4]:rows[strings][4]+rows[strings][5]]
        for label,_,_,vma,start,length,*_ in rows:
            if stringtab[label:].split(b"\0",1)[0].decode() == name:
                return [vma,length,sha(data[start:start+length])]
    else:
        assert name==".text" and data[:4]==b"\xcf\xfa\xed\xfe"
        cursor=32
        for _ in range(struct.unpack_from("<I",data,16)[0]):
            tag,size=struct.unpack_from("<II",data,cursor)
            if tag==0x19:
                for i in range(struct.unpack_from("<I",data,cursor+64)[0]):
                    label,seg,vma,length,start=struct.unpack_from("<16s16sQQI",data,cursor+72+80*i)
                    if label.rstrip(b"\0")==b"__text" and seg.rstrip(b"\0")==b"__TEXT":
                        return [vma,length,sha(data[start:start+length])]
            cursor+=size
    raise ValueError((exe,name))

def measure(site, image, args, cwd):
    site.unlink(missing_ok=True)
    os.link(image,site)
    assert site.samefile(image)
    return float(sp.check_output([site,*map(str,args)],cwd=cwd,text=True))

def pin():
    if hasattr(os,"sched_setaffinity"):
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})

def compare(rows, left, right):
    ratios=[row[right]/row[left] for row in rows]
    rng=random.Random(59271)
    boot=sorted(statistics.median(rng.choices(ratios,k=len(ratios))) for _ in range(4000))
    return dict(base_ns=statistics.median(row[left] for row in rows),
                candidate_ns=statistics.median(row[right] for row in rows),
                ratio=statistics.median(ratios),lo=boot[99],hi=boot[3899])
