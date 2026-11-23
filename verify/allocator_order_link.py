#!/usr/bin/env python3
"""Relink the final executable, moving exactly one existing Rust object."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess as sp
import sys

def allocations(link_map):
    pattern=(r'^ ([.]text[.]\S+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+) ([^\n]+)\n'
             r'\s*0x[0-9a-f]+\s+__rustc::__rust_(alloc|realloc)$')
    hits={symbol:(obj,int(address,16),int(size,16)) for _,address,size,obj,symbol in re.findall(pattern,link_map,re.M)}
    assert set(hits)=={"alloc","realloc"},hits
    assert hits["alloc"][0]==hits["realloc"][0],hits
    return hits

def functions(image):
    symbols=sp.check_output(["nm","-nS","-C","--defined-only",image],text=True)
    labels=("core::str::converts::from_utf8","vec_round_slice::measure","serde_json::ser::format_escaped_str")
    result={}
    for key in labels:
        match=re.findall(r"^([0-9a-f]+) ([0-9a-f]+) [tT] "+re.escape(key)+"$",symbols,re.M)
        assert len(match)==1,(key,match)
        result[key]=[int(v,16) for v in match[0]]
    return result

def link():
    original=sys.argv[1:]
    cc=os.environ["ORIGINAL_CC"]
    expanded=[x for arg in original for x in (shlex.split(Path(arg[1:]).read_text()) if arg.startswith("@") else [arg])]
    if "-o" not in expanded or not Path(expanded[expanded.index("-o")+1]).name.startswith("vec_round_slice-"):
        os.execv(cc,[cc,*original])
    target=Path(expanded[expanded.index("-o")+1])
    out=Path(os.environ["ALLOCATOR_ORDER_OUTPUT"]);out.mkdir(parents=True,exist_ok=True)
    link_map=out/"input.map"
    def run(args,label):
        sp.run([cc,*args,"-Wl,-Map,"+str(link_map)],check=True)
        saved=out/label;shutil.copy2(target,saved)
        found=allocations(link_map.read_text())
        return {"routines":functions(saved),"allocator_entries":{k:v[1:] for k,v in found.items()}},found["alloc"][0]
    native,filename=run(original,"native")
    select=[a for a in expanded if a.endswith(".o") and Path(a).resolve()==Path(filename).resolve()]
    assert len(select)==1,(filename,select)
    allocator=select[0]
    def preceding(tag):
        choices=[a for a in expanded if a.endswith(".rcgu.o") and tag in Path(a).name]
        assert choices,tag
        return choices[0]
    positions={"before-core":preceding(".addr2line-"),"after-core":preceding(".faster_hex-")}
    results={"native":native}
    for label,anchor in positions.items():
        moved=[arg for arg in expanded if arg!=allocator]
        moved.insert(moved.index(anchor),allocator)
        assert len(moved)==len(expanded)
        assert [a for a in moved if a!=allocator]==[a for a in expanded if a!=allocator]
        copy,_=run(moved,label)
        copy["allocator_arg_before"]=expanded.index(allocator)
        copy["allocator_arg_after"]=moved.index(allocator)
        copy["anchor_object"]=Path(anchor).name
        copy["native_order_already"]=moved==expanded
        if moved==expanded:
            assert (out/"native").read_bytes()==(out/label).read_bytes()
        results[label]=copy
    (out/"link-order.json").write_text(json.dumps(results,indent=2))
    # Return the unaltered product to Cargo for canonical fingerprint checks.
    sp.run([cc,*original],check=True)
    assert target.read_bytes()==(out/"native").read_bytes()

if __name__=="__main__":link()
