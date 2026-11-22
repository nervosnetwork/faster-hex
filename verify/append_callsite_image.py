"""Record the compiled call sites separately from the paired timings."""
from pathlib import Path
import json
import os
import re
import subprocess as sp
import sys

work = Path(os.environ.get("PACKAGED_WORK", Path(__file__).resolve().parents[1]/"real")).resolve()
mode = os.environ.get("CARGO_PROFILE_RELEASE_LTO", "default")
out = work/"qualification"/mode

def run(args):
    return sp.check_output(args,text=True)

def record(img):
    symbols=[]
    for row in run(["nm","-a","-n","-C",img]).splitlines():
        m=re.match(r"^([0-9a-fA-F]+)\s+([Tt])\s+(.+)$",row)
        if m: symbols.append((int(m[1],16),m[3]))
    captured=[]
    for i,(start,name) in enumerate(symbols[:-1]):
        select=("append_callsite::sample" in name or "append_callsite::caller_boundary" in name
                or "faster_hex::decode::hex_decode_append" in name)
        if not select: continue
        end=next((a for a,n in symbols[i+1:] if a>start),None)
        if end is None: continue
        if sys.platform=="darwin":
            cmd=["xcrun","llvm-objdump","-d","--demangle","--start-address="+str(start),"--stop-address="+str(end),img]
        else:
            cmd=["objdump","-d","-C","--start-address="+str(start),"--stop-address="+str(end),img]
        asm=run(cmd)
        indirect=[l.strip() for l in asm.splitlines() if re.search(r"\b(?:blr\s+x\d+|callq?\s+\*(?:%r\w+|[^\n]*\(%r(?:sp|bp)\)))",l)]
        calls=[l.strip() for l in asm.splitlines() if re.search(r"\b(?:bl|b|callq?|jmpq?)\s+",l) and re.search("hex_decode_append|caller_boundary|hex_decode_neon|decode_appended_blocks",l)]
        captured.append(dict(symbol=name,start=start,length=end-start,indirect=indirect,decode_calls=calls))
    return captured

answer={}
for role in ('pr','scoped','ordinary'):
    rows=record(out/(role+'-append_callsite'))
    samples=[r for r in rows if "append_callsite::sample" in r['symbol']]
    assert len(samples)==2,(role,[r['symbol'] for r in rows])
    assert any(r['indirect'] for r in samples),(role,rows)
    answer[role]=rows
(work/'append-callsite-image.json').write_text(json.dumps(answer,indent=2))
