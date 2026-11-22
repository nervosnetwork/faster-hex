"""Cross the writer and reader instruction positions in the same compiled application."""
from cause_common import *
import itertools
import re
import shutil

work=ROOT/"consumer-work"; out=ROOT/"results/cause"; out.mkdir(exist_ok=True,parents=True)
pin()
driver=work/"downstream"
grid=list(itertools.product((0,16,32,48),repeat=2))
symbols={"read":"skip_to_escape","write":"format_escaped_str"}

def inspect(exe, assembly_dir=None):
    full=sp.check_output(["nm","-n","--defined-only",exe],text=True)
    sized=sp.check_output(["nm","-nS","--defined-only",exe],text=True)
    all_symbols={}
    chosen={}
    for line in full.splitlines():
        parts=line.split(maxsplit=2)
        if len(parts)!=3:continue
        addr,kind,name=parts
        if kind.lower() in ("t","w","r","d","b") and name not in ("__probe_w","__probe_r"):
            all_symbols[name]=int(addr,16)
    for key,substring in symbols.items():
        rows=[s.split() for s in sized.splitlines() if re.search(substring+r"17h[0-9a-f]+E",s) and re.search(r"\s[tTwW]\s",s)]
        assert len(rows)==1,(exe,key,rows)
        address,size,_,name=rows[0];address,size=int(address,16),int(size,16)
        assert all_symbols.pop(name)==address
        raw=sp.check_output(["objdump","-dC","--no-show-raw-insn",f"--start-address={address}",f"--stop-address={address+size}",exe],text=True)
        normalized=[]
        for line in raw.splitlines():
            m=re.match(r"\s*([0-9a-f]+):\s+(.+)",line)
            if not m:continue
            ins=m[2].split("#")[0].strip()
            ins=re.sub(r"-?(?:0x)?[0-9a-f]+\(%rip\)","<data>(%rip)",ins)
            j=re.match(r"((?:j\w+|callq?|jmpq?)\s+)([0-9a-f]+)\s+<([^>]+)>",ins)
            if j:
                at=int(j[2],16)
                dest=hex(at-address) if address<=at<address+size else re.sub(r"(?:\.llvm\.\d+|::h[0-9a-f]{16})","",j[3])
                ins=j[1]+dest
            normalized.append(ins)
        chosen[key]=dict(start=address,offset=address%64,size=size,ops=sha("\n".join(normalized).encode()))
        if assembly_dir:
            (out/(assembly_dir+"-"+key+".asm")).write_text(raw)
            (out/(assembly_dir+"-"+key+"-opcodes.txt")).write_text("\n".join(normalized))
    chosen["other_symbols"]=[len(all_symbols),sha(json.dumps(all_symbols,sort_keys=True).encode())]
    chosen["rodata"]=section(exe,".rodata")
    chosen["text"]=section(exe)
    return chosen

# Remove only the new Serde adapter, keeping the candidate's decoder and CPU dispatch.
serde_file=work/"codec/src/serde.rs"
old=sp.check_output(["git","show",BASE+":src/serde.rs"],cwd=ROOT)
new=sp.check_output(["git","show",HEAD+":src/serde.rs"],cwd=ROOT)
assert serde_file.read_bytes()==new
def writers(src):
    lines=src.decode().splitlines(keepends=True);bodies=[]
    for i,line in enumerate(lines):
        match=re.match(r"^( *)(?:pub(?:\(crate\))? )?fn (?:serialize|serialize_option)\b",line)
        if match:
            j=next(j for j in range(i+1,len(lines)) if lines[j].rstrip("\n")==match[1]+"}")
            bodies.append("".join(lines[i:j+1]))
    return bodies
assert len(writers(old))==6 and writers(old)==writers(new)
serde_file.write_bytes(old)
env=dict(os.environ,CARGO_TARGET_DIR=str(work/"target"),CARGO_PROFILE_RELEASE_LTO=os.environ["CARGO_PROFILE_BENCH_LTO"])
env.pop("JSON_LINK_OUTPUT",None)
for cmd in (["cargo","clean","--release","-p","faster-hex","-p","consumer-timing"],["cargo","build","--locked","--release","--bins","--quiet"]):
    sp.run(cmd,cwd=driver,env=env,check=True)
revert=work/"old-serde";revert.mkdir(exist_ok=True)
for name in ("mixed","escapedmixed"):shutil.copy2(work/"target/release"/name,revert/name)

for case in ("mixed","escapedmixed"):
    images={};info={};ordinary={}
    for role in ("base","head","old-serde"):
        label=role+"/ordinary";images[label]=work/role/case;ordinary[role]=inspect(images[label],case+"-"+role)
        info[label]=ordinary[role]
        if role=="old-serde":continue
        other=set();locations=set();roparts=set()
        for r,w in grid:
            label=f"{role}/r{r}w{w}"
            images[label]=work/("link-"+role)/f"{case}-r{r}w{w}"
            rec=inspect(images[label]);info[label]=rec
            assert (rec["read"]["offset"],rec["write"]["offset"])==(r,w),(label,rec)
            other.add(tuple(rec["other_symbols"]));roparts.add(tuple(rec["rodata"]))
            locations.add((rec["read"]["start"]-r,rec["write"]["start"]-w))
        assert len(other)==len(locations)==1,(case,role,"uncontrolled symbol movement",len(other),locations)
        print(case,role,"distinct read-only sections",len(roparts),"base addresses",locations,flush=True)
    save(out/(case+"-images.json"),info)
    rng=random.Random(43611);site=work/"same-json-image";rows=[]
    n=max(1200,round(12500000/measure(site,images["base/ordinary"],[4096,5000],driver)))
    images["aa"]=images["base/ordinary"];images["bb"]=images["head/ordinary"]
    for cycle in range(20):
        seq=list(images);rng.shuffle(seq);samples={s:[] for s in seq}
        for label in seq+seq[::-1]:
            samples[label].append(measure(site,images[label],[4096,n],driver))
        rows.append({label:statistics.mean(times) for label,times in samples.items()})
    save(out/(case+"-samples.json"),rows)
    a=ordinary["base"];b=ordinary["head"]
    ar,aw=a["read"]["offset"],a["write"]["offset"];br,bw=b["read"]["offset"],b["write"]["offset"]
    assert (ar,aw) in grid and (br,bw) in grid,(case,ar,aw,br,bw)
    pairs={"ordinary":("base/ordinary","head/ordinary"),"source_control":("base/ordinary","old-serde/ordinary"),
           "serde_only":("old-serde/ordinary","head/ordinary"),"aa":("base/ordinary","aa"),"bb":("head/ordinary","bb"),
           "cross_natural_offsets":(f"base/r{ar}w{aw}",f"head/r{br}w{bw}")}
    for r,w in grid:pairs[f"held/r{r}w{w}"]=(f"base/r{r}w{w}",f"head/r{r}w{w}")
    for role in ("base","head"):
        for r,w in grid:
            pairs[f"{role}/writer/r{r}w{w}"]=(f"{role}/r{r}w0",f"{role}/r{r}w{w}")
            pairs[f"{role}/reader/r{r}w{w}"]=(f"{role}/r0w{w}",f"{role}/r{r}w{w}")
    result={k:compare(rows,*both) for k,both in pairs.items()}
    save(out/(case+"-result.json"),result)
    print(case,"normal positions",ar,aw,br,bw,result["ordinary"],flush=True)
