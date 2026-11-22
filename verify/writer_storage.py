"""Compare the original writer with the same bytes, JSON buffer, and hex scratch buffer."""
from cause_common import *
import shutil

work=ROOT/os.getenv("WRITER_AREA","writer-buffer-work")
out=work/"results"; out.mkdir(parents=True,exist_ok=True)
app=work/"app";bins=app/"src/bin";bins.mkdir(parents=True,exist_ok=True)
primary=(ROOT/"verify/common_json_writer.rs").read_text()
(app/"src/main.rs").write_text(primary)
start=primary.index("#[inline(never)]\nfn measure")
stop=primary.index("fn as_seed",start)
(bins/"fixed-scratch.rs").write_text(primary[:start]+(ROOT/"verify/writer_storage.rs").read_text()+primary[stop:])
(app/"Cargo.toml").write_text('[package]\nname="same-json-writer"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[dependencies]\nleft={package="faster-hex-left",path="../left"}\nright={package="faster-hex",path="../right"}\nserde={version="=1.0.229",features=["derive"]}\nserde_json="=1.0.154"\n')
smoke=bool(os.getenv("WRITER_SMOKE"))
pin()
summary={};samples={};checks={}
for side,a,b in [("forward",BASE,HEAD),("reverse",HEAD,BASE)]:
    for dirname,rev in [("left",a),("right",b)]:
        path=work/dirname;path.mkdir(exist_ok=True)
        archive=work/"product.tar"
        sp.run(["git","archive","-o",archive,rev],cwd=ROOT,check=True)
        sp.run(["tar","-xf",archive,"-C",path],check=True)
        if dirname=="left":
            m=path/"Cargo.toml"; txt=m.read_text(); assert txt.count('name = "faster-hex"')==1
            m.write_text(txt.replace('name = "faster-hex"','name = "faster-hex-left"'))
    target=work/("target-"+side)
    env=dict(os.environ,CARGO_TARGET_DIR=str(target))
    sp.run(["cargo","build","--release","--quiet","--bins"],cwd=app,env=env,check=True)
    save(out/(side+"-sections.json"),{n:section(target/"release"/n) for n in ("same-json-writer","fixed-scratch")})
    base,cand=(0,1) if side=="forward" else (1,0)
    for dest in ("vec","array"):
        for kind in ("plain","escaped","reader"):
            key=f"{side}/{dest}/{kind}"
            cycles=2 if smoke else 18
            count=5 if smoke else (720 if kind!="reader" else 320)
            def run(name):
                image=target/"release"/name
                symbols=sp.check_output(["nm","-n",image],text=True)
                assert sum(x.endswith((" common_json_writer"," _common_json_writer")) for x in symbols.splitlines())==1
                site=work/"same-program";site.unlink(missing_ok=True);os.link(image,site)
                return sp.check_output([site,dest,kind,str(count),str(cycles)],text=True).splitlines()
            original=[list(map(float,l.split())) for l in run("same-json-writer")]
            assert len(original)==cycles and len(original[0])==12
            result={label:compare(original,6+x,6+y) for label,x,y in [("unchanged",base,cand),("unchanged_self",0,2)]}
            recorded=run("fixed-scratch")
            head=recorded[0].split()
            assert head[0]=="meta" and len(head)==6
            arms=head[-1].split(",")
            rows=[list(map(float,s.split()[1:])) for s in recorded if s.startswith("row ")]
            assert len(rows)==cycles and len(rows[0])==len(arms)*3
            hist=[s for s in recorded if s.startswith("hist ")]
            assert len(hist)==len(arms)*3
            meta=dict(left=int(head[1]),right=int(head[2]),output=int(head[3]),input=int(head[4]),
                      placements=arms,system_histograms=hist,allocs=recorded[-1])
            assert meta["allocs"].startswith("allocs ")
            for i,arm in enumerate(arms):
                result[arm]=compare(rows,i*3+base,i*3+cand)
                result[arm+"/self"]=compare(rows,i*3,i*3+2)
                if i:
                    for keyname,index in (("base",base),("candidate",cand)):
                        result[arm+"/"+keyname+"_vs_natural"]=compare(rows,index,i*3+index)
            samples[key]=dict(original=original,probed=rows);summary[key]=result;checks[key]=meta
            for name,value in (("times",summary),("samples",samples),("addresses",checks)):save(out/(name+".json"),value)
            print(key,head[1:],{k:round((v["ratio"]-1)*100,1) for k,v in result.items() if "/" not in k},flush=True)
(out/"host.txt").write_text((sp.check_output(["lscpu"],text=True) if sys.platform=="linux" else os.uname().machine)+"\n"+sp.check_output(["rustc","-vV"],text=True))
