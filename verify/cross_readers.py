from cause_common import *
import shutil

work=ROOT/os.environ.get("CROSS_AREA","crossed-readers")
app=work/"driver";(app/"src").mkdir(exist_ok=True,parents=True)
out=work/"results";out.mkdir(exist_ok=True)
(app/"src/main.rs").write_bytes((ROOT/"verify/common_json_writer.rs").read_bytes())
(app/"src/bin").mkdir(exist_ok=True)
(app/"src/bin/same-parser.rs").write_bytes((ROOT/"verify/common_json_reader.rs").read_bytes())
(app/"Cargo.toml").write_text('[package]\nname="same-json-writer"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[dependencies]\nleft={package="faster-hex-left",path="../left"}\nright={package="faster-hex",path="../right"}\nserde={version="=1.0.229",features=["derive"]}\nserde_json="=1.0.154"\n')
smoke=bool(os.environ.get("CROSS_SMOKE"))
results={};raw={};pin()
for name,l,r in [("forward",BASE,HEAD),("reverse",HEAD,BASE)]:
    for rel,rev in [("left",l),("right",r)]:
        path=work/rel;path.mkdir(exist_ok=True)
        tar=work/"source.tar"
        sp.run(["git","archive","-o",tar,rev],cwd=ROOT,check=True)
        sp.run(["tar","-xf",tar,"-C",path],check=True)
        if rel=="left":
            manifest=path/"Cargo.toml";text=manifest.read_text()
            assert text.count('name = "faster-hex"')==1
            manifest.write_text(text.replace('name = "faster-hex"','name = "faster-hex-left"'))
    target=work/("target-"+name)
    env=dict(os.environ,CARGO_TARGET_DIR=str(target),CARGO_PROFILE_RELEASE_LTO=os.environ.get("CARGO_PROFILE_BENCH_LTO","false"))
    sp.run(["cargo","build","--release","--bins","--quiet"],cwd=app,env=env,check=True)
    exe=target/"release/same-json-writer"
    syms=sp.check_output(["nm","-n",exe],text=True)
    assert len([l for l in syms.splitlines() if l.split() and l.split()[-1] in ("common_json_writer","_common_json_writer")])==1
    for dest in ("vec","array"):
        for kind in ("plain","escaped","reader"):
            site=work/"same-writer-program";site.unlink(missing_ok=True);os.link(exe,site)
            n=30 if smoke else (1800 if kind!="reader" else 650)
            cycles=2 if smoke else 20
            data=sp.check_output([site,dest,kind,str(n),str(cycles)],cwd=app,text=True)
            rows=[list(map(float,line.split())) for line in data.splitlines()]
            assert len(rows)==cycles and all(len(row)==12 for row in rows)
            key=f"{name}/{dest}/{kind}"; raw[key]=rows
            record={}
            for i,label in enumerate(("roundtrip","write_fresh","write_fixed_address","read_only")):
                base,cand=(i*3,i*3+1) if name=="forward" else (i*3+1,i*3)
                record[label]={"pair":compare(rows,base,cand),"self":compare(rows,i*3,i*3+2)}
            parser=work/"same-parser-program";parser.unlink(missing_ok=True);os.link(target/"release/same-parser",parser)
            values=sp.check_output([parser,dest,kind,str(n),str(cycles)],cwd=app,text=True)
            mapped=[list(map(float,line.split())) for line in values.splitlines()]
            assert len(mapped)==cycles and all(len(row)==6 for row in mapped)
            raw[key+"/shared_parser"]=mapped
            for i,label in enumerate(("same_parser","direct_visitor")):
                base,cand=(i*3,i*3+1) if name=="forward" else (i*3+1,i*3)
                record[label]={"pair":compare(mapped,base,cand),"self":compare(mapped,i*3,i*3+2)}
            results[key]=record
            save(out/"common-writer.json",results);save(out/"samples.json",raw)
            print(key,{k:round((v["pair"]["ratio"]-1)*100,2) for k,v in record.items()},flush=True)
(out/"host.txt").write_text((sp.check_output(["lscpu"],text=True) if sys.platform=="linux" else os.uname().machine)+"\n"+sp.check_output(["rustc","-vV"],text=True))
