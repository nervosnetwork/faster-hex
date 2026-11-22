"""Read-only, predecoded write-only and full field calls, with ownership confirmed separately."""
from cause_common import *
import shutil
import tarfile

work=ROOT/os.environ.get("FIELD_AREA","field-cause-work");out=work/"results";out.mkdir(parents=True,exist_ok=True)
driver=work/"downstream";bins=driver/"src/bin";bins.mkdir(parents=True,exist_ok=True)
codec=work/"codec"; codec.mkdir(exist_ok=True)
(driver/"Cargo.toml").write_text('[package]\nname="field-phase-check"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[dependencies]\nfaster-hex={path="../codec"}\nserde={version="=1.0.229",features=["derive"]}\nserde_json="=1.0.154"\n')
phases=["read_slice","read_reader","write","round_slice","round_reader"]
destinations=["vec","array","optvec","optarray"]
sizes=(32,4096)
def make(name,phase):
    array="array" in name; opt=name.startswith("opt")
    generics="<const N:usize>" if array else ""
    inst="Field<N>" if array else "Field"
    ty="[u8;N]" if array else "Vec<u8>"
    adapter="faster_hex"+("::option_withpfx_ignorecase" if opt else "")+("::array" if array else "")
    if opt:ty="Option<"+ty+">"
    derive="serde::Serialize" if phase=="write" else "serde::Deserialize" if phase.startswith("read") else "serde::Deserialize,serde::Serialize"
    get="value.bytes.as_ref().unwrap().as_slice()" if opt else "value.bytes.as_slice()"
    owned="expected.as_slice().try_into().unwrap()" if array else "expected.clone()"
    if opt:owned="Some("+owned+")"
    setup="";op=""
    run="fn measure<const N:usize>(kind:&str,n:usize,count:usize)->f64" if array else "fn measure(kind:&str,n:usize,count:usize)->f64"
    if array:setup+="assert_eq!(N,n);"
    if phase=="write":
        setup+=f"let value:{inst}=Field{{bytes:{owned}}};assert_eq!(serde_json::to_vec(&value).unwrap(),canonical.as_bytes());"
        op="dst.clear();serde_json::to_writer(&mut dst,black_box(&value)).unwrap();black_box(dst.as_slice());"
    else:
        parse="from_reader" if phase.endswith("reader") else "from_slice"
        read=f"let value:{inst}=serde_json::{parse}(black_box(json.as_bytes())).unwrap();"
        setup+="{"+read+f"assert_eq!({get},expected.as_slice());"
        if phase.startswith("round"):setup+="assert_eq!(serde_json::to_vec(&value).unwrap(),canonical.as_bytes());"
        setup+="}"
        op=read+("dst.clear();serde_json::to_writer(&mut dst,&value).unwrap();black_box(dst.as_slice());" if phase.startswith("round") else "black_box(value);")
    call="match n{32=>measure::<32>(kind,n,k),4096=>measure::<4096>(kind,n,k),_=>unreachable!()}" if array else "measure(kind,n,k)"
    return '''#![allow(unused_mut,unused_variables)]
use std::{hint::black_box,time::Instant};
#[derive(DERIVE)]
struct FieldGEN {#[serde(with="ADAPT")]bytes:TYPE}
RUN{
 let expected:Vec<u8>=(0..n).map(|i|(37*i+11)as u8).collect();
 let digits=expected.iter().map(|b|format!("{b:02x}")).collect::<String>();
 let alt=expected.iter().enumerate().map(|(i,b)| if i%3==0{format!("{b:02X}")}else{format!("{b:02x}")}).collect::<String>();
 let canonical=format!(r#"{{"bytes":"0x{digits}"}}"#);
 let json=if kind=="escaped"{format!(r#"{{"bytes":"\\u0030x{alt}"}}"#)}else{format!(r#"{{"bytes":"0x{alt}"}}"#)};
 let mut dst=Vec::<u8>::with_capacity(canonical.len());
 SETUP
 let start=Instant::now();for _ in 0..count{OP}
 start.elapsed().as_nanos()as f64/count as f64
}
fn main(){let a:Vec<_>=std::env::args().collect();let n=a[1].parse().unwrap();let k:usize=a[2].parse().unwrap();let kind=a[3].as_str();let run=|k|CALL;black_box(run((k/6).max(16)));println!("{:.6}",run(k));}
'''.replace("DERIVE",derive).replace("GEN",generics).replace("ADAPT",adapter).replace("TYPE",ty).replace("RUN",run).replace("SETUP",setup).replace("OP",op).replace("CALL",call)
for dest in destinations:
    for phase in phases:(bins/(dest+"_"+phase+".rs")).write_text(make(dest,phase))
(bins/"ownership.rs").write_text(r'''
use serde::{Deserialize,Deserializer,de::{Error,Visitor}};
use std::fmt;
#[derive(Debug,PartialEq)]enum How{Borrowed,Temporary,Owned}
impl<'de> Deserialize<'de> for How{
 fn deserialize<D:Deserializer<'de>>(d:D)->Result<Self,D::Error>{
 struct Probe;
 impl<'de> Visitor<'de> for Probe{type Value=How;
 fn expecting(&self,f:&mut fmt::Formatter)->fmt::Result{f.write_str("hex text")}
 fn visit_borrowed_str<E:Error>(self,_:&'de str)->Result<How,E>{Ok(How::Borrowed)}
 fn visit_str<E:Error>(self,_:&str)->Result<How,E>{Ok(How::Temporary)}
 fn visit_string<E:Error>(self,_:String)->Result<How,E>{Ok(How::Owned)}}
 d.deserialize_string(Probe)
 }}
fn main(){#[derive(Deserialize)]struct F{bytes:How}
 let p=br#"{"bytes":"0xab"}"#;let e=br#"{"bytes":"\u0030xab"}"#;
 assert_eq!(serde_json::from_slice::<F>(p).unwrap().bytes,How::Borrowed);
 assert_eq!(serde_json::from_slice::<F>(e).unwrap().bytes,How::Temporary);
 assert_eq!(serde_json::from_reader::<_,F>(&p[..]).unwrap().bytes,How::Temporary);
}
''')
if os.getenv("FIELD_DRIVERS_ONLY"):
    sys.exit(0)
smoke=bool(os.environ.get("CAUSE_SMOKE"))
profiles=os.environ.get("CARGO_PROFILE_BENCH_LTO","false")
roles=["base","head","old-serde"]
sections={}
for role in roles:
    rev=BASE if role=="base" else HEAD
    archive=work/"source.tar"
    sp.run(["git","archive","-o",archive,rev],cwd=ROOT,check=True)
    if codec.exists():shutil.rmtree(codec)
    codec.mkdir();sp.run(["tar","-xf",archive,"-C",codec],check=True)
    if role=="old-serde":
        (codec/"src/serde.rs").write_bytes(sp.check_output(["git","show",BASE+":src/serde.rs"],cwd=ROOT))
    target=work/("target-"+role)
    env=dict(os.environ,CARGO_TARGET_DIR=str(target),CARGO_PROFILE_RELEASE_LTO=profiles)
    sp.run(["cargo","build","--quiet","--release","--bins"],cwd=driver,env=env,check=True)
    sp.run([target/"release/ownership"],check=True)
    for d in destinations:
        for p in phases:
            name=d+"_"+p; sections[role+"/"+name]=section(target/"release"/name)
save(out/"sections.json",sections)
host=sp.check_output(["lscpu"],text=True) if sys.platform=="linux" else os.uname().machine
(out/"host.txt").write_text(host+"\n"+sp.check_output(["rustc","-vV"],text=True))
shutil.copy2(driver/"Cargo.lock",out/"Cargo.lock")
pin()
site=work/"same-field-image";cases=[]
for d in destinations:
    for p in phases:
        for size in sizes:
            for kind in (("plain","escaped") if p.endswith("slice") else ("reader",) if p.endswith("reader") else ("prebuilt",)):
                cases.append((d,p,size,kind))
rng=random.Random(62415)
rng.shuffle(cases)
rows={};summary={}
for d,p,n,kind in cases:
    name=d+"_"+p;key=f"{d}/{p}/{n}/{kind}"
    def sample(role,k):
        image=work/("target-"+("base" if role=="aa" else role))/"release"/name
        return measure(site,image,[n,k,kind],driver)
    count=10 if smoke else max(250,min(2000000,round(9_000_000/max(1,sample("base",3500)))))
    data=[]
    for cycle in range(2 if smoke else 20):
        order=[*roles,"aa"];rng.shuffle(order)
        scores={r:[] for r in order}
        for r in order+order[::-1]:scores[r].append(sample(r,count))
        data.append({r:statistics.mean(s) for r,s in scores.items()})
    rows[key]=data
    summary[key]={name:compare(data,a,b) for name,a,b in [("pair","base","head"),("source","old-serde","head"),("revert","base","old-serde"),("aa","base","aa")]}
    save(out/"fields.json",summary)
    save(out/"samples.json",rows)
    if not smoke:print(key,round(100*(summary[key]["pair"]["ratio"]-1),2),flush=True)
