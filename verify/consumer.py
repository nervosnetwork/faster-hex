"""Independent downstream executables; one operation per binary and the same source path for both revisions."""
from pathlib import Path
from build_variant import select
import gzip,hashlib,json,math,os,platform,random,re,shutil,statistics,subprocess,sys
root=Path.cwd()
work=Path(os.environ.get("STUDY_WORK","consumer-work")).absolute()
out=Path(os.environ.get("RESULTS","results")).absolute()
work.mkdir(exist_ok=True,parents=True);out.mkdir(exist_ok=True,parents=True)
source=work/'codec';driver=work/'downstream'
driver.mkdir(exist_ok=True);bins=driver/'src/bin';bins.mkdir(exist_ok=True,parents=True)
env=dict(os.environ,CARGO_TARGET_DIR=str(work/'target'))
if (lto:=os.environ.get("CARGO_PROFILE_BENCH_LTO")): env["CARGO_PROFILE_RELEASE_LTO"]=lto
pin=["taskset","-c",str(min(os.sched_getaffinity(0)))] if sys.platform=="linux" else []
def output(a,**kwargs): return subprocess.check_output(a,env=env,text=True,**kwargs)
def run(a,**kwargs): return subprocess.run(a,env=env,check=True,**kwargs)
base=os.environ.get("REFERENCE_REV","25cfd8eb6a4cd8257a96fabaf73771cabcced4b4")
head=os.environ["PRODUCT_REV"]
cases={"encode":[8,32],"owned_string":[32],"decode":[4,32],"prefix":[12],
       "serialize":[10,32,256],"deserialize":[10,32],"field4":[4],"field4096":[4096]}
ops={
"encode":('','faster_hex::hex_encode(black_box(&bytes), black_box(&mut dst)).unwrap(); black_box(&dst);'),
"owned_string":('','black_box(faster_hex::hex_string(black_box(&bytes)));'),
"decode":('','faster_hex::hex_decode(black_box(&hex),black_box(&mut dst[..n])).unwrap(); black_box(&dst);'),
"prefix":('','black_box(faster_hex::Hex::new(black_box(&bytes)).leading_digits(black_box(n)).encode_to(black_box(&mut dst)).unwrap());'),
"serialize":('#[derive(serde::Serialize)] struct Payload { #[serde(with="faster_hex")] bytes: Vec<u8> }','dst.clear();serde_json::to_writer(&mut dst,black_box(&payload)).unwrap();black_box(&dst);'),
"deserialize":('#[derive(serde::Deserialize)] struct Payload { #[serde(with="faster_hex")] bytes: Vec<u8> }','black_box(serde_json::from_str::<Payload>(black_box(&json)).unwrap());'),
"field4":('','black_box(faster_hex::array::deserialize::<_,4>(serde::de::value::BorrowedStrDeserializer::<serde::de::value::Error>::new(black_box(&field))).unwrap());'),
"field4096":('','black_box(faster_hex::array::deserialize::<_,4096>(serde::de::value::BorrowedStrDeserializer::<serde::de::value::Error>::new(black_box(&field))).unwrap());'),
}
if variant:=os.environ.get("ARRAY_VARIANT"):
 cases={k:v for k,v in cases.items() if k in ["field4","field4096"]}
 cases["optional"]=[32]
 ops["optional"]=('#[derive(serde::Deserialize)] struct Optional(#[serde(with="faster_hex::option_withpfx_ignorecase::array")] Option<[u8;32]>);','black_box(serde_json::from_str::<Optional>(black_box(&optional_json)).unwrap().0.unwrap());')
 for n in [32,4096]:
  opt=f"option{n}"; cases[opt]=[n]
  ops[opt]=(ops["optional"][0].replace("32",str(n)),ops["optional"][1])
  trans=f"transient{n}"; cases[trans]=[n]
  ops[trans]=("",ops["field4096"][1].replace("4096",str(n)).replace("BorrowedStrDeserializer", "StrDeserializer"))
  js=f"json{n}"; cases[js]=[n]
  ops[js]=('#[derive(serde::Deserialize)] struct Required(#[serde(with="faster_hex::array")] [u8;'+str(n)+']);','black_box(serde_json::from_str::<Required>(black_box(&optional_json)).unwrap().0);')
 del cases["optional"]
 for n in [20,32,256,4095,4097,8192]:
  key=f"field{n}";cases[key]=[n]
  ops[key]=(ops["field4096"][0],ops["field4096"][1].replace("4096",str(n)))
 for op,expr in {
  "bad4096":'black_box(faster_hex::array::deserialize::<_,4096>(serde::de::value::BorrowedStrDeserializer::<serde::de::value::Error>::new(black_box("0x00")))).unwrap_err();',
  "error4096":'black_box(faster_hex::array::deserialize::<_,4096>(serde::de::value::BorrowedStrDeserializer::<serde::de::value::Error>::new(black_box("0x00"))).unwrap_err());',
 }.items():
  cases[op]=[4096];ops[op]=("",expr)
 if os.environ.get("FOCUSED_FIELDS"):
  covered={"option32","option4096","field4096","field4095","json32","json4096","transient32","transient4096","bad4096","error4096"}
  cases={k:v for k,v in cases.items() if k in covered}
 if os.environ.get("ESCAPED_ARRAYS"):
  cases={}
  ops={}
  present='''struct Present<D>(D);
impl<'de,D:serde::Deserializer<'de>> serde::Deserializer<'de> for Present<D>{
 type Error=D::Error;
 fn deserialize_any<V:serde::de::Visitor<'de>>(self,v:V)->Result<V::Value,D::Error>{v.visit_some(self.0)}
 serde::forward_to_deserialize_any!{bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any}
}'''
  for n in [32,4096]:
   for opt in [False,True]:
    adapter="faster_hex::option_withpfx_ignorecase::array" if opt else "faster_hex::array"
    ty=f"Option<[u8;{n}]>" if opt else f"[u8;{n}]"
    k=("escapedoption" if opt else "escapedrequired")+str(n)
    defs=f'#[derive(serde::Deserialize)] struct Value(#[serde(with="{adapter}")] {ty});'
    cases[k]=[n];ops[k]=(defs,'black_box(serde_json::from_str::<Value>(black_box(&optional_json)).unwrap().0);')
   k="rawoption"+str(n)
   cases[k]=[n];ops[k]=(present,f'black_box(faster_hex::option_withpfx_ignorecase::array::deserialize::<_,{n}>(Present(serde::de::value::StrDeserializer::<serde::de::value::Error>::new(black_box(&field)))).unwrap().unwrap());')
  for n in [1023,1024,1025,4095,4097,8192]:
   k="transient"+str(n)
   cases[k]=[n];ops[k]=("",f'black_box(faster_hex::array::deserialize::<_,{n}>(serde::de::value::StrDeserializer::<serde::de::value::Error>::new(black_box(&field))).unwrap());')
 if os.environ.get('SHORT_FIELDS'):
  cases={k:v for k,v in cases.items() if k in ['field4','field4096','transient4096','error4096','bad4096','option32','json32']}
  for n in [1,2,3,4,5,6,7,8]:
   for op in ['array','field']:
    name=op+str(n)
    cases[name]=[n]
    if op=='array':
     ops[name]=('',f'black_box(faster_hex::hex_decode_array::<{n}>(black_box(&hex)).unwrap());')
    else:
     ops[name]=('',ops['field4096'][1].replace('4096',str(n)))
 if os.environ.get("RELEASE_FIELDS"):
  # Cover owned and borrowed forms in the same runner as the large optional field.
  for n in range(1,9):
   for op in ['array','field']:
    key=op+str(n); cases[key]=[n]
    ops[key]=('',f'black_box(faster_hex::hex_decode_array::<{n}>(black_box(&hex)).unwrap());') if op=='array' else ('',ops['field4096'][1].replace('4096',str(n)))
  setup='''struct Present<D>(D);
impl<'de,D:serde::Deserializer<'de>> serde::Deserializer<'de> for Present<D>{
 type Error=D::Error;
 fn deserialize_any<V:serde::de::Visitor<'de>>(self,v:V)->Result<V::Value,D::Error>{v.visit_some(self.0)}
 serde::forward_to_deserialize_any!{bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any}
}'''
  cases["rawoption4096"]=[4096]
  ops["rawoption4096"]=(setup,'black_box(faster_hex::option_withpfx_ignorecase::array::deserialize::<_,4096>(Present(serde::de::value::StrDeserializer::<serde::de::value::Error>::new(black_box(&field)))).unwrap().unwrap());')
  cases["escapedoption4096"]=[4096]
  ops["escapedoption4096"]=('#[derive(serde::Deserialize)] struct Value(#[serde(with="faster_hex::option_withpfx_ignorecase::array")] Option<[u8;4096]>);','black_box(serde_json::from_str::<Value>(black_box(&optional_json)).unwrap().0);')
 ops={k:v for k,v in ops.items() if k in cases}
 shutil.rmtree(bins);bins.mkdir()
elif os.environ.get('EXISTING_CONTROLS'):
 cases.update(encode=[4,8,32,256],decode=[4,32,256],serialize=[10,32,65,256,4096],deserialize=[10,32,256,4096])
 cases['array4']=[4]
 ops['array4']=('', 'black_box(faster_hex::hex_decode_array::<4>(black_box(&hex)).unwrap());')
 for stale in bins.glob('*.rs'):
  if stale.stem not in ops: stale.unlink()
if os.environ.get("MIXED_CALLER"):
 cases={"mixed":[10,32,65,256,4096],"escapedmixed":[10,32,65,256,4096],"serialize":[10,32,65,256,4096]}
 payload_type='#[derive(serde::Serialize,serde::Deserialize)] struct Payload { #[serde(with="faster_hex")] bytes: Vec<u8> }'
 operation='let value=serde_json::from_str::<Payload>(black_box(&json)).unwrap(); dst.clear();serde_json::to_writer(&mut dst,&value).unwrap();black_box(dst.as_slice());'
 ops={k:(payload_type,operation) if k!="serialize" else ops[k] for k in cases}
 for f in bins.glob('*.rs'):
  if f.stem not in cases:f.unlink()
if os.environ.get("RELEASE_COMMON"):
 cases={'encode':[4,8,16,20,32,65,256,4096], 'owned_string':[32], 'decode':[4,32,256,4096], 'field4':[4],'field4096':[4096],'serialize':[32,4096],'deserialize':[32,4096]}
 ops={k:v for k,v in ops.items() if k in cases}
 for f in bins.glob('*.rs'):
  if f.stem not in cases:f.unlink()
if os.environ.get("RELEASE_FOCUS"):
 cases={"encode":[16,20,32,65], "decode":[32,256,4096]}
 ops={k:v for k,v in ops.items() if k in cases}
 for file in bins.glob('*.rs'):
  if file.stem not in cases:file.unlink()
if os.environ.get("FIELD_COST"):
 original=ops["field4096"][1]
 borrowed=original.split("black_box(",1)[1].rsplit(");",1)[0]
 temporary=borrowed.replace("BorrowedStrDeserializer","StrDeserializer")
 raw='faster_hex::hex_decode_array::<4096>(black_box(&hex)).unwrap()'
 ops={}
 for name,expr in [('array',raw),('borrowed',borrowed),('transient',temporary)]:
  ops[name]=('',f'black_box({expr});')
  ops[name+'_ref']=('',f'let value={expr}; black_box(&value);')
 cases={k:[4096] for k in ops}
 for f in bins.glob('*.rs'):
  if f.stem not in cases: f.unlink()
kernel=os.environ.get("KERNEL_CASES")
focused=os.environ.get("KERNEL_FOCUS")
if kernel=="lanes":
 cases={"encode":[8,20,31,32,33,40,63,64,65,128,256,4096],
        "encode_upper":[20,31,32,33,64,65,4096]}
 if focused:cases={"encode":[20,32,33,64,256,4096],"encode_upper":[32,4096]}
 ops={"encode":ops["encode"],"encode_upper":("",ops["encode"][1].replace("hex_encode(","hex_encode_upper("))}
if kernel=="mask":
 sizes=[31,32,63,64,127,128,129,256,4096]
 cases={"decode":[4,8,20,32,64,96,97,128,256,1024,4096],
        "check_mixed":sizes,"check_lower":[32,127,128,4096],"check_upper":[32,128,129,4096],
        "check_first":[32,128,4096],"check_last":[32,127,128,4096]}
 if focused:cases={"decode":[32,96,97,256,4096],"check_mixed":[32,128,4096],
                   "check_lower":[128],"check_upper":[128],"check_last":[4096]}
 ops={"decode":ops["decode"]}
 for name in cases:
  if name.startswith("check_"):
   policy={"check_lower":"Lower","check_upper":"Upper"}.get(name,"None")
   ops[name]=("",f"black_box(faster_hex::hex_check_with_case(black_box(&checked),faster_hex::CheckCase::{policy}));")
if kernel:
 for f in bins.glob("*.rs"):
  if f.stem not in cases:f.unlink()
diagnostics = os.environ.get("RELEASE_DIAGNOSTICS")
if diagnostics:
 cases = {"decode": [32, 256, 4096]}
 ops = {"decode": ops["decode"]}
 for name in ("first", "middle", "last"):
  cases[name] = [1, 32, 4096]
  ops[name] = ("", "black_box(faster_hex::hex_decode(black_box(&malformed),black_box(&mut dst[..n])).unwrap_err());")
 for f in bins.glob("*.rs"):
  if f.stem not in cases: f.unlink()
if os.environ.get("OWNED_VECTORS"):
 ops['raw_vec']=('', 'black_box(faster_hex::hex_decode_vec(black_box(&hex)).unwrap());')
 cases['raw_vec']=[0,4,32,256,1024,1025,4096]
(driver/'Cargo.toml').write_text('[package]\nname="consumer-timing"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nfaster-hex={path="../codec"}\nserde={version="1",features=["derive"]}\nserde_json="1"\n[workspace]\n')
for k,(defs,op) in ops.items():
 prepare="let payload=Payload{bytes:bytes.clone()};" if k=="serialize" else ""
 if kernel=="lanes":
  cap="upper" if k.endswith("upper") else "lower"
  prepare=f"let expected=hex.to_ascii_{cap}case(); assert_eq!(faster_hex::hex_encode{'_upper' if cap=='upper' else ''}(&bytes,&mut dst).unwrap().as_bytes(),expected);"
 if kernel=="mask" and k.startswith("check_"):
  method={"check_upper":"checked.make_ascii_uppercase();","check_lower":"checked.make_ascii_lowercase();","check_first":"checked[0]=255;","check_last":"checked[n-1]=255;"}.get(k,"")
  prepare="let mut checked=hex[..n].to_vec();"+method+"assert_eq!("+op.split("black_box(",1)[1].rsplit(");",1)[0]+","+("false" if k in ("check_first","check_last") else "true")+");"
 if diagnostics and k in ("first","middle","last"):
  index={"first":"0","middle":"n","last":"2*n-1"}[k]
  prepare=f'''
   let mut malformed=hex.clone();
   let index={index};
   malformed[index]=0xff;
   dst.fill(0xa5);
   let error=faster_hex::hex_decode(&malformed,&mut dst[..n]).unwrap_err();
   assert!(matches!(error,faster_hex::Error::InvalidChar{{index:i,byte:0xff,..}} if i==index));
   assert!(dst.iter().all(|b|*b==0xa5));'''
 code='''#![allow(unused_variables,unused_mut,dead_code)]
use std::{hint::black_box,time::Instant};
DEFS
#[no_mangle] #[inline(never)]
pub fn run_sample(n:usize, iterations:usize)->f64 {
 let len=if "KIND"=="prefix"{32}else{n};
 let bytes:Vec<u8>=(0..len).map(|i|(i*37+11) as u8).collect();
 let hex:Vec<u8>=bytes.iter().enumerate().flat_map(|(i,b)| if i%3==0 {format!("{b:02X}").into_bytes()}else{format!("{b:02x}").into_bytes()}).collect();
 let field=format!("0x{}",std::str::from_utf8(&hex).unwrap());
 let json=format!(r#"{{"bytes":"{field}"}}"#);
 OPTIONAL\n let mut dst=vec![0;len*2+32];
 PREPARE
 let start=Instant::now();
 for _ in 0..iterations {OP}
 start.elapsed().as_nanos() as f64/iterations as f64
}
fn main() {
 let mut args=std::env::args().skip(1);
 let n=args.next().unwrap().parse().unwrap();
 let iters:usize=args.next().unwrap().parse().unwrap();
 black_box(run_sample(n,(iters/6).max(32)));
 println!("{:.6}",run_sample(n,iters));
}
'''.replace("OPTIONAL",'let optional_json=format!("{field:?}");' if k.startswith(("option","json")) else "").replace("DEFS",defs).replace("KIND",k).replace("PREPARE",prepare).replace("OP",op)
 if k=="escapedmixed":
  code=code.replace('let start=Instant::now();','let json=json.replace("0x",&format!("{}u0030x",char::from(92))); let start=Instant::now();')
 elif k.startswith('escaped'):
  code=code.replace('let start=Instant::now();','let q=char::from(34); let slash=char::from(92); let optional_json=format!("{q}{slash}u0030{}{q}", &field[1..]); let start=Instant::now();')
 (bins/(k+'.rs')).write_text(code)
if os.environ.get("GENERATE_ONLY"):
 sys.exit(0)
def text_segment(exe):
 if sys.platform=="darwin":
  part=next(x for x in output(["otool","-l",exe]).split("Section\n") if re.match(r"\s*sectname __text\s+segname __TEXT",x))
  addr,size,offset=map(lambda s:int(s,0),[re.search(r"\b"+n+r"\s+(\S+)",part)[1] for n in ["addr","size","offset"]])
  return addr,exe.read_bytes()[offset:offset+size]
 tmp=work/'text.bin';run(["objcopy","--dump-section",".text="+str(tmp),exe])
 header=output(["objdump","-h",exe])
 addr=int(next(l.split()[3] for l in header.splitlines() if re.search(r"^\s*\d+\s+\.text\s",l)),16)
 return addr,tmp.read_bytes()
(out/'host.txt').write_text(platform.platform()+'\n'+output(['lscpu'] if sys.platform=='linux' else ['sysctl','-n','machdep.cpu.brand_string'])+'\n'+output(['rustc','-vV']))
info={}
for role,rev in [('base',base),('head',head)]:
 if source.exists(): shutil.rmtree(source)
 source.mkdir()
 tar=work/'codec.tar'
 run(['git','archive','-o',str(tar),rev],cwd=root)
 run(['tar','-xf',tar],cwd=source)
 select(source,role,os.environ)
 if (work/'target').exists(): run(['cargo','clean','--release','-p','faster-hex','-p','consumer-timing'],cwd=driver)
 run(['cargo','build','--release','--bins'],cwd=driver)
 dest=work/role;dest.mkdir(exist_ok=True)
 for k in cases:
  exe=dest/k;shutil.copy2(work/'target/release'/k,exe)
  addr,t=text_segment(exe)
  info[role+'/'+k]={'address':hex(addr),'bytes':len(t),'sha256':hashlib.sha256(t).hexdigest()}
 if os.environ.get("FIELD_ASSEMBLY") and sys.platform=="linux":
  # Keep the ordinary binaries untouched. Inspect the final linked caller.
  for name in ("field4096","transient4096","rawoption4096","raw_vec"):
   (out/(role+"-"+name+".asm")).write_text(output(["objdump","-d","-C","--disassemble=run_sample",dest/name]))
(out/'sections.json').write_text(json.dumps(info,indent=2))
if os.environ.get("CHECK_UNCHANGED") and all(info["base/"+k]==info["head/"+k] for k in cases):
 print(f"All {len(cases)} downstream executables have identical .text address, length and bytes.")
 sys.exit(0)
def measured(k,n,role,it):
 return float(output(pin+[str(work/role/k),str(n),str(it)]))
times={};iters={}
for k,ns in cases.items():
 for n in ns:
  case=k+'/'+str(n);cal=measured(k,n,'base',max(500,100000//max(1,n//16)))
  iters[k,n]=int(max(20_000,min(120_000_000,55_000_000/max(.4,cal))))
  times[case]={p:[] for p in ['pair','base_control','head_control']}
rng=random.Random(170771)
orders={}
for k,ns in cases.items():
 for n in ns:
  family=[]
  for label,roles,pairs in [('pair',('base','head'),20),('base_control',('base','base'),8),('head_control',('head','head'),8)]:
   family += [(label,roles,swap) for swap in [False,True] for _ in range(pairs//2)]
  rng.shuffle(family);orders[k,n]=family
for i in range(36):
 keys=list(orders);rng.shuffle(keys)
 for k,n in keys:
  label,roles,swap=orders[k,n][i];a,b=roles;it=iters[k,n]
  if swap: second=measured(k,n,b,it);first=measured(k,n,a,it)
  else: first=measured(k,n,a,it);second=measured(k,n,b,it)
  times[k+'/'+str(n)][label].append([first,second])
 (out/'independent.json').write_text(json.dumps(times))
def describe(pairs):
 ratios=[b/a for a,b in pairs]
 med=statistics.median(ratios)
 boot=sorted(statistics.median(rng.choices(ratios,k=len(ratios))) for _ in range(5000))
 return {'a_ns':statistics.median(a for a,b in pairs),'b_ns':statistics.median(b for a,b in pairs),'ratio':med,'lo95':boot[124],'hi95':boot[4874]}
stats={k:{p:describe(v) for p,v in x.items()} for k,x in times.items()}
(out/'independent-summary.json').write_text(json.dumps(stats,indent=2))
rows=['| Operation / size | Same machine code and address | Base ns | Candidate ns | Median paired change, 95% interval | A/A | B/B |','|---|---|---:|---:|---:|---:|---:|']
for k,s in stats.items():
 kind=k.split('/')[0];identical=info['base/'+kind]==info['head/'+kind];v=s['pair']
 fmt=lambda x:f'{(x-1)*100:+.1f}%'
 rows.append(f"| {k} | {identical} | {v['a_ns']:.3f} | {v['b_ns']:.3f} | {fmt(v['ratio'])} ({fmt(v['lo95'])} to {fmt(v['hi95'])}) | {fmt(s['base_control']['ratio'])} | {fmt(s['head_control']['ratio'])} |")
message="Separate downstream binaries. Each operation is built from the same path and timed in 20 randomized balanced process pairs; two eight-pair same-source controls, fixed input, warm buffers. Machine code includes the entire .text section. Revisions: "+base+" and "+head+".\n\n"+"\n".join(rows)
print(message)
if path:=os.environ.get('GITHUB_STEP_SUMMARY'):
 with open(path,'a') as f:f.write(message+'\n')
