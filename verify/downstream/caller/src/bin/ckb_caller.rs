use std::{hint::black_box,time::Instant};
fn main() {
 let mut args=std::env::args().skip(1);
 let n:usize=args.next().unwrap().parse().unwrap();
 let mode=args.next().unwrap();
 let loops:usize=args.next().unwrap().parse().unwrap();
 let bytes:Vec<u8>=(0..n).map(|i| (37*i+11) as u8).collect();
 let text:String=bytes.iter().map(|b|format!("{b:02x}")).collect();
 let expected=format!("\"0x{text}\"");
 let input=if mode=="escaped" { expected.replace("0x",&format!("{}u0030x",char::from(92))) } else {expected.clone()};
 assert_eq!(input.len(), expected.len() + if mode=="escaped" {5} else {0});
 let json=input.as_bytes();let parsed:ckb_jsonrpc_types::JsonBytes=serde_json::from_slice(json).unwrap();
 assert_eq!(parsed.as_bytes(),bytes);assert_eq!(serde_json::to_string(&parsed).unwrap(),expected);
 let mut output=Vec::with_capacity(expected.len());
 for warm in [true,false] {
   let iterations=if warm { loops/8+1 }else{loops};
   let start=Instant::now();
   for _ in 0..iterations { let parsed:ckb_jsonrpc_types::JsonBytes=serde_json::from_slice(black_box(json)).unwrap();
 output.clear();serde_json::to_writer(&mut output,&parsed).unwrap();black_box(output.as_slice()); }
   let elapsed=start.elapsed().as_nanos();
   if !warm { println!("{:.6}", elapsed as f64 / iterations as f64); }
 }
}
