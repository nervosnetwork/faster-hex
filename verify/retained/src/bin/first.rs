#![allow(unused_variables,unused_mut,dead_code)]
use std::{hint::black_box,time::Instant};

#[no_mangle] #[inline(never)]
pub fn run_sample(n:usize, iterations:usize)->f64 {
 let len=if "first"=="prefix"{32}else{n};
 let bytes:Vec<u8>=(0..len).map(|i|(i*37+11) as u8).collect();
 let hex:Vec<u8>=bytes.iter().enumerate().flat_map(|(i,b)| if i%3==0 {format!("{b:02X}").into_bytes()}else{format!("{b:02x}").into_bytes()}).collect();
 let field=format!("0x{}",std::str::from_utf8(&hex).unwrap());
 let json=format!(r#"{{"bytes":"{field}"}}"#);

 let mut dst=vec![0;len*2+32];

   let mut malformed=hex.clone();
   let index=0;
   malformed[index]=0xff;
   dst.fill(0xa5);
   let error=faster_hex::hex_decode(&malformed,&mut dst[..n]).unwrap_err();
   assert!(matches!(error,faster_hex::Error::InvalidChar{index:i,byte:0xff,..} if i==index));
   assert!(dst.iter().all(|b|*b==0xa5));
 let start=Instant::now();
 for _ in 0..iterations {black_box(faster_hex::hex_decode(black_box(&malformed),black_box(&mut dst[..n])).unwrap_err());}
 start.elapsed().as_nanos() as f64/iterations as f64
}
fn main() {
 let mut args=std::env::args().skip(1);
 let n=args.next().unwrap().parse().unwrap();
 let iters:usize=args.next().unwrap().parse().unwrap();
 black_box(run_sample(n,(iters/6).max(32)));
 println!("{:.6}",run_sample(n,iters));
}
