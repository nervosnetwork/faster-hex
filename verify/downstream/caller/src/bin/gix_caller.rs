use std::{hint::black_box,time::Instant};
fn main() {
 let mut args=std::env::args().skip(1);
 let n:usize=args.next().unwrap().parse().unwrap();
 let mode=args.next().unwrap();
 let loops:usize=args.next().unwrap().parse().unwrap();
 let bytes:Vec<u8>=(0..n).map(|i| (37*i+11) as u8).collect();
 let text:String=bytes.iter().map(|b|format!("{b:02x}")).collect();
 assert_eq!(mode,"parse");
 let input=text.as_bytes();assert_eq!(gix_hash::ObjectId::from_hex(input).unwrap().as_slice(),bytes);
 for warm in [true,false] {
   let iterations=if warm { loops/8+1 }else{loops};
   let start=Instant::now();
   for _ in 0..iterations { black_box(gix_hash::ObjectId::from_hex(black_box(input)).unwrap()); }
   let elapsed=start.elapsed().as_nanos();
   if !warm { println!("{:.6}", elapsed as f64 / iterations as f64); }
 }
}
