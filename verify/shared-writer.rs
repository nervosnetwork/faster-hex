use serde::Serialize;
use std::{hint::black_box, time::Instant};

#[derive(Serialize)]
struct Old<'a> { #[serde(with = "codec_a")] bytes: &'a [u8] }
#[derive(Serialize)]
struct New<'a> { #[serde(with = "codec_b")] bytes: &'a [u8] }
type Writer = fn(&[u8], &mut Vec<u8>);
#[inline(never)]
fn old(input: &[u8], out: &mut Vec<u8>) { serde_json::to_writer(out, &Old { bytes: input }).unwrap() }
#[inline(never)]
fn new(input: &[u8], out: &mut Vec<u8>) { serde_json::to_writer(out, &New { bytes: input }).unwrap() }

#[inline(never)]
fn timed(f: Writer, input: &[u8], dst: &mut Vec<u8>, offset: usize, count: usize) -> f64 {
    let t = Instant::now();
    for _ in 0..count {
        dst.truncate(offset);
        f(black_box(input), black_box(dst));
        black_box(dst.as_slice());
    }
    t.elapsed().as_nanos() as f64 / count as f64
}
fn main() {
    eprintln!("same writer address: {}", std::ptr::fn_addr_eq(old as Writer, new as Writer));
    println!("len,source_offset,output_offset,round,base,head,base_control,head_control");
    for n in [10, 32, 65, 256, 4096] {
        let mut buffer = vec![0; n+128];
        let aligned = (64 - buffer.as_ptr() as usize % 64) % 64;
        let mut dst=Vec::with_capacity(2*n+256);
        let out_aligned=(64-dst.as_ptr() as usize%64)%64;
        let count=(160_000_usize*32/n).clamp(1800,140_000);
        for (input_offset, output_offset) in [(0,0),(1,0),(0,1),(1,1),(15,15),(31,0),(0,31),(63,63)] {
            let input=&mut buffer[aligned+input_offset..][..n];
            for (i,b) in input.iter_mut().enumerate(){*b=(37*i+11) as u8;}
            let offset=out_aligned+output_offset;
            dst.resize(offset,0);
            old(input,&mut dst);
            let text=dst[offset..].to_vec();
            dst.truncate(offset);
            new(input,&mut dst);
            assert_eq!(&dst[offset..],&text);
            for round in 0..19 {
                let roles = if round%2==0 { [old as Writer,new, new,old] } else { [new as Writer,old,old,new] };
                let v=roles.map(|f|timed(f,input,&mut dst,offset,count));
                let [a,b,bc,ac] = if round%2==0 {v} else {[v[1],v[0],v[3],v[2]]};
                if round>0 {println!("{n},{input_offset},{output_offset},{round},{a:.6},{b:.6},{ac:.6},{bc:.6}");}
            }
        }
    }
}