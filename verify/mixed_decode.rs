
use std::{hint::black_box, time::Instant};
fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let iterations: usize = args.next().unwrap().parse().unwrap();
    let expected: Vec<u8> = (0..n).map(|i| (i*37+11) as u8).collect();
    let input: Vec<_> = expected.iter().enumerate().flat_map(|(i,b)| (if i % 3 == 0 { format!("{b:02X}") } else { format!("{b:02x}") }).into_bytes()).collect();
    let mut dst = vec![0; n];
    let mut decode = || {
        let source = black_box(input.as_slice());
        let out = black_box(dst.as_mut_slice());
        black_box(faster_hex::hex_decode(source, out).unwrap());
    };
    for _ in 0..(iterations/8).max(64) { decode(); }
    let start = Instant::now();
    for _ in 0..iterations { decode(); }
    let elapsed = start.elapsed().as_nanos();
    assert_eq!(dst, expected);
    println!("{:.6}", elapsed as f64 / iterations as f64);
}
