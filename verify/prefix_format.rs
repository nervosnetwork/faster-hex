use std::{hint::black_box,fmt::Write,time::Instant};
fn main() {
    let mut args=std::env::args().skip(1);
    let n:usize=args.next().unwrap().parse().unwrap();
    let rounds:usize=args.next().unwrap().parse().unwrap();
    let bytes=[0xab;32];let mut buf=String::with_capacity(64);
    let mut measure=|count| {
        let start=Instant::now();
        for _ in 0..count {
            write!(buf,"{}",faster_hex::Hex::new(black_box(&bytes)).leading_digits(black_box(n))).unwrap();
            black_box(buf.as_bytes());buf.clear();
        }
        start.elapsed().as_nanos() as f64/count as f64
    };
    black_box(measure((rounds/6).max(32)));println!("{:.6}",measure(rounds));
}
