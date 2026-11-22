use std::{hint::black_box, time::Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let n = args.next().unwrap().parse().unwrap();
    let repeats: usize = args.next().unwrap().parse().unwrap();
    let text = b"aF".repeat(n);
    assert!(faster_hex::hex_check(&text));
    let run = |repeats| {
        let started = Instant::now();
        for _ in 0..repeats {
            black_box(faster_hex::hex_check(black_box(&text)));
        }
        started.elapsed().as_nanos() as f64 / repeats as f64
    };
    black_box(run((repeats / 6).max(32)));
    println!("{:.6}", run(repeats));
}
