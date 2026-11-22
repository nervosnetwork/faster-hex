use faster_hex::{hex_validate, Error};
use std::{hint::black_box, time::Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let mut src = b"aF".repeat(n);
    match mode.as_str() {
        "valid" => assert_eq!(hex_validate(&src),Ok(())),
        "odd" => {
            src.push(b'!');
            assert_eq!(hex_validate(&src),Err(Error::OddLength));
        }
        "first" | "middle" | "last" => {
            let index = match mode.as_str() { "first" => 0, "middle" => n, _ => 2*n-1 };
            src[index] = b'!';
            assert!(matches!(hex_validate(&src), Err(Error::InvalidChar { index: actual, byte: b'!', .. }) if actual == index));
        }
        _ => unreachable!()
    };
    let timing = |count| {
        let now = Instant::now();
        for _ in 0..count {
            let _ = black_box(hex_validate(black_box(&src)));
        }
        now.elapsed().as_nanos() as f64 / count as f64
    };
    black_box(timing((rounds / 6).max(32)));
    println!("{:.6}",timing(rounds));
}
