use std::{hint::black_box, time::Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let fail = mode != "valid";
    let mut text = b"0F".repeat(n);
    if fail {
        let index = match &*mode {"first" => 0, "middle" => n, _ => 2*n - 1};
        text[index] = b'!';
    }
    let mut dst = Vec::with_capacity(n + 3);
    dst.extend_from_slice(&[1, 2, 3]);
    let mut sample = |iters| {
        let start = Instant::now();
        for _ in 0..iters {
            let received = faster_hex::hex_decode_append(black_box(&text), black_box(&mut dst));
            assert_eq!(black_box(received).is_err(), fail);
            black_box(&dst);
            dst.truncate(3);
        }
        start.elapsed().as_nanos() as f64 / iters as f64
    };
    black_box(sample((rounds / 6).max(32)));
    println!("{:.6}", sample(rounds));
    assert_eq!(dst, [1, 2, 3]);
}
