use std::{hint::black_box, time::Instant};

fn run<const N: usize>(rounds: usize, mode: &str) {
    let mut input = b"0f".repeat(N);
    let invalid = mode.ends_with("late");
    if invalid {
        *input.last_mut().unwrap() = b'!';
    }
    let array = mode.starts_with("array");
    let verify_error = |error| {
        assert!(matches!(error, faster_hex::Error::InvalidChar { index, byte: b'!', .. } if index == 2 * N - 1));
    };
    if array {
        match faster_hex::hex_decode_array::<N>(&input) {
            Ok(out) => assert!(!invalid && out.iter().all(|x| *x == 15)),
            Err(error) => { assert!(invalid); verify_error(error); }
        }
    } else {
        match faster_hex::hex_decode_vec(&input) {
            Ok(out) => assert!(!invalid && out.len() == N && out.iter().all(|x| *x == 15)),
            Err(error) => { assert!(invalid); verify_error(error); }
        }
    }
    let sample = |iters| {
        let start = Instant::now();
        if array {
            for _ in 0..iters {
                let out = faster_hex::hex_decode_array::<N>(black_box(&input));
                assert_eq!(black_box(&out).is_err(), invalid);
            }
        } else {
            for _ in 0..iters {
                let out = faster_hex::hex_decode_vec(black_box(&input));
                assert_eq!(black_box(&out).is_err(), invalid);
            }
        }
        start.elapsed().as_nanos() as f64 / iters as f64
    };
    black_box(sample((rounds / 6).max(32)));
    println!("{:.6}", sample(rounds));
}
fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    match n {
        32 => run::<32>(rounds, &mode),
        256 => run::<256>(rounds, &mode),
        4096 => run::<4096>(rounds, &mode),
        4097 => run::<4097>(rounds, &mode),
        _ => panic!("unmeasured size"),
    }
}
