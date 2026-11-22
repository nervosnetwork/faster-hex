use faster_hex::{hex_decode_with_case, CheckCase, Error};
use std::{hint::black_box, time::Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let len: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let (policy, location) = mode.split_once('-').unwrap();
    let (case, bad) = match policy {
        "mixed" => (CheckCase::None, b'!'),
        "upper" => (CheckCase::Upper, b'a'),
        "lower" => (CheckCase::Lower, b'A'),
        _ => unreachable!(),
    };
    let mut input = vec![b'3'; 2 * len];
    let mut output = vec![0xa5; len];
    let at = match location {
        "first" => 0,
        "second" => 1,
        "middle" => len,
        "boundary" => 64,
        "last" => input.len() - 1,
        _ => unreachable!(),
    };
    input[at] = bad;
    assert!(matches!(hex_decode_with_case(&input, &mut output, case),
        Err(Error::InvalidChar { index, byte, .. }) if index == at && byte == bad));
    assert!(output.iter().all(|&b| b == 0xa5));
    let mut sample = |count| {
        let start = Instant::now();
        for _ in 0..count {
            let err = hex_decode_with_case(black_box(&input), black_box(&mut output), case);
            let _ = black_box(err);
        }
        start.elapsed().as_nanos() as f64 / count as f64
    };
    black_box(sample((rounds / 6).max(20)));
    println!("{:.6}", sample(rounds));
}
