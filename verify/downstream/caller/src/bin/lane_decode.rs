use faster_hex::{CheckCase, hex_decode_with_case};
use std::{hint::black_box, time::Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let policy = args.next().unwrap();
    let iterations: usize = args.next().unwrap().parse().unwrap();
    let expected: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
    let input: Vec<_> = expected
        .iter()
        .enumerate()
        .flat_map(|(i, b)| {
            if policy == "upper" || (policy == "mixed" && i % 3 == 0) {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
            .into_bytes()
        })
        .collect();
    let case = match policy.as_str() {
        "mixed" => CheckCase::None,
        "lower" => CheckCase::Lower,
        "upper" => CheckCase::Upper,
        _ => unreachable!(),
    };
    let mut output = vec![0; n];
    for warm in [true, false] {
        let loops = if warm {
            (iterations / 8).max(64)
        } else {
            iterations
        };
        let start = Instant::now();
        for _ in 0..loops {
            black_box(
                hex_decode_with_case(black_box(&input), black_box(&mut output), case).unwrap(),
            );
        }
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(output, expected);
        if !warm {
            println!("{:.6}", elapsed as f64 / loops as f64);
        }
    }
}
