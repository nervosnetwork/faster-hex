use faster_hex::{hex_check_with_case, CheckCase};
use std::{hint::black_box, time::Instant};

fn admissible(byte: u8, case: CheckCase) -> bool {
    byte.is_ascii_digit()
        || (case != CheckCase::Lower && (b'A'..=b'F').contains(&byte))
        || (case != CheckCase::Upper && (b'a'..=b'f').contains(&byte))
}

fn exhaust_bytes() {
    for case in [CheckCase::None, CheckCase::Lower, CheckCase::Upper] {
        for n in [15, 16, 17, 31, 32, 33, 63, 64, 65, 79, 127, 128, 129] {
            let mut bytes = vec![b'5'; n];
            for position in 0..n {
                for byte in 0..=u8::MAX {
                    bytes[position] = byte;
                    assert_eq!(hex_check_with_case(&bytes, case), admissible(byte, case));
                }
                bytes[position] = b'5';
            }
        }
    }
    println!(
        "All 256 byte values in every position, across 13 boundary lengths and three case policies"
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next().unwrap();
    if first == "exhaustive" {
        return exhaust_bytes();
    }
    let n: usize = first.parse().unwrap();
    let iterations: usize = args.next().unwrap().parse().unwrap();
    let kind = args.next().unwrap();
    let (case, content) = match kind.split_once('-').unwrap() {
        ("mixed", how) => (CheckCase::None, how),
        ("upper", how) => (CheckCase::Upper, how),
        ("lower", how) => (CheckCase::Lower, how),
        _ => unreachable!(),
    };
    let mut bytes: Vec<_> = (0..n)
        .map(|i| {
            let lower = case == CheckCase::Lower || (case == CheckCase::None && i % 3 != 0);
            let alphabet = if lower {
                b"0123456789abcdef"
            } else {
                b"0123456789ABCDEF"
            };
            alphabet[(i * 37 + 11) % 16]
        })
        .collect();
    if content != "valid" {
        let at = match content {
            "first" => 0,
            "middle" => n / 2,
            "last" => n - 1,
            _ => unreachable!(),
        };
        bytes[at] = match case {
            CheckCase::None => 0x80,
            CheckCase::Upper => b'a',
            CheckCase::Lower => b'A',
        };
    }
    let expected = bytes.iter().all(|&b| admissible(b, case));
    assert_eq!(hex_check_with_case(&bytes, case), expected);
    let measure = |count: usize| {
        let begin = Instant::now();
        for _ in 0..count {
            black_box(hex_check_with_case(black_box(&bytes), black_box(case)));
        }
        begin.elapsed().as_nanos() as f64 / count as f64
    };
    black_box(measure((iterations / 6).max(32)));
    println!("{:.6}", measure(iterations));
}
