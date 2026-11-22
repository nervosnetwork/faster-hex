use std::{hint::black_box, time::Instant};

fn sample(rounds: usize, mut operation: impl FnMut()) -> f64 {
    for _ in 0..(rounds / 6).max(32) {
        operation();
    }
    let start = Instant::now();
    for _ in 0..rounds {
        operation();
    }
    start.elapsed().as_nanos() as f64 / rounds as f64
}

fn offset_for(pointer: *const u8, wanted: usize) -> usize {
    wanted.wrapping_sub(pointer as usize) & 63
}

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let fields: Vec<_> = mode.split('-').collect();
    let [operation, source_offset, destination_offset, outcome] = fields.as_slice() else {
        panic!("expected an operation, source offset, destination offset and outcome");
    };
    let src_mod: usize = source_offset.parse().unwrap();
    let dst_mod: usize = destination_offset.parse().unwrap();
    let bad = *outcome == "late";
    let expected: Vec<_> = (0..n).map(|i| (73 * i + i / 7) as u8).collect();
    let hex = b"0123456789aBcDeF";
    let mut text = vec![0; 2 * n + 64];
    let skip = offset_for(text.as_ptr(), src_mod);
    let text = &mut text[skip..skip + 2 * n];
    for (&byte, digits) in expected.iter().zip(text.chunks_exact_mut(2)) {
        digits.copy_from_slice(&[hex[(byte >> 4) as usize], hex[(byte & 15) as usize]]);
    }
    if bad {
        *text.last_mut().unwrap() = b'!';
    }
    assert_eq!(text.as_ptr() as usize & 63, src_mod);

    let mut dst: Vec<u8> = Vec::with_capacity(n + 128);
    let prefix = 64 + offset_for(dst.as_ptr(), dst_mod);
    dst.resize(prefix, 0xa5);
    assert_eq!((dst.as_ptr() as usize + prefix) & 63, dst_mod);
    let pointer = dst.as_ptr();
    let received = faster_hex::hex_decode_append(text, &mut dst);
    if bad {
        assert!(
            matches!(received, Err(faster_hex::Error::InvalidChar {index, byte: b'!', ..}) if index == 2*n-1)
        );
        assert_eq!(dst.len(), prefix);
    } else {
        assert_eq!(received.unwrap(), expected);
    }
    assert_eq!(dst.as_ptr(), pointer);
    assert!(dst[..prefix].iter().all(|&byte| byte == 0xa5));
    dst.truncate(prefix);

    let ns = match *operation {
        "reuse" => sample(rounds, || {
            let result = faster_hex::hex_decode_append(black_box(text), black_box(&mut dst));
            assert_eq!(black_box(result).is_err(), bad);
            black_box(&dst);
            dst.truncate(prefix);
        }),
        "grow" => {
            // Prefix and allocation lifetime belong to each operation here.
            let mut fresh = vec![0xa5; 3];
            assert_eq!(fresh.capacity(), 3);
            let got = faster_hex::hex_decode_append(text, &mut fresh);
            if bad {
                assert!(
                    matches!(got, Err(faster_hex::Error::InvalidChar {index, byte: b'!', ..}) if index == 2*n-1)
                );
                assert_eq!(fresh, [0xa5; 3]);
            } else {
                assert_eq!(got.unwrap(), expected);
                assert_eq!(&fresh[..3], &[0xa5; 3]);
            }
            sample(rounds, || {
                let mut fresh = vec![0xa5; 3];
                let result = faster_hex::hex_decode_append(black_box(text), black_box(&mut fresh));
                assert_eq!(black_box(result).is_err(), bad);
                black_box(&fresh);
            })
        }
        "slice" => {
            dst.resize(prefix + n, 0);
            let out = &mut dst[prefix..];
            assert_eq!(out.as_ptr() as usize & 63, dst_mod);
            sample(rounds, || {
                let result = faster_hex::hex_decode(black_box(text), black_box(&mut *out));
                assert_eq!(black_box(result).is_err(), bad);
            })
        }
        "zero" => {
            assert!(!bad);
            sample(rounds, || {
                let out = black_box(&mut dst);
                out.resize(prefix + n, 0);
                black_box(&out[prefix..]);
                out.truncate(prefix);
            })
        }
        _ => panic!("unknown operation"),
    };
    println!("{ns:.6}");
}
