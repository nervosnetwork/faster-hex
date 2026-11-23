use faster_hex::{hex_encode, hex_encode_upper, Error};

fn main() {
    let mut checked = 0;
    for n in (0..256).chain(512..576).chain(4096..4160) {
        for offset in 0..32 {
            let source: Vec<u8> = (0..offset + n)
                .map(|i| (i * 37 + n + offset) as u8)
                .collect();
            let input = &source[offset..];
            for upper in [false, true] {
                let alphabet = if upper {
                    b"0123456789ABCDEF"
                } else {
                    b"0123456789abcdef"
                };
                let expected: Vec<_> = input
                    .iter()
                    .flat_map(|&b| [alphabet[usize::from(b >> 4)], alphabet[usize::from(b & 15)]])
                    .collect();
                let encode = if upper { hex_encode_upper } else { hex_encode };
                for shift in [0, 1, 15] {
                    let begin = (13 * offset + shift) % 32;
                    for capacity in [n * 2, n * 2 + 17, (n * 2).saturating_sub(1)] {
                        let mut dst = vec![0xa5; begin + capacity + 17];
                        let pointer = dst[begin..].as_ptr();
                        let got = encode(input, &mut dst[begin..begin + capacity]);
                        if capacity < expected.len() {
                            assert!(
                                matches!(got, Err(Error::OutputTooSmall { required, .. }) if required == expected.len())
                            );
                            assert!(dst.iter().all(|&b| b == 0xa5));
                        } else {
                            let text = got.unwrap();
                            assert_eq!(text.as_ptr(), pointer);
                            assert_eq!(text.as_bytes(), expected);
                            assert!(dst[..begin]
                                .iter()
                                .chain(&dst[begin + expected.len()..])
                                .all(|&b| b == 0xa5));
                        }
                        checked += 1;
                    }
                }
            }
        }
    }
    println!(
        "{checked} public encodes, both cases, exact output, guard bytes and insufficient capacity"
    );
}
