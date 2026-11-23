use faster_hex::{hex_decode_with_case, CheckCase, Error};

fn nibble(byte: u8, case: CheckCase) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' if case != CheckCase::Lower => Some(byte - b'A' + 10),
        b'a'..=b'f' if case != CheckCase::Upper => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn main() {
    let mut examples = 0;
    for case in [CheckCase::None, CheckCase::Upper, CheckCase::Lower] {
        for n in [2, 14, 16, 18, 30, 32, 34, 62, 64, 66, 126, 128, 130, 192] {
            let mut text = vec![b'5'; n];
            for pos in 0..n {
                for byte in 0..=255 {
                    text[pos] = byte;
                    let mut output = [0xa5; 98];
                    let result = hex_decode_with_case(&text, &mut output[1..97], case);
                    match nibble(byte, case) {
                        Some(v) => {
                            let got = result.unwrap();
                            assert_eq!(got.len(), n / 2);
                            for (i, actual) in got.iter().enumerate() {
                                let expected = if i != pos / 2 { 0x55 } else if pos % 2 == 0 { v << 4 | 5 } else { 0x50 | v };
                                assert_eq!(*actual, expected);
                            }
                            assert_eq!(output[0], 0xa5);
                            assert!(output[1+n/2..].iter().all(|&v| v == 0xa5));
                        }
                        None => {
                            assert!(matches!(result, Err(Error::InvalidChar { index, byte: bad, .. }) if index==pos && bad==byte));
                            assert_eq!(output,[0xa5;98]);
                        }
                    }
                    examples+=1;
                }
                text[pos]=b'5';
            }
        }
    }
    println!("{examples} position, byte and case combinations");
}
