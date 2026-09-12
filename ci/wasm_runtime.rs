//! Deterministic runtime checks without host-only test harness dependencies.
use core::fmt::{self, Write};
use faster_hex::{CheckCase, Error, Hex};

fn reference(bytes: &[u8], upper: bool) -> String {
    let alphabet = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    bytes
        .iter()
        .flat_map(|byte| {
            [
                alphabet[(byte >> 4) as usize] as char,
                alphabet[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}

fn nibble(byte: u8, case: CheckCase) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' if case != CheckCase::Upper => Some(byte - b'a' + 10),
        b'A'..=b'F' if case != CheckCase::Lower => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[no_mangle]
pub extern "C" fn pointer_width() -> u32 {
    usize::BITS
}

#[no_mangle]
pub extern "C" fn codec_cases() -> u32 {
    let mut cases = 0;
    for len in (0..=257).chain([1024, 4096]) {
        let source: Vec<u8> = (0..len + 32).map(|index| (index * 73) as u8).collect();
        for source_offset in [0, 1, 7, 15, 31] {
            let input = &source[source_offset..source_offset + len];
            let destination_offset = (source_offset * 7 + 3) % 32;
            for upper in [false, true] {
                let expected = reference(input, upper);
                let mut encoded = vec![0xa5; destination_offset + len * 2 + 17];
                let output = &mut encoded[destination_offset..];
                let written = if upper {
                    faster_hex::hex_encode_upper(input, output)
                } else {
                    faster_hex::hex_encode(input, output)
                }
                .unwrap();
                assert_eq!(&*written, expected.as_str());
                assert!(encoded[..destination_offset]
                    .iter()
                    .all(|&byte| byte == 0xa5));
                assert!(encoded[destination_offset + len * 2..]
                    .iter()
                    .all(|&byte| byte == 0xa5));
                let mut decoded = vec![0xa5; source_offset + len + 17];
                let case = if upper {
                    CheckCase::Upper
                } else {
                    CheckCase::Lower
                };
                assert!(faster_hex::hex_check_with_case(expected.as_bytes(), case));
                assert_eq!(
                    faster_hex::hex_decode_with_case(
                        expected.as_bytes(),
                        &mut decoded[source_offset..],
                        case
                    )
                    .unwrap(),
                    input
                );
                assert!(decoded[..source_offset].iter().all(|&byte| byte == 0xa5));
                assert!(decoded[source_offset + len..]
                    .iter()
                    .all(|&byte| byte == 0xa5));
                cases += 1;
            }
        }
    }
    cases
}

#[no_mangle]
pub extern "C" fn error_cases() -> u32 {
    let mut cases = 0;
    for first in 0..=255u8 {
        for second in 0..=255u8 {
            for case in [CheckCase::None, CheckCase::Lower, CheckCase::Upper] {
                let input = [first, second];
                let mut output = [0xa5; 3];
                let expected = nibble(first, case)
                    .zip(nibble(second, case))
                    .map(|(hi, lo)| hi * 16 + lo);
                assert_eq!(
                    faster_hex::hex_check_with_case(&input, case),
                    expected.is_some()
                );
                match (
                    faster_hex::hex_decode_with_case(&input, &mut output, case),
                    expected,
                ) {
                    (Ok(bytes), Some(byte)) => assert_eq!(bytes, &[byte]),
                    (Err(Error::InvalidChar { index, byte, .. }), None) => {
                        let expected_index = usize::from(nibble(first, case).is_some());
                        assert_eq!((index, byte), (expected_index, input[expected_index]));
                        assert_eq!(output, [0xa5; 3]);
                    }
                    _ => panic!("decoder disagrees with independent ASCII grammar"),
                }
                assert_eq!(&output[1..], &[0xa5; 2]);
                cases += 1;
            }
        }
    }
    for length in [0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 256, 4096] {
        let mut input = vec![b'0'; length];
        let mut output = vec![0xa5; length / 2 + 3];
        if length % 2 == 1 {
            assert_eq!(
                faster_hex::hex_decode(&input, &mut output),
                Err(Error::OddLength)
            );
            assert!(output.iter().all(|&byte| byte == 0xa5));
        } else if length != 0 {
            for index in [0, length / 2, length - 1] {
                input[index] = 0xff;
                assert!(matches!(faster_hex::hex_decode(&input, &mut output),
                                 Err(Error::InvalidChar { index: found, byte: 0xff, .. }) if found == index));
                assert!(output.iter().all(|&byte| byte == 0xa5));
                input[index] = b'0';
            }
            let short = &mut output[..length / 2 - 1];
            assert!(matches!(faster_hex::hex_decode(&input, short),
                             Err(Error::OutputTooSmall { required, .. }) if required == length / 2));
            assert!(output.iter().all(|&byte| byte == 0xa5));
        }
        assert!(faster_hex::hex_check(&input));
        cases += 1;
    }
    // Length rejection wins over bad characters, even with an empty destination.
    assert_eq!(faster_hex::hex_decode(b"g", &mut []), Err(Error::OddLength));
    assert!(matches!(
        faster_hex::hex_decode(b"gg", &mut []),
        Err(Error::OutputTooSmall { required: 1, .. })
    ));
    cases + 2
}

struct Expected<'a>(&'a str);
impl fmt::LowerHex for Expected<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad_integral(true, "0x", self.0)
    }
}
impl fmt::UpperHex for Expected<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad_integral(true, "0x", self.0)
    }
}

struct LimitedWriter {
    bytes: [u8; 32],
    length: usize,
    failed: bool,
}
impl Write for LimitedWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        assert!(!self.failed, "formatter must stop after a writer error");
        let accepted = text.len().min(self.bytes.len() - self.length);
        self.bytes[self.length..self.length + accepted]
            .copy_from_slice(&text.as_bytes()[..accepted]);
        self.length += accepted;
        if accepted != text.len() {
            self.failed = true;
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}

#[no_mangle]
pub extern "C" fn formatting_cases() -> u32 {
    let mut cases = 0;
    for length in [0, 1, 8, 16, 32, 63, 64, 255, 256, 257, 4096] {
        let bytes: Vec<u8> = (0..length).map(|index| (index * 73) as u8).collect();
        let view = Hex::new(&bytes);
        let lower = reference(&bytes, false);
        let upper = reference(&bytes, true);
        assert_eq!(format!("{view}"), lower);
        assert_eq!(format!("{view:X}"), upper);
        for width in [0, 1, 7, 64, 521] {
            let expected = Expected(&lower);
            assert_eq!(
                format!("{view:+#0width$x}"),
                format!("{expected:+#0width$x}")
            );
            assert_eq!(
                format!("{view:界^#width$x}"),
                format!("{expected:界^#width$x}")
            );
            assert_eq!(
                format!("{view:<width$.1x}"),
                format!("{expected:<width$.1x}")
            );
            let expected = Expected(&upper);
            assert_eq!(
                format!("{view:+#0width$X}"),
                format!("{expected:+#0width$X}")
            );
            cases += 1;
        }
    }
    let bytes = [0xab; 1024];
    let mut writer = LimitedWriter {
        bytes: [0; 32],
        length: 0,
        failed: false,
    };
    assert!(write!(&mut writer, "{}", Hex::new(&bytes)).is_err());
    assert!(writer.failed);
    assert_eq!(&writer.bytes, b"abababababababababababababababab");
    cases + 1
}

fn array_cases<const N: usize>() {
    let bytes: [u8; N] = core::array::from_fn(|index| (index * 73) as u8);
    let lower = reference(&bytes, false);
    let upper = reference(&bytes, true);
    assert_eq!(
        faster_hex::hex_decode_array::<N>(lower.as_bytes()).unwrap(),
        bytes
    );
    assert_eq!(
        faster_hex::hex_decode_array_with_case::<N>(upper.as_bytes(), CheckCase::Upper).unwrap(),
        bytes
    );
    assert!(
        matches!(faster_hex::hex_decode_array::<N>(format!("{lower}00").as_bytes()),
                     Err(Error::LengthMismatch { expected, actual, .. }) if expected == N && actual == N + 1)
    );
    #[cfg(alloc_api)]
    {
        assert_eq!(faster_hex::hex_decode_vec(lower.as_bytes()).unwrap(), bytes);
        assert_eq!(
            faster_hex::hex_decode_vec_with_case(upper.as_bytes(), CheckCase::Upper).unwrap(),
            bytes
        );
        assert_eq!(faster_hex::hex_decode_vec(b"g"), Err(Error::OddLength));
        assert!(matches!(
            faster_hex::hex_decode_vec(b"0x"),
            Err(Error::InvalidChar {
                index: 1,
                byte: b'x',
                ..
            })
        ));
    }
}

#[no_mangle]
pub extern "C" fn owned_cases() -> u32 {
    array_cases::<0>();
    array_cases::<1>();
    array_cases::<16>();
    array_cases::<32>();
    array_cases::<33>();
    array_cases::<64>();
    array_cases::<129>();
    array_cases::<256>();
    assert_eq!(
        faster_hex::hex_decode_array::<0>(b"g"),
        Err(Error::OddLength)
    );
    assert!(matches!(
        faster_hex::hex_decode_array::<1>(b"g0"),
        Err(Error::InvalidChar {
            index: 0,
            byte: b'g',
            ..
        })
    ));
    10
}
