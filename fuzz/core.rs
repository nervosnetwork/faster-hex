//! Shared by AFL, libFuzzer and the corpus coverage replay.
//!
//! Numeric controls select length/alignment/faults independently of payload.
//! No input is filtered out. Even empty inputs drive a multi-block conversion;
//! a second length explores the short/bounded/overlapping-tail thresholds.

use faster_hex::{
    fuzzing::backends, hex_decode_array_with_case, hex_decode_with_case, CheckCase, Error,
};

const BOUNDARIES: &[usize] = &[
    0, 1, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 255, 256, 257,
    1023, 1024, 1025, 4096,
];
const CANARY: u8 = 0xa5;

fn ascii(nibble: u8, upper: bool) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => (if upper { b'A' } else { b'a' }) + nibble - 10,
    }
}

fn intact(buffer: &[u8], offset: usize, written: usize) {
    assert!(buffer[..offset]
        .iter()
        .chain(&buffer[offset + written..])
        .all(|&b| b == CANARY));
}

pub fn exercise(data: &[u8]) {
    let control = |i| data.get(i).copied().unwrap_or(0);
    let source_offset = usize::from(control(0) % 64);
    let target_offset = usize::from(control(1) % 64);
    let payload = data.get(4..).unwrap_or_default();
    for len in [
        BOUNDARIES[usize::from(control(2)) % BOUNDARIES.len()],
        65 + usize::from(control(3)) % 193,
    ] {
        let mut source = vec![CANARY; source_offset + len];
        for (i, byte) in source[source_offset..source_offset + len]
            .iter_mut()
            .enumerate()
        {
            *byte = if payload.is_empty() {
                (i as u8).wrapping_mul(37)
            } else {
                payload[i % payload.len()]
            };
        }
        let raw = &source[source_offset..source_offset + len];
        for case in [CheckCase::Lower, CheckCase::Upper, CheckCase::None] {
            // Decode input is made independently of every encoder under test.
            let mut text = vec![CANARY; source_offset + len * 2];
            for (i, &byte) in raw.iter().enumerate() {
                for (j, nibble) in [byte >> 4, byte & 15].into_iter().enumerate() {
                    let upper = case == CheckCase::Upper || (case == CheckCase::None && i % 2 == j);
                    text[source_offset + i * 2 + j] = ascii(nibble, upper);
                }
            }
            let text = &mut text[source_offset..source_offset + len * 2];
            if len == 4 {
                assert_eq!(hex_decode_array_with_case::<4>(text, case).unwrap(), raw);
            }
            if len == 1025 {
                assert_eq!(hex_decode_array_with_case::<1025>(text, case).unwrap(), raw);
            }
            for backend in backends() {
                let mut output = vec![CANARY; target_offset + len * 2 + 32];
                if case != CheckCase::None {
                    backend.encode(
                        raw,
                        &mut output[target_offset..target_offset + len * 2],
                        case == CheckCase::Upper,
                    );
                    assert_eq!(&output[target_offset..target_offset + len * 2], text);
                    intact(&output, target_offset, len * 2);
                }
                assert!(backend.check(text, case));
                output.fill(CANARY);
                assert!(backend.decode(
                    text,
                    &mut output[target_offset..target_offset + len],
                    case
                ));
                assert_eq!(&output[target_offset..target_offset + len], raw);
                intact(&output, target_offset, len);
                output.fill(CANARY);
                assert!(backend.decode_owned(
                    text,
                    &mut output[target_offset..target_offset + len],
                    case
                ));
                assert_eq!(&output[target_offset..target_offset + len], raw);
                intact(&output, target_offset, len);
                if text.is_empty() {
                    continue;
                }
                // Checkers also accept valid odd-length strings. Decoders only
                // receive complete pairs, so no length error can mask a fault.
                assert!(backend.check(&text[..text.len() - 1], case));
                let selected =
                    usize::from(u16::from_le_bytes([control(4), control(5)])) % text.len();
                for position in [selected, text.len() - 1] {
                    let original = text[position];
                    let candidate = control(3);
                    let valid = match case {
                        CheckCase::Lower => {
                            candidate.is_ascii_digit() || (b'a'..=b'f').contains(&candidate)
                        }
                        CheckCase::Upper => {
                            candidate.is_ascii_digit() || (b'A'..=b'F').contains(&candidate)
                        }
                        _ => candidate.is_ascii_hexdigit(),
                    };
                    text[position] = if valid { b'?' } else { candidate };
                    output.fill(CANARY);
                    assert!(!backend.check(text, case));
                    assert!(!backend.decode(
                        text,
                        &mut output[target_offset..target_offset + len],
                        case
                    ));
                    intact(&output, 0, 0);
                    // The public boundary must report this exact late fault,
                    // including case errors, without changing any destination byte.
                    assert!(matches!(
                        hex_decode_with_case(text, &mut output[target_offset..], case),
                        Err(Error::InvalidChar { index, byte, .. })
                            if index == position && byte == text[position]
                    ));
                    intact(&output, 0, 0);
                    if len == 4 {
                        assert!(matches!(hex_decode_array_with_case::<4>(text, case),
                            Err(Error::InvalidChar { index, byte, .. })
                                if index == position && byte == text[position]));
                    }
                    if len == 1025 {
                        assert!(matches!(hex_decode_array_with_case::<1025>(text, case),
                            Err(Error::InvalidChar { index, byte, .. })
                                if index == position && byte == text[position]));
                    }
                    assert!(!backend.decode_owned(
                        text,
                        &mut output[target_offset..target_offset + len],
                        case
                    ));
                    // Owned output is discarded on error; only bytes outside
                    // the destination are required to retain their canaries.
                    intact(&output, target_offset, len);
                    text[position] = original;
                }
            }
        }
    }
}
