use faster_hex::{
    hex_check_with_case, hex_decode_with_case, hex_encode, hex_encode_upper, CheckCase, Error,
};

#[path = "core.rs"]
mod core;

fn digit(byte: u8, case: CheckCase) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' if case != CheckCase::Upper => Some(byte - b'a' + 10),
        b'A'..=b'F' if case != CheckCase::Lower => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn exercise(data: &[u8]) {
    core::exercise(data);
    let (header, input) = data.split_at(data.len().min(4));
    let control = |i| header.get(i).copied().unwrap_or(0);
    let source_offset = usize::from(control(0) % 32);
    let target_offset = usize::from(control(1) % 32);
    let destination_len =
        usize::from(u16::from_le_bytes([control(2), control(3)])) % (input.len() / 2 + 65);
    let mut source = vec![0; source_offset];
    source.extend_from_slice(input);
    let input = &source[source_offset..];

    // Arbitrary source bytes and an independently sized, unaligned destination.
    for case in [CheckCase::None, CheckCase::Lower, CheckCase::Upper] {
        let valid = input.iter().all(|b| digit(*b, case).is_some());
        assert_eq!(hex_check_with_case(input, case), valid);
        let mut output = vec![0xa5; target_offset + destination_len + 32];
        let result = hex_decode_with_case(
            input,
            &mut output[target_offset..target_offset + destination_len],
            case,
        );
        if !input.len().is_multiple_of(2) {
            assert_eq!(result.unwrap_err(), Error::OddLength);
        } else if destination_len < input.len() / 2 {
            assert!(
                matches!(result, Err(Error::OutputTooSmall { required, .. }) if required == input.len() / 2)
            );
        } else if let Some((position, &invalid)) = input
            .iter()
            .enumerate()
            .find(|(_, b)| digit(**b, case).is_none())
        {
            assert!(
                matches!(result, Err(Error::InvalidChar { index, byte, .. }) if (index, byte) == (position, invalid))
            );
        } else {
            assert_eq!(result.unwrap().len(), input.len() / 2);
            for (i, pair) in input.chunks_exact(2).enumerate() {
                assert_eq!(
                    output[target_offset + i],
                    digit(pair[0], case).unwrap() * 16 + digit(pair[1], case).unwrap()
                );
            }
            assert!(output[..target_offset]
                .iter()
                .chain(&output[target_offset + input.len() / 2..])
                .all(|b| *b == 0xa5));
            continue;
        }
        assert!(output.iter().all(|b| *b == 0xa5));
    }

    // Each fuzzer input also drives valid scalar/SIMD conversion in both cases.
    for upper in [false, true] {
        let mut encoded = vec![0xff; target_offset + input.len() * 2 + 32];
        let encode = if upper { hex_encode_upper } else { hex_encode };
        let written = encode(input, &mut encoded[target_offset..]).unwrap();
        assert_eq!(written.len(), input.len() * 2);
        for (pair, byte) in written.as_bytes().chunks_exact(2).zip(input) {
            let case = if upper {
                CheckCase::Upper
            } else {
                CheckCase::Lower
            };
            assert_eq!(digit(pair[0], case), Some(byte >> 4));
            assert_eq!(digit(pair[1], case), Some(byte & 15));
        }
        let hex_len = written.len();
        assert!(encoded[..target_offset]
            .iter()
            .chain(&encoded[target_offset + hex_len..])
            .all(|b| *b == 0xff));
        let encoded = &mut encoded[target_offset..target_offset + hex_len];
        let case = if upper {
            CheckCase::Upper
        } else {
            CheckCase::Lower
        };
        let mut decoded = vec![0xa5; source_offset + input.len() + 32];
        hex_decode_with_case(encoded, &mut decoded[source_offset..], case).unwrap();
        assert_eq!(&decoded[source_offset..source_offset + input.len()], input);
        assert!(decoded[..source_offset]
            .iter()
            .chain(&decoded[source_offset + input.len()..])
            .all(|b| *b == 0xa5));
        // Mix cases so valid decode is not restricted to the encoder's case policy.
        for (i, byte) in encoded.iter_mut().enumerate() {
            if i % 3 == 0 {
                *byte = byte.to_ascii_uppercase();
            }
        }
        decoded.fill(0xa5);
        hex_decode_with_case(encoded, &mut decoded[source_offset..], CheckCase::None).unwrap();
        assert_eq!(&decoded[source_offset..source_offset + input.len()], input);
        assert!(decoded[..source_offset]
            .iter()
            .chain(&decoded[source_offset + input.len()..])
            .all(|b| *b == 0xa5));

        if !input.is_empty() {
            let mut short = vec![0xa5; input.len() * 2 - 1];
            assert!(matches!(encode(input, &mut short),
                Err(Error::OutputTooSmall { required, .. }) if required == input.len() * 2));
            assert!(short.iter().all(|b| *b == 0xa5));
        }
    }
}
