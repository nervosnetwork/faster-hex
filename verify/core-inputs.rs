use faster_hex::{hex_check_with_case, hex_encode, hex_encode_upper, CheckCase};

#[test]
fn byte_order_and_case_at_vector_boundaries() {
    for len in 0..=161 {
        let src: Vec<u8> = (0..len).map(|i| (i * 151 + 37) as u8).collect();
        let base: String = src.iter().map(|b| format!("{b:02x}")).collect();
        let mut out = vec![0xa5; len * 2 + 1];
        assert_eq!(
            hex_encode(&src, &mut out).unwrap().as_bytes(),
            base.as_bytes()
        );
        assert_eq!(
            hex_encode_upper(&src, &mut out).unwrap().as_bytes(),
            base.to_ascii_uppercase().as_bytes(),
        );
        assert_eq!(out.last(), Some(&0xa5));
    }
}

#[test]
fn every_digit_and_location_matches_the_ascii_policy() {
    for len in [31, 32, 33, 63, 64, 65, 127, 128, 129, 159, 160, 257] {
        let mut src = vec![b'0'; len];
        for pos in 0..len {
            for byte in u8::MIN..=u8::MAX {
                src[pos] = byte;
                for (mode, valid) in [
                    (CheckCase::None, byte.is_ascii_hexdigit()),
                    (
                        CheckCase::Upper,
                        byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte),
                    ),
                    (
                        CheckCase::Lower,
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
                    ),
                ] {
                    assert_eq!(hex_check_with_case(&src, mode), valid, "{len} {pos} {byte}");
                }
            }
            src[pos] = b'0';
        }
    }
}

#[test]
fn every_valid_pair_decodes_at_each_vector_position() {
    let alphabet = b"0123456789ABCDEFabcdef";
    let mut text = Vec::new();
    let mut expected = Vec::new();
    for &hi in alphabet {
        for &lo in alphabet {
            text.extend_from_slice(&[hi, lo]);
            let hi = char::from(hi).to_digit(16).unwrap();
            let lo = char::from(lo).to_digit(16).unwrap();
            expected.push((hi * 16 + lo) as u8);
        }
    }
    let mut decoded = vec![0; expected.len()];
    for _ in 0..32 {
        faster_hex::hex_decode(&text, &mut decoded).unwrap();
        assert_eq!(decoded, expected);
        text.rotate_left(2);
        expected.rotate_left(1);
    }
}

#[test]
fn adjacent_blocks_and_the_final_window_keep_the_suffix_untouched() {
    for n in 96..=321 {
        let expected: Vec<_> = (0..n).map(|i| (151 * i + 73) as u8).collect();
        let text = faster_hex::hex_string(&expected);
        let mut output = vec![0xa5; n + 1];
        assert_eq!(
            faster_hex::hex_decode(text.as_bytes(), &mut output).unwrap(),
            expected
        );
        assert_eq!(output[n], 0xa5);
    }
}

#[test]
fn case_errors_in_either_region_leave_the_full_destination_untouched() {
    use faster_hex::{hex_decode_with_case, Error};

    for n in 95..=257 {
        let mut text = vec![b'0'; n * 2];
        let sentinel = vec![0xa5; n + 3];
        let mut out = sentinel.clone();
        for (mode, rejected) in [
            (CheckCase::None, b'g'),
            (CheckCase::Lower, b'A'),
            (CheckCase::Upper, b'a'),
        ] {
            for index in 0..text.len() {
                text[index] = rejected;
                assert!(matches!(
                    hex_decode_with_case(&text, &mut out, mode),
                    Err(Error::InvalidChar { index: at, byte, .. }) if at == index && byte == rejected
                ));
                assert_eq!(out, sentinel);
                text[index] = b'0';
            }
        }
    }
}
