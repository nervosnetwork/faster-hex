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
