use faster_hex::{hex_check_with_case, hex_encode, hex_encode_upper, CheckCase};

#[test]
fn byte_order_and_case_at_vector_boundaries() {
    for len in 0..=161 {
        let src: Vec<u8> = (0..len).map(|i| (i * 151 + 37) as u8).collect();
        let base: String = src.iter().map(|b| format!("{b:02x}")).collect();
        let mut out = vec![0xa5; len * 2 + 1];
        assert_eq!(hex_encode(&src, &mut out).unwrap(), base);
        assert_eq!(hex_encode_upper(&src, &mut out).unwrap(), base.to_ascii_uppercase());
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
                    (CheckCase::Upper, byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)),
                    (CheckCase::Lower, byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                ] {
                    assert_eq!(hex_check_with_case(&src, mode), valid, "{len} {pos} {byte}");
                }
            }
            src[pos] = b'0';
        }
    }
}
