use faster_hex::{hex_decode_with_case, CheckCase, Error};

#[test]
fn every_byte_matches_each_case_before_storing() {
    for mode in [CheckCase::None, CheckCase::Lower, CheckCase::Upper] {
        for size in 8..=32 {
            let mut input = vec![b'0'; 2 * size];
            for index in 0..input.len() {
                for byte in 0..=u8::MAX {
                    input[index] = byte;
                    let mut dst = vec![0x55; size + 1];
                    let value = match byte {
                        b'0'..=b'9' => Some(byte - b'0'),
                        b'A'..=b'F' if mode != CheckCase::Lower => Some(byte - b'A' + 10),
                        b'a'..=b'f' if mode != CheckCase::Upper => Some(byte - b'a' + 10),
                        _ => None,
                    };
                    let res = hex_decode_with_case(&input, &mut dst, mode);
                    if let Some(nibble) = value {
                        let mut expected = vec![0; size];
                        expected[index/2] = if index%2 == 0 { nibble << 4 } else { nibble };
                        assert_eq!(res.unwrap(),expected);
                        assert_eq!(dst[size],0x55);
                    } else {
                        assert!(matches!(res,Err(Error::InvalidChar {index: i, byte: b, ..}) if i==index && b==byte));
                        assert!(dst.iter().all(|&b|b==0x55));
                    }
                }
                input[index]=b'0';
            }
        }
    }
}
