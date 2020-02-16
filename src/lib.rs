mod decode;
mod encode;
mod error;
pub use crate::decode::{hex_decode, hex_decode_unchecked};
pub use crate::encode::{hex_encode, hex_encode_fallback, hex_string};
pub use crate::error::Error;

#[allow(deprecated)]
pub use crate::encode::hex_to;

#[cfg(feature = "bench")]
pub use crate::decode::{
    arch::avx2::hex_check as hex_check_avx2,
    arch::fallback::{
        hex_check as hex_check_fallback, hex_decode as hex_decode_fallback,
        hex_decode_unchecked as hex_decode_unchecked_fallback,
    },
};

#[cfg(test)]
mod tests {
    use crate::decode::hex_decode;
    use crate::encode::{hex_encode, hex_string};
    use proptest::{proptest, proptest_helper};
    use std::str;

    fn _test_hex_encode(s: &String) {
        let mut buffer = vec![0; s.as_bytes().len() * 2];
        hex_encode(s.as_bytes(), &mut buffer).unwrap();
        let encode = unsafe { str::from_utf8_unchecked(&buffer[..s.as_bytes().len() * 2]) };

        let hex_string = hex_string(s.as_bytes());

        assert_eq!(encode, hex::encode(s));
        assert_eq!(hex_string, hex::encode(s));
    }

    proptest! {
        #[test]
        fn test_hex_encode(ref s in ".*") {
            _test_hex_encode(s);
        }
    }

    fn _test_hex_decode(s: &String) {
        let len = s.as_bytes().len();
        let mut dst = Vec::with_capacity(len);
        dst.resize(len, 0);

        let hex_string = hex_string(s.as_bytes());

        hex_decode(hex_string.as_bytes(), &mut dst).unwrap();

        assert_eq!(&dst[..], s.as_bytes());
    }

    proptest! {
        #[test]
        fn test_hex_decode(ref s in ".+") {
            _test_hex_decode(s);
        }
    }

    fn _test_hex_decode_check(s: &String, ok: bool) {
        let len = s.as_bytes().len();
        let mut dst = Vec::with_capacity(len / 2);
        dst.resize(len / 2, 0);
        assert!(hex_decode(s.as_bytes(), &mut dst).is_ok() == ok);
    }

    proptest! {
        #[test]
        fn test_hex_decode_check(ref s in "([0-9a-fA-F][0-9a-fA-F])+") {
            _test_hex_decode_check(s, true);
        }
    }

    proptest! {
        #[test]
        fn test_hex_decode_check_odd(ref s in "[0-9a-fA-F]{11}") {
            _test_hex_decode_check(s, false);
        }
    }

    proptest! {
        #[test]
        fn test_roundtrip(input: Vec<u8>) {
            let mut encoded = vec![0; input.len() * 2];
            hex_encode(&input, &mut encoded).unwrap();
            let mut decoded = vec![0; input.len()];
            hex_decode(&encoded, &mut decoded).unwrap();
            assert_eq!(&decoded, &input);
        }
    }
}
