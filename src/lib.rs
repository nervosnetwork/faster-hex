mod decode;
mod encode;
mod error;
pub use crate::decode::{decode, decode_to_slice, decode_to_slice_unchecked};
pub use crate::encode::{encode, encode_to_slice};
pub use crate::error::Error;

#[cfg(feature = "bench")]
pub use crate::decode::{
    arch::avx2::check as check_avx2,
    arch::fallback::{
        check as check_fallback, decode as decode_fallback,
        decode_unchecked as decode_unchecked_fallback,
    },
    arch::sse41::check as check_sse,
};
#[cfg(feature = "bench")]
pub use crate::encode::encode_fallback;

#[cfg(test)]
mod tests {
    use crate::decode::decode;
    use crate::encode::{encode, encode_to_slice};
    use proptest::{proptest, proptest_helper};
    use std::str;

    fn _test_encode(s: &String) {
        let mut buffer = vec![0; s.as_bytes().len() * 2];
        encode_to_slice(s.as_bytes(), &mut buffer).unwrap();
        let encoded = unsafe { str::from_utf8_unchecked(&buffer[..s.as_bytes().len() * 2]) };

        let hex_string = encode(s);

        assert_eq!(encoded, hex::encode(s));
        assert_eq!(hex_string, hex::encode(s));
    }

    proptest! {
        #[test]
        fn test_encode(ref s in ".*") {
            _test_encode(s);
        }
    }

    fn _test_decode_check(s: &String, ok: bool) {
        assert!(decode(s).is_ok() == ok);
    }

    proptest! {
        #[test]
        fn test_decode_check(ref s in "([0-9a-fA-F][0-9a-fA-F])+") {
            _test_decode_check(s, true);
        }
    }

    proptest! {
        #[test]
        fn test_decode_check_odd(ref s in "[0-9a-fA-F]{11}") {
            _test_decode_check(s, false);
        }
    }

    proptest! {
        #[test]
        fn test_roundtrip(input: Vec<u8>) {
            let encoded = encode(&input);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(&decoded, &input);
        }

        #[test]
        fn test_encode_matches(input: Vec<u8>) {
            let encoded = encode(&input);
            let expected = hex::encode(&input);
            assert_eq!(encoded, expected);
        }

        #[test]
        fn test_decode_matches(input: Vec<u8>) {
            let decoded = decode(&input).map_err(|_| ());
            let expected = hex::decode(&input).map_err(|_| ());
            assert_eq!(decoded, expected);
        }
    }
}
