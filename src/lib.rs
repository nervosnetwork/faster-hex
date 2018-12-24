mod decode;
mod encode;
pub use crate::decode::{hex_decode, hex_decode_fallback};
pub use crate::encode::{hex_encode, hex_encode_fallback, hex_string, hex_to};

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

        let hex_string = hex_string(s.as_bytes()).unwrap();

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

        let hex_string = hex_string(s.as_bytes()).unwrap();

        hex_decode(hex_string.as_bytes(), &mut dst).unwrap();

        assert_eq!(&dst[..], s.as_bytes());
    }

    proptest! {
        #[test]
        fn test_hex_decode(ref s in ".*") {
            _test_hex_decode(s);
        }
    }
}
