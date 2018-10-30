#[cfg(test)]
#[macro_use]
extern crate proptest;
#[cfg(test)]
extern crate hex;

mod encode;

pub use encode::{hex_string, hex_to};

#[cfg(test)]
mod tests {
    use super::*;
    use encode::hex_string;
    use std::str;

    fn _test_hex(s: &String) {
        let mut buffer = vec![0; s.as_bytes().len() * 2];
        hex_to(s.as_bytes(), &mut buffer).unwrap();
        let encode = unsafe { str::from_utf8_unchecked(&buffer[..s.as_bytes().len() * 2]) };

        let hex_string = hex_string(s.as_bytes()).unwrap();

        assert_eq!(encode, hex::encode(s));
        assert_eq!(hex_string, hex::encode(s));
    }

    proptest! {
        #[test]
        fn test_hex(ref s in ".*") {
            _test_hex(s);
        }
    }
}
