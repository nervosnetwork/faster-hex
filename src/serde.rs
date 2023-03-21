#![warn(missing_docs)]

use std::iter::FromIterator;

mod internal {
    use crate::{
        decode::{hex_decode_with_case, CheckCase},
        encode::hex_encode_custom,
    };
    use serde::{de::Error, Deserializer, Serializer};
    use std::iter::FromIterator;

    pub(crate) fn serialize<S, T>(
        data: T,
        serializer: S,
        with_prefix: bool,
        case: CheckCase,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        let src: &[u8] = data.as_ref();

        let mut dst_length = data.as_ref().len() << 1;
        if with_prefix {
            dst_length += 2;
        }

        let mut dst = vec![0u8; dst_length];
        let mut dst_start = 0;
        if with_prefix {
            dst[0] = b'0';
            dst[1] = b'x';

            dst_start = 2;
        }

        hex_encode_custom(src, &mut dst[dst_start..], matches!(case, CheckCase::Upper))
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(unsafe { ::std::str::from_utf8_unchecked(&dst) })
    }

    pub(crate) fn deserialize<'de, D, T>(
        deserializer: D,
        with_prefix: bool,
        check_case: CheckCase,
    ) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromIterator<u8>,
    {
        let raw_src: &[u8] = serde::Deserialize::deserialize(deserializer)?;
        if with_prefix && (raw_src.len() < 2 || raw_src[0] != b'0' || raw_src[1] != b'x') {
            return Err(D::Error::custom("invalid prefix".to_string()));
        }

        let src: &[u8] = {
            if with_prefix {
                &raw_src[2..]
            } else {
                raw_src
            }
        };

        if src.len() & 1 != 0 {
            return Err(D::Error::custom("invalid length".to_string()));
        }

        // we have already checked src's length, so src's length is a even integer
        let mut dst = vec![0; src.len() >> 1];
        hex_decode_with_case(src, &mut dst, check_case)
            .map_err(|e| Error::custom(format!("{:?}", e)))?;
        Ok(dst.into_iter().collect())
    }
}

/// Serde: Serialize with 0x-prefix and ignore case
pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: AsRef<[u8]>,
{
    withpfx_ignorecase::serialize(data, serializer)
}

/// Serde: Deserialize with 0x-prefix and ignore case
pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromIterator<u8>,
{
    withpfx_ignorecase::deserialize(deserializer)
}

/// Generate module with serde methods
#[macro_export]
macro_rules! faster_hex_serde_macros {
    ($mod_name:ident, $with_pfx:expr, $check_case:expr) => {
        /// Serialize and deserialize with or without 0x-prefix,
        /// and lowercase or uppercase or ignorecase
        pub mod $mod_name {
            use crate::decode::CheckCase;
            use crate::serde::internal;
            use std::iter::FromIterator;

            /// Serializes `data` as hex string
            pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
                T: AsRef<[u8]>,
            {
                internal::serialize(data, serializer, $with_pfx, $check_case)
            }

            /// Deserializes a hex string into raw bytes.
            pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: FromIterator<u8>,
            {
                internal::deserialize(deserializer, $with_pfx, $check_case)
            }
        }
    };
}

// /// Serialize with 0x-prefix and lowercase
// /// When deserialize, expect 0x-prefix and don't care case
faster_hex_serde_macros!(withpfx_ignorecase, true, CheckCase::None);
// /// Serialize without 0x-prefix and lowercase
// /// When deserialize, expect without 0x-prefix and don't care case
faster_hex_serde_macros!(nopfx_ignorecase, false, CheckCase::None);
// /// Serialize with 0x-prefix and lowercase
// /// When deserialize, expect with 0x-prefix and lower case
faster_hex_serde_macros!(withpfx_lowercase, true, CheckCase::Lower);
// /// Serialize without 0x-prefix and lowercase
// /// When deserialize, expect without 0x-prefix and lower case
faster_hex_serde_macros!(nopfx_lowercase, false, CheckCase::Lower);

// /// Serialize with 0x-prefix and upper case
// /// When deserialize, expect with 0x-prefix and upper case
faster_hex_serde_macros!(withpfx_uppercase, true, CheckCase::Upper);
// /// Serialize without 0x-prefix and upper case
// /// When deserialize, expect without 0x-prefix and upper case
faster_hex_serde_macros!(nopfx_uppercase, false, CheckCase::Upper);
