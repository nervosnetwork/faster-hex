#![warn(missing_docs)]

use core::iter::FromIterator;

mod internal {
    use crate::{
        decode::{hex_decode_with_case, CheckCase},
        encode::hex_encode_custom,
    };
    use alloc::{borrow::Cow, string::String, vec, vec::Vec};
    use core::{fmt, iter::FromIterator};
    use serde::{
        de::{Error, Unexpected, Visitor},
        Deserialize, Deserializer, Serialize, Serializer,
    };

    // Serde's Cow<str> deserializer always allocates. This adapter preserves
    // String's deserialize_string hint and accepted inputs, but borrows text
    // that the format can lend (for example, unescaped JSON from a slice).
    struct Text<'a>(Cow<'a, str>);

    impl<'de> Deserialize<'de> for Text<'de> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct TextVisitor;

            impl<'de> Visitor<'de> for TextVisitor {
                type Value = Text<'de>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("a string")
                }

                fn visit_str<E: Error>(self, text: &str) -> Result<Self::Value, E> {
                    Ok(Text(Cow::Owned(text.into())))
                }

                fn visit_borrowed_str<E: Error>(self, text: &'de str) -> Result<Self::Value, E> {
                    Ok(Text(Cow::Borrowed(text)))
                }

                fn visit_string<E: Error>(self, text: String) -> Result<Self::Value, E> {
                    Ok(Text(Cow::Owned(text)))
                }

                fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                    match core::str::from_utf8(bytes) {
                        Ok(text) => self.visit_str(text),
                        Err(_) => Err(E::invalid_value(Unexpected::Bytes(bytes), &self)),
                    }
                }

                fn visit_borrowed_bytes<E: Error>(
                    self,
                    bytes: &'de [u8],
                ) -> Result<Self::Value, E> {
                    match core::str::from_utf8(bytes) {
                        Ok(text) => self.visit_borrowed_str(text),
                        Err(_) => Err(E::invalid_value(Unexpected::Bytes(bytes), &self)),
                    }
                }

                fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
                    match String::from_utf8(bytes) {
                        Ok(text) => self.visit_string(text),
                        Err(error) => {
                            Err(E::invalid_value(Unexpected::Bytes(error.as_bytes()), &self))
                        }
                    }
                }
            }
            deserializer.deserialize_string(TextVisitor)
        }
    }

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
        let src = data.as_ref();
        let prefix: &[u8] = if with_prefix { b"0x" } else { b"" };
        let len = src
            .len()
            .checked_mul(2)
            .and_then(|len| len.checked_add(prefix.len()))
            .ok_or_else(|| serde::ser::Error::custom(crate::Error::Overflow))?;
        // Hashes and short identifiers fit on the stack, including the prefix.
        // Initialize only the storage selected for this call.
        let mut stack;
        let mut heap;
        let dst = if len <= 130 {
            stack = [0; 130];
            &mut stack[..len]
        } else {
            heap = vec![0; len];
            &mut heap
        };
        dst[..prefix.len()].copy_from_slice(prefix);
        hex_encode_custom(src, &mut dst[prefix.len()..], case == CheckCase::Upper)
            .map_err(serde::ser::Error::custom)?;
        // SAFETY: The prefix and encoder initialized the complete output as ASCII.
        serializer.serialize_str(unsafe { core::str::from_utf8_unchecked(dst) })
    }

    fn payload<E: Error>(text: &str, with_prefix: bool) -> Result<&str, E> {
        let text = if with_prefix {
            text.strip_prefix("0x")
                .ok_or_else(|| E::custom("invalid prefix"))?
        } else {
            text
        };
        if !text.len().is_multiple_of(2) {
            return Err(E::custom("invalid length"));
        }
        Ok(text)
    }

    fn decode<E: Error>(
        text: &str,
        with_prefix: bool,
        case: CheckCase,
        max_bytes: usize,
    ) -> Result<Vec<u8>, E> {
        let text = payload::<E>(text, with_prefix)?;
        let len = text.len() / 2;
        if len > max_bytes {
            return Err(E::custom(format_args!(
                "expected at most {max_bytes} decoded bytes, got {len}"
            )));
        }
        let mut bytes = vec![0; len];
        hex_decode_with_case(text.as_bytes(), &mut bytes, case).map_err(E::custom)?;
        Ok(bytes)
    }

    fn decode_array<E: Error, const N: usize>(
        text: &str,
        with_prefix: bool,
        case: CheckCase,
    ) -> Result<[u8; N], E> {
        let text = payload::<E>(text, with_prefix)?;
        let actual = text.len() / 2;
        if actual != N {
            return Err(E::custom(format_args!(
                "expected {N} decoded bytes, got {actual}"
            )));
        }
        let mut bytes = [0; N];
        hex_decode_with_case(text.as_bytes(), &mut bytes, case).map_err(E::custom)?;
        Ok(bytes)
    }

    pub(crate) fn deserialize_array<'de, D, const N: usize>(
        deserializer: D,
        with_prefix: bool,
        case: CheckCase,
    ) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = Text::deserialize(deserializer)?;
        decode_array(&text.0, with_prefix, case)
    }

    pub(crate) fn deserialize_option_array<'de, D, const N: usize>(
        deserializer: D,
        with_prefix: bool,
        case: CheckCase,
    ) -> Result<Option<[u8; N]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Text>::deserialize(deserializer)?
            .map(|text| decode_array(&text.0, with_prefix, case))
            .transpose()
    }

    pub(crate) fn deserialize<'de, D, T>(
        deserializer: D,
        with_prefix: bool,
        check_case: CheckCase,
        max_bytes: usize,
    ) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromIterator<u8>,
    {
        let text = Text::deserialize(deserializer)?;
        decode(&text.0, with_prefix, check_case, max_bytes).map(|bytes| bytes.into_iter().collect())
    }

    pub(crate) fn serialize_option<S, T>(
        data: &Option<T>,
        serializer: S,
        with_prefix: bool,
        case: CheckCase,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        // Some serializers attach an Option tag before serializing its value.
        // Give them a hex representation that implements Serde's value protocol.
        struct Hex<'a> {
            data: &'a [u8],
            with_prefix: bool,
            case: CheckCase,
        }

        impl Serialize for Hex<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serialize(self.data, serializer, self.with_prefix, self.case)
            }
        }

        match data {
            Some(data) => serializer.serialize_some(&Hex {
                data: data.as_ref(),
                with_prefix,
                case,
            }),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize_option<'de, D, T>(
        deserializer: D,
        with_prefix: bool,
        check_case: CheckCase,
        max_bytes: usize,
    ) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: FromIterator<u8>,
    {
        // Let Serde retain its complete Option protocol, including untagged
        // handling; the same decoder serves both optional and required text.
        let bytes = Option::<Text>::deserialize(deserializer)?
            .map(|text| decode(&text.0, with_prefix, check_case, max_bytes))
            .transpose()?;
        Ok(bytes.map(|bytes| bytes.into_iter().collect()))
    }
}

/// Serializes a byte view as lowercase hex with a `0x` prefix.
///
/// Available with `serde`. This is the default serializer used by
/// `#[serde(with = "faster_hex")]`. It accepts any `AsRef<[u8]>`, reads that view
/// once, and writes a Serde string in every format, including binary formats.
/// Empty bytes serialize as `"0x"`. Use a named policy module to change the
/// prefix or letter case.
///
/// # Errors
///
/// Returns the serializer's error if writing the string fails, or if the encoded
/// length including the prefix cannot be represented as a `usize`.
///
/// # Panics
///
/// Panics if temporary output storage would exceed `isize::MAX` bytes. Allocation
/// failure follows the allocator's error handling. No particular allocation count
/// is guaranteed.
///
/// # Examples
///
/// ```
/// #[derive(serde::Serialize)]
/// struct Record {
///     #[serde(with = "faster_hex")]
///     bytes: Vec<u8>,
/// }
///
/// let value = Record { bytes: vec![0xab, 1] };
/// assert_eq!(serde_json::to_string(&value)?, r#"{"bytes":"0xab01"}"#);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: AsRef<[u8]>,
{
    withpfx_ignorecase::serialize(data, serializer)
}

/// Deserializes a `0x`-prefixed hex string into a byte collection.
///
/// Available with `serde`. This is the default deserializer for
/// `#[serde(with = "faster_hex")]`. The prefix must be exactly `0x`; payload
/// letters may use either case, including mixed case. Whitespace and separators
/// are rejected. `"0x"` produces an empty collection.
///
/// Decoded bytes are collected into `T: FromIterator<u8>`, such as `Vec<u8>` or
/// `VecDeque<u8>`. Input text is borrowed when the format can lend it; transient,
/// escaped or owned text may require storage. Use [`array`](mod@crate::array)
/// for `[u8; N]` fields, or [`deserialize_bounded`] to limit decoded output.
///
/// # Errors
///
/// Propagates deserializer errors, including invalid input types or UTF-8. Once
/// text is available, checks the prefix, even payload length, then characters,
/// in that order. Character diagnostics report the first invalid byte and its
/// byte position within the payload, excluding `0x`. Collection starts only
/// after successful decoding.
///
/// # Panics
///
/// A custom collector may panic, for example when its fixed capacity is exceeded.
/// This adapter does not provide fallible collection. Allocation failure follows
/// the allocator's error handling.
///
/// # Examples
///
/// ```
/// #[derive(serde::Deserialize)]
/// struct Record {
///     #[serde(with = "faster_hex")]
///     bytes: Vec<u8>,
/// }
///
/// let value: Record = serde_json::from_str(r#"{"bytes":"0x00aB"}"#)?;
/// assert_eq!(value.bytes, [0, 0xab]);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromIterator<u8>,
{
    withpfx_ignorecase::deserialize(deserializer)
}

/// Deserializes at most `MAX` decoded bytes from a `0x`-prefixed hex string.
///
/// Available with `serde`. The prefix, case and collection behavior is the same
/// as [`deserialize`]. `MAX` counts decoded bytes, so at most twice that many
/// hex digits are accepted. A zero limit accepts `"0x"`.
///
/// The limit is checked before allocating decoded output or invoking the collector.
/// It does not limit input text storage used by the format, error-message storage,
/// or allocations performed by a custom collector. It also does not constrain
/// serialization; pair this function with the ordinary [`serialize`] function.
///
/// # Errors
///
/// Propagates deserializer errors. After obtaining text, checks the prefix, even
/// payload length, the decoded-byte limit, then characters/case, in that order.
/// An over-limit value is rejected even if it also contains invalid hex digits.
///
/// # Panics
///
/// A custom collector can still panic when full; the acceptance limit does not
/// change its capacity or collection implementation. Allocation failure follows
/// the allocator's error handling.
///
/// # Examples
///
/// ```
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct Packet {
///     #[serde(
///         serialize_with = "faster_hex::serialize",
///         deserialize_with = "faster_hex::deserialize_bounded::<2, _, _>"
///     )]
///     bytes: Vec<u8>,
/// }
///
/// let packet: Packet = serde_json::from_str(r#"{"bytes":"0xab01"}"#)?;
/// assert_eq!(packet.bytes, [0xab, 1]);
/// assert!(serde_json::from_str::<Packet>(r#"{"bytes":"0x000102"}"#).is_err());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn deserialize_bounded<'de, const MAX: usize, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromIterator<u8>,
{
    withpfx_ignorecase::deserialize_bounded::<MAX, D, T>(deserializer)
}

// Required and optional adapters share one prefix/case policy declaration.
macro_rules! serde_adapters {
    ($mod_name:ident, $option_name:ident, $with_pfx:expr, $check_case:expr, $prefix:literal, $description:literal) => {
        #[doc = $description]
        #[doc = concat!(
            r###"Available with `serde`. Use this module with `#[serde(with = "...")]` for
byte collections. [`serialize`](fn@crate::"###,
                stringify!($mod_name),
                r###"::serialize) reads one `AsRef<[u8]>` view; [`deserialize`](fn@crate::"###,
                stringify!($mod_name),
                r###"::deserialize)
collects into `FromIterator<u8>`. All formats use strings, not binary byte arrays.

A required prefix is exactly `0x`, never `0X`. Payloads contain only ASCII hex
digits, with no whitespace or separators. Empty payloads are accepted.
For exact-length arrays use [`array`](mod@crate::"###,
                stringify!($mod_name),
                r###"::array); for an acceptance limit use
[`deserialize_bounded`](fn@crate::"###,
                stringify!($mod_name),
                r###"::deserialize_bounded). See each function for errors and allocation behavior.

# Examples

```
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Record {
    #[serde(with = "faster_hex::"###,
            stringify!($mod_name),
            r###"")]
    bytes: Vec<u8>,
}

let record = Record { bytes: vec![0x12, 0x34] };
let json = serde_json::to_string(&record)?;
assert_eq!(json, r#"{"bytes":""###,
            $prefix,
            r###"1234"}"#);
assert_eq!(serde_json::from_str::<Record>(&json)?, record);
# Ok::<(), serde_json::Error>(())
```
"###
        )]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        pub mod $mod_name {
            use crate::decode::CheckCase;
            use crate::serde::internal;
            use core::iter::FromIterator;

            #[doc = concat!(
                r###"Serializes a byte view as a hex string with this module's prefix/case policy.

Reads `AsRef<[u8]>` once. Every format receives a string; no byte-array protocol
is selected for binary formats. See the [module](mod@crate::"###,
                stringify!($mod_name),
                r###") for attribute usage.

# Errors

Propagates serializer errors and reports encoded-length arithmetic overflow.

# Panics

Panics if temporary output storage would exceed `isize::MAX` bytes. Allocation
failure follows the allocator's error handling; allocation counts are unspecified.

# Examples

```
use faster_hex::"###,
                stringify!($mod_name),
                r###";

let mut output = Vec::new();
let mut serializer = serde_json::Serializer::new(&mut output);
"###,
                stringify!($mod_name),
                r###"::serialize([0x12, 0x34], &mut serializer)?;
assert_eq!(output, br#"""###,
                $prefix,
                r###"1234""#);
# Ok::<(), serde_json::Error>(())
```
"###
            )]
            pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
                T: AsRef<[u8]>,
            {
                internal::serialize(data, serializer, $with_pfx, $check_case)
            }

            #[doc = concat!(
                r###"Deserializes a hex string into a byte collection using this module's policy.

The string hint is preserved, and input text is borrowed when the format permits
it. Transient or escaped text may require storage. Decoded bytes are collected
into `T`; use [`array`](mod@crate::"###,
                stringify!($mod_name),
                r###"::array) for exact arrays or [`deserialize_bounded`](fn@crate::"###,
                stringify!($mod_name),
                r###"::deserialize_bounded) for a limit.

# Errors

Propagates format/type/UTF-8 errors. After obtaining text, validates the prefix,
even payload length, then characters and case, in that order. Invalid-byte
positions count bytes within the payload, excluding any prefix. Collection
starts only after the complete payload has been decoded successfully.

# Panics

The collector can panic, including on fixed-capacity exhaustion. Allocation
failure follows the allocator's error handling.

# Examples

```
use faster_hex::"###,
                stringify!($mod_name),
                r###";

let mut deserializer = serde_json::Deserializer::from_str(r#"""###,
                $prefix,
                r###"1234""#);
let bytes: Vec<u8> = "###,
                stringify!($mod_name),
                r###"::deserialize(&mut deserializer)?;
assert_eq!(bytes, [0x12, 0x34]);
# Ok::<(), serde_json::Error>(())
```
"###
            )]
            pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: FromIterator<u8>,
            {
                internal::deserialize(deserializer, $with_pfx, $check_case, usize::MAX)
            }

            #[doc = concat!(
                r###"Deserializes at most `MAX` decoded bytes using this module's prefix/case policy.

The limit counts decoded bytes, not hex characters. `MAX == 0` accepts an empty
payload. The decoded vector is allocated and the collector is invoked only after
the limit check. Input text storage, error-message storage and collector-internal
allocations are not bounded. Serialization remains the ordinary [`serialize`](fn@crate::"###,
                stringify!($mod_name),
                r###"::serialize).

# Errors

Propagates deserializer errors. After obtaining text, checks prefix, even payload
length, decoded-byte limit, then character/case validity, in that order.

# Panics

A fixed-capacity collector can still panic when full. Allocation failure follows
the allocator's error handling.

# Examples

```
use faster_hex::"###,
                stringify!($mod_name),
                r###";

let mut deserializer = serde_json::Deserializer::from_str(r#"""###,
                $prefix,
                r###"1234""#);
let bytes: Vec<u8> = "###,
                stringify!($mod_name),
                r###"::deserialize_bounded::<2, _, _>(&mut deserializer)?;
assert_eq!(bytes, [0x12, 0x34]);
let mut too_long = serde_json::Deserializer::from_str(r#"""###,
                $prefix,
                r###"123456""#);
assert!("###,
                stringify!($mod_name),
                r###"::deserialize_bounded::<2, _, Vec<u8>>(&mut too_long).is_err());
# Ok::<(), serde_json::Error>(())
```
"###
            )]
            pub fn deserialize_bounded<'de, const MAX: usize, D, T>(
                deserializer: D,
            ) -> Result<T, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: FromIterator<u8>,
            {
                internal::deserialize(deserializer, $with_pfx, $check_case, MAX)
            }

            #[doc = concat!(
                r###"Exact-length byte arrays using this module's prefix and case policy.

Available with `serde`. Deserialization returns `[u8; N]` and requires exactly
`N` decoded bytes. It writes directly into the array without an intermediate
byte vector. Input text is borrowed where possible; the format may still need
storage for escaped or transient text. Any const array length is supported.

[`serialize`](fn@crate::"###,
                stringify!($mod_name),
                r###"::serialize) is the parent module's byte-view serializer. Array length is
checked on deserialization; no length metadata is added to the string format.

# Examples

```
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Record {
    #[serde(with = "faster_hex::"###,
                stringify!($mod_name),
                r###"::array")]
    id: [u8; 2],
}

let record = Record { id: [0x12, 0x34] };
let json = serde_json::to_string(&record)?;
assert_eq!(json, r#"{"id":""###,
                $prefix,
                r###"1234"}"#);
assert_eq!(serde_json::from_str::<Record>(&json)?, record);
assert!(serde_json::from_str::<Record>(r#"{"id":""###,
                $prefix,
                r###"12"}"#).is_err());
# Ok::<(), serde_json::Error>(())
```
"###
            )]
            pub mod array {
                use super::{internal, CheckCase};

                pub use super::serialize;

                #[doc = concat!(
                    r###"Deserializes exactly `N` bytes into an owned array.

The result does not borrow the input. No intermediate decoded vector is
allocated, although input text storage depends on the format. An empty payload
succeeds only for `N == 0`.

# Errors

Propagates deserializer errors. Checks prefix, even payload length, exact decoded
length, then invalid byte/case, in that order. Length diagnostics count decoded
bytes; invalid-byte positions count payload bytes, excluding the prefix.

# Examples

```
use faster_hex::"###,
                    stringify!($mod_name),
                    r###"::array;

let mut deserializer = serde_json::Deserializer::from_str(r#"""###,
                    $prefix,
                    r###"1234""#);
let bytes: [u8; 2] = array::deserialize(&mut deserializer)?;
assert_eq!(bytes, [0x12, 0x34]);
# Ok::<(), serde_json::Error>(())
```
"###
                )]
                pub fn deserialize<'de, D, const N: usize>(
                    deserializer: D,
                ) -> Result<[u8; N], D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    internal::deserialize_array(deserializer, $with_pfx, $check_case)
                }
            }
        }
        #[doc = concat!($description, " Optional values.")]
        #[doc = concat!(
            r###"Available with `serde`. This module handles `Option<T>` using the same
prefix and case policy as the required adapter. Present values are hex strings;
absent values use the format's `None` representation (`null` in JSON).
Serde's `Some`/`None` tags are preserved in binary formats, so `Some(empty)`
remains distinct from `None`.

Use `#[serde(default)]` alongside `with` to treat a missing struct field as
`None`. For fixed-length arrays use [`array`](mod@crate::"###,
                stringify!($option_name),
                r###"::array); for present values with a
size limit use [`deserialize_bounded`](fn@crate::"###,
                stringify!($option_name),
                r###"::deserialize_bounded).

# Examples

```
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Record {
    #[serde(default, with = "faster_hex::"###,
            stringify!($option_name),
            r###"")]
    bytes: Option<Vec<u8>>,
}

let record = Record { bytes: Some(vec![0x12, 0x34]) };
let json = serde_json::to_string(&record)?;
assert_eq!(json, r#"{"bytes":""###,
            $prefix,
            r###"1234"}"#);
assert_eq!(serde_json::from_str::<Record>(&json)?, record);
assert_eq!(serde_json::from_str::<Record>(r#"{"bytes":null}"#)?.bytes, None);
assert_eq!(serde_json::from_str::<Record>("{}")?.bytes, None);
# Ok::<(), serde_json::Error>(())
```
"###
        )]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        pub mod $option_name {
            use crate::decode::CheckCase;
            use crate::serde::internal;
            use core::iter::FromIterator;

            #[doc = concat!(
                r###"Serializes an optional byte view while preserving Serde's Option tags.

`None` becomes the format's absent-value representation. A present value uses
this module's hex string policy, even when its byte slice is empty. Its
`AsRef<[u8]>` view is read once. JSON uses `null` for `None`; binary formats
retain their normal `Some`/`None` distinction.

# Errors

Propagates serializer errors and reports encoded-length arithmetic overflow.

# Panics

Panics if temporary output storage would exceed `isize::MAX` bytes. Allocation
failure follows the allocator's error handling.

# Examples

```
use faster_hex::"###,
                stringify!($option_name),
                r###";

let mut output = Vec::new();
let mut serializer = serde_json::Serializer::new(&mut output);
"###,
                stringify!($option_name),
                r###"::serialize(&Some([0x12, 0x34]), &mut serializer)?;
assert_eq!(output, br#"""###,
                $prefix,
                r###"1234""#);
# Ok::<(), serde_json::Error>(())
```
"###
            )]
            pub fn serialize<S, T>(data: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
                T: AsRef<[u8]>,
            {
                internal::serialize_option(data, serializer, $with_pfx, $check_case)
            }

            #[doc = concat!(
                r###"Deserializes an optional hex string into an optional byte collection.

Absent values become `None`; present strings follow this module's prefix/case
policy and are collected into `T: FromIterator<u8>`. A present empty payload
becomes `Some(empty)`, never `None`. For missing struct fields, add
`#[serde(default)]` as shown in the [module](mod@crate::"###,
                stringify!($option_name),
                r###") example.

# Errors

Propagates format/Option/type/UTF-8 errors. Present text is checked for prefix,
even payload length, then character/case validity before collection. Invalid
hex is an error rather than an absent value. Byte positions exclude any prefix.

# Panics

A fixed-capacity collector can panic when full. Allocation failure follows
the allocator's error handling.

# Examples

```
use faster_hex::"###,
                stringify!($option_name),
                r###";

let mut deserializer = serde_json::Deserializer::from_str("null");
let bytes: Option<Vec<u8>> = "###,
                stringify!($option_name),
                r###"::deserialize(&mut deserializer)?;
assert_eq!(bytes, None);
let mut present = serde_json::Deserializer::from_str(r#"""###,
                $prefix,
                r###"1234""#);
let bytes: Option<Vec<u8>> = "###,
                stringify!($option_name),
                r###"::deserialize(&mut present)?;
assert_eq!(bytes, Some(vec![0x12, 0x34]));
# Ok::<(), serde_json::Error>(())
```
"###
            )]
            pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: FromIterator<u8>,
            {
                internal::deserialize_option(deserializer, $with_pfx, $check_case, usize::MAX)
            }

            #[doc = concat!(
                r###"Deserializes an optional collection of at most `MAX` decoded bytes.

`None` is accepted, including when `MAX == 0`; a present empty payload remains
`Some(empty)`. Present values follow the prefix/case policy of this module.
The limit precedes decoded-output allocation and collection, but does not bound
input/error storage or allocations inside a custom collector. Serialization is
unchanged; use the existing [`serialize`](fn@crate::"###,
                stringify!($option_name),
                r###"::serialize) function.

# Errors

Propagates deserializer errors. Present text is checked for prefix, even payload
length, the decoded-byte limit, then character/case validity, in that order.
An invalid or over-limit present value is an error, not `None`.

# Panics

A fixed-capacity collector can still panic when full. Allocation failure follows
the allocator's error handling.

# Examples

```
use faster_hex::"###,
                stringify!($option_name),
                r###";

let mut deserializer = serde_json::Deserializer::from_str(r#"""###,
                $prefix,
                r###"1234""#);
let bytes: Option<Vec<u8>> = "###,
                stringify!($option_name),
                r###"::deserialize_bounded::<2, _, _>(&mut deserializer)?;
assert_eq!(bytes, Some(vec![0x12, 0x34]));
let mut absent = serde_json::Deserializer::from_str("null");
let bytes: Option<Vec<u8>> = "###,
                stringify!($option_name),
                r###"::deserialize_bounded::<0, _, _>(&mut absent)?;
assert_eq!(bytes, None);
# Ok::<(), serde_json::Error>(())
```
"###
            )]
            pub fn deserialize_bounded<'de, const MAX: usize, D, T>(
                deserializer: D,
            ) -> Result<Option<T>, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: FromIterator<u8>,
            {
                internal::deserialize_option(deserializer, $with_pfx, $check_case, MAX)
            }

            #[doc = concat!(
                r###"Optional fixed-length arrays using this module's prefix and case policy.

Available with `serde`. Present values must decode to exactly `N` bytes and are
written directly into `[u8; N]`, without an intermediate byte vector. The format
may still allocate input text storage. `None` and `Some([])` remain distinct,
including in binary formats. Use `#[serde(default)]` to accept a missing field.

# Examples

```
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Record {
    #[serde(default, with = "faster_hex::"###,
                stringify!($option_name),
                r###"::array")]
    id: Option<[u8; 2]>,
}

let record = Record { id: Some([0x12, 0x34]) };
let json = serde_json::to_string(&record)?;
assert_eq!(json, r#"{"id":""###,
                $prefix,
                r###"1234"}"#);
assert_eq!(serde_json::from_str::<Record>(&json)?, record);
assert_eq!(serde_json::from_str::<Record>("{}")?.id, None);
# Ok::<(), serde_json::Error>(())
```
"###
            )]
            pub mod array {
                use super::{internal, CheckCase};

                pub use super::serialize;

                #[doc = concat!(
                    r###"Deserializes an optional array containing exactly `N` bytes.

Absent values become `None`; present text produces an owned array with no
intermediate decoded vector. Empty present payloads are accepted only when
`N == 0`. Input text storage depends on the deserializer.

# Errors

Propagates deserializer errors. Present text is checked for prefix, even payload
length, exact decoded length, then characters/case, in that order. Invalid input
is an error, not `None`. Lengths count decoded bytes; byte positions exclude the
prefix.

# Examples

```
use faster_hex::"###,
                    stringify!($option_name),
                    r###"::array;

let mut deserializer = serde_json::Deserializer::from_str(r#"""###,
                    $prefix,
                    r###"1234""#);
let bytes: Option<[u8; 2]> = array::deserialize(&mut deserializer)?;
assert_eq!(bytes, Some([0x12, 0x34]));
# Ok::<(), serde_json::Error>(())
```
"###
                )]
                pub fn deserialize<'de, D, const N: usize>(
                    deserializer: D,
                ) -> Result<Option<[u8; N]>, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    internal::deserialize_option_array(deserializer, $with_pfx, $check_case)
                }
            }
        }
    };
}

serde_adapters!(
    withpfx_ignorecase,
    option_withpfx_ignorecase,
    true,
    CheckCase::None,
    "0x",
    "Lowercase serialization with a 0x prefix; accepts either letter case."
);
serde_adapters!(
    nopfx_ignorecase,
    option_nopfx_ignorecase,
    false,
    CheckCase::None,
    "",
    "Lowercase serialization without a prefix; accepts either letter case."
);
serde_adapters!(
    withpfx_lowercase,
    option_withpfx_lowercase,
    true,
    CheckCase::Lower,
    "0x",
    "Lowercase hex with a required 0x prefix."
);
serde_adapters!(
    nopfx_lowercase,
    option_nopfx_lowercase,
    false,
    CheckCase::Lower,
    "",
    "Lowercase hex without a prefix."
);
serde_adapters!(
    withpfx_uppercase,
    option_withpfx_uppercase,
    true,
    CheckCase::Upper,
    "0x",
    "Uppercase hex with a required 0x prefix."
);
serde_adapters!(
    nopfx_uppercase,
    option_nopfx_uppercase,
    false,
    CheckCase::Upper,
    "",
    "Uppercase hex without a prefix."
);

#[cfg(test)]
mod tests {
    use super::{
        nopfx_ignorecase, nopfx_lowercase, nopfx_uppercase, option_nopfx_ignorecase,
        option_nopfx_lowercase, option_nopfx_uppercase, option_withpfx_ignorecase,
        option_withpfx_lowercase, option_withpfx_uppercase, withpfx_ignorecase, withpfx_lowercase,
        withpfx_uppercase,
    };
    use crate as faster_hex;
    use bytes::Bytes;
    use proptest::proptest;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Simple {
        #[serde(with = "faster_hex")]
        bar: Vec<u8>,
    }

    #[test]
    fn test_deserialize_escaped() {
        // 0x03 but escaped.
        let x: Simple = serde_json::from_str(
            r#"{
            "bar": "\u0030x\u00303"
        }"#,
        )
        .unwrap();
        assert_eq!(x.bar, b"\x03");
    }

    fn _test_simple(src: &str) {
        let simple = Simple { bar: src.into() };
        let result = serde_json::to_string(&simple);
        assert!(result.is_ok());
        let result = result.unwrap();

        // #[serde(with = "faster_hex")] should result with 0x prefix
        assert!(result.starts_with(r#"{"bar":"0x"#));

        // #[serde(with = "faster_hex")] shouldn't contains uppercase
        assert!(result[7..].chars().all(|c| !c.is_uppercase()));

        let decode_simple = serde_json::from_str::<Simple>(&result);
        assert!(decode_simple.is_ok());
        assert_eq!(decode_simple.unwrap(), simple);
    }

    proptest! {
        #[test]
        fn test_simple(ref s in ".*") {
            _test_simple(s);
        }
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Foo {
        #[serde(with = "nopfx_lowercase")]
        bar_nopfx_lowercase_vec: Vec<u8>,
        #[serde(with = "nopfx_lowercase")]
        bar_nopfx_lowercase_bytes: Bytes,

        #[serde(with = "withpfx_lowercase")]
        bar_withpfx_lowercase_vec: Vec<u8>,
        #[serde(with = "withpfx_lowercase")]
        bar_withpfx_lowercase_bytes: Bytes,

        #[serde(with = "nopfx_uppercase")]
        bar_nopfx_uppercase_vec: Vec<u8>,
        #[serde(with = "nopfx_uppercase")]
        bar_nopfx_uppercase_bytes: Bytes,

        #[serde(with = "withpfx_uppercase")]
        bar_withpfx_uppercase_vec: Vec<u8>,
        #[serde(with = "withpfx_uppercase")]
        bar_withpfx_uppercase_bytes: Bytes,

        #[serde(with = "withpfx_ignorecase")]
        bar_withpfx_ignorecase_vec: Vec<u8>,
        #[serde(with = "withpfx_ignorecase")]
        bar_withpfx_ignorecase_bytes: Bytes,

        #[serde(with = "nopfx_ignorecase")]
        bar_nopfx_ignorecase_vec: Vec<u8>,
        #[serde(with = "nopfx_ignorecase")]
        bar_nopfx_ignorecase_bytes: Bytes,

        #[serde(with = "option_nopfx_ignorecase")]
        bar_nopfx_ignorecase_vec_option: Option<Vec<u8>>,
        #[serde(with = "option_nopfx_ignorecase")]
        bar_nopfx_ignorecase_bytes_option: Option<Bytes>,

        #[serde(with = "option_withpfx_ignorecase")]
        bar_withpfx_ignorecase_vec_option: Option<Vec<u8>>,
        #[serde(with = "option_withpfx_ignorecase")]
        bar_withpfx_ignorecase_bytes_option: Option<Bytes>,

        #[serde(with = "option_nopfx_lowercase")]
        bar_nopfx_lowercase_vec_option: Option<Vec<u8>>,
        #[serde(with = "option_nopfx_lowercase")]
        bar_nopfx_lowercase_bytes_option: Option<Bytes>,

        #[serde(with = "option_withpfx_lowercase")]
        bar_withpfx_lowercase_vec_option: Option<Vec<u8>>,
        #[serde(with = "option_withpfx_lowercase")]
        bar_withpfx_lowercase_bytes_option: Option<Bytes>,

        #[serde(with = "option_nopfx_uppercase")]
        bar_nopfx_uppercase_vec_option: Option<Vec<u8>>,
        #[serde(with = "option_nopfx_uppercase")]
        bar_nopfx_uppercase_bytes_option: Option<Bytes>,

        #[serde(with = "option_withpfx_uppercase")]
        bar_withpfx_uppercase_vec_option: Option<Vec<u8>>,
        #[serde(with = "option_withpfx_uppercase")]
        bar_withpfx_uppercase_bytes_option: Option<Bytes>,
    }

    #[test]
    fn test_serde_default() {
        {
            let foo_defuault = Foo {
                bar_nopfx_lowercase_vec: vec![],
                bar_nopfx_lowercase_bytes: Default::default(),
                bar_withpfx_lowercase_vec: vec![],
                bar_withpfx_lowercase_bytes: Default::default(),
                bar_nopfx_uppercase_vec: vec![],
                bar_nopfx_uppercase_bytes: Default::default(),
                bar_withpfx_uppercase_vec: vec![],
                bar_withpfx_uppercase_bytes: Default::default(),
                bar_withpfx_ignorecase_vec: vec![],
                bar_withpfx_ignorecase_bytes: Default::default(),
                bar_nopfx_ignorecase_vec: vec![],
                bar_nopfx_ignorecase_bytes: Default::default(),
                bar_nopfx_ignorecase_vec_option: Default::default(),
                bar_nopfx_ignorecase_bytes_option: Default::default(),
                bar_withpfx_ignorecase_vec_option: Default::default(),
                bar_withpfx_ignorecase_bytes_option: Default::default(),
                bar_nopfx_lowercase_vec_option: Default::default(),
                bar_nopfx_lowercase_bytes_option: Default::default(),
                bar_withpfx_lowercase_vec_option: Default::default(),
                bar_withpfx_lowercase_bytes_option: Default::default(),
                bar_nopfx_uppercase_vec_option: Default::default(),
                bar_nopfx_uppercase_bytes_option: Default::default(),
                bar_withpfx_uppercase_vec_option: Default::default(),
                bar_withpfx_uppercase_bytes_option: Default::default(),
            };
            let serde_result = serde_json::to_string(&foo_defuault).unwrap();
            let expect = r#"
{"bar_nopfx_lowercase_vec":"",
"bar_nopfx_lowercase_bytes":"",
"bar_withpfx_lowercase_vec":"0x",
"bar_withpfx_lowercase_bytes":"0x",
"bar_nopfx_uppercase_vec":"",
"bar_nopfx_uppercase_bytes":"",
"bar_withpfx_uppercase_vec":"0x",
"bar_withpfx_uppercase_bytes":"0x",
"bar_withpfx_ignorecase_vec":"0x",
"bar_withpfx_ignorecase_bytes":"0x",
"bar_nopfx_ignorecase_vec":"",
"bar_nopfx_ignorecase_bytes":"",
"bar_nopfx_ignorecase_vec_option":null,
"bar_nopfx_ignorecase_bytes_option":null,
"bar_withpfx_ignorecase_vec_option":null,
"bar_withpfx_ignorecase_bytes_option":null,
"bar_nopfx_lowercase_vec_option":null,
"bar_nopfx_lowercase_bytes_option":null,
"bar_withpfx_lowercase_vec_option":null,
"bar_withpfx_lowercase_bytes_option":null,
"bar_nopfx_uppercase_vec_option":null,
"bar_nopfx_uppercase_bytes_option":null,
"bar_withpfx_uppercase_vec_option":null,
"bar_withpfx_uppercase_bytes_option":null}"#;

            let expect = expect.replace('\n', "");
            assert_eq!(serde_result, expect);

            let foo_src: Foo = serde_json::from_str(&serde_result).unwrap();
            assert_eq!(foo_defuault, foo_src);
        }
    }

    fn _test_serde(src: &str) {
        let foo = Foo {
            bar_nopfx_lowercase_vec: Vec::from(src),
            bar_nopfx_lowercase_bytes: Bytes::from(Vec::from(src)),
            bar_withpfx_lowercase_vec: Vec::from(src),
            bar_withpfx_lowercase_bytes: Bytes::from(Vec::from(src)),
            bar_nopfx_uppercase_vec: Vec::from(src),
            bar_nopfx_uppercase_bytes: Bytes::from(Vec::from(src)),
            bar_withpfx_uppercase_vec: Vec::from(src),
            bar_withpfx_uppercase_bytes: Bytes::from(Vec::from(src)),

            bar_withpfx_ignorecase_vec: Vec::from(src),
            bar_withpfx_ignorecase_bytes: Bytes::from(Vec::from(src)),
            bar_nopfx_ignorecase_vec: Vec::from(src),
            bar_nopfx_ignorecase_bytes: Bytes::from(Vec::from(src)),
            bar_withpfx_ignorecase_vec_option: Some(Vec::from(src)),
            bar_nopfx_ignorecase_bytes_option: Some(Bytes::from(Vec::from(src))),
            bar_nopfx_ignorecase_vec_option: Some(Vec::from(src)),
            bar_withpfx_ignorecase_bytes_option: Some(Bytes::from(Vec::from(src))),
            bar_nopfx_lowercase_vec_option: Some(Vec::from(src)),
            bar_nopfx_lowercase_bytes_option: Some(Bytes::from(Vec::from(src))),
            bar_withpfx_lowercase_vec_option: Some(Vec::from(src)),
            bar_withpfx_lowercase_bytes_option: Some(Bytes::from(Vec::from(src))),
            bar_nopfx_uppercase_vec_option: Some(Vec::from(src)),
            bar_nopfx_uppercase_bytes_option: Some(Bytes::from(Vec::from(src))),
            bar_withpfx_uppercase_vec_option: Some(Vec::from(src)),
            bar_withpfx_uppercase_bytes_option: Some(Bytes::from(Vec::from(src))),
        };
        let hex_str = hex::encode(src);
        let hex_str_upper = hex::encode_upper(src);
        let serde_result = serde_json::to_string(&foo).unwrap();

        let expect = format!(
            r#"{{"bar_nopfx_lowercase_vec":"{}",
"bar_nopfx_lowercase_bytes":"{}",
"bar_withpfx_lowercase_vec":"0x{}",
"bar_withpfx_lowercase_bytes":"0x{}",
"bar_nopfx_uppercase_vec":"{}",
"bar_nopfx_uppercase_bytes":"{}",
"bar_withpfx_uppercase_vec":"0x{}",
"bar_withpfx_uppercase_bytes":"0x{}",
"bar_withpfx_ignorecase_vec":"0x{}",
"bar_withpfx_ignorecase_bytes":"0x{}",
"bar_nopfx_ignorecase_vec":"{}",
"bar_nopfx_ignorecase_bytes":"{}",
"bar_nopfx_ignorecase_vec_option":"{}",
"bar_nopfx_ignorecase_bytes_option":"{}",
"bar_withpfx_ignorecase_vec_option":"0x{}",
"bar_withpfx_ignorecase_bytes_option":"0x{}",
"bar_nopfx_lowercase_vec_option":"{}",
"bar_nopfx_lowercase_bytes_option":"{}",
"bar_withpfx_lowercase_vec_option":"0x{}",
"bar_withpfx_lowercase_bytes_option":"0x{}",
"bar_nopfx_uppercase_vec_option":"{}",
"bar_nopfx_uppercase_bytes_option":"{}",
"bar_withpfx_uppercase_vec_option":"0x{}",
"bar_withpfx_uppercase_bytes_option":"0x{}"}}"#,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str_upper,
            hex_str_upper,
            hex_str_upper,
            hex_str_upper,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str,
            hex_str_upper,
            hex_str_upper,
            hex_str_upper,
            hex_str_upper,
        );
        let expect = expect.replace('\n', "");
        assert_eq!(serde_result, expect);

        let foo_src: Foo = serde_json::from_str(&serde_result).unwrap();
        assert_eq!(foo, foo_src);
    }

    proptest! {
        #[test]
        fn test_serde(ref s in ".*") {
            _test_serde(s);
        }
    }

    fn _test_serde_deserialize(src: &str) {
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct FooNoPfxLower {
            #[serde(with = "nopfx_lowercase")]
            bar: Vec<u8>,
        }

        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct FooWithPfxLower {
            #[serde(with = "withpfx_lowercase")]
            bar: Vec<u8>,
        }

        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct FooNoPfxUpper {
            #[serde(with = "nopfx_uppercase")]
            bar: Vec<u8>,
        }
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct FooWithPfxUpper {
            #[serde(with = "withpfx_uppercase")]
            bar: Vec<u8>,
        }

        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct FooNoPfxIgnoreCase {
            #[serde(with = "nopfx_ignorecase")]
            bar: Vec<u8>,
        }
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct FooWithPfxIgnoreCase {
            #[serde(with = "withpfx_ignorecase")]
            bar: Vec<u8>,
        }

        let upper = serde_json::to_string(&FooWithPfxUpper { bar: src.into() }).unwrap();
        let decoded: FooWithPfxIgnoreCase = serde_json::from_str(&upper).unwrap();
        assert_eq!(decoded.bar, src.as_bytes());
        let lower = serde_json::to_string(&FooNoPfxLower { bar: src.into() }).unwrap();
        let decoded: FooNoPfxIgnoreCase = serde_json::from_str(&lower).unwrap();
        assert_eq!(decoded.bar, src.as_bytes());

        {
            let hex_foo = serde_json::to_string(&FooNoPfxLower { bar: src.into() }).unwrap();
            let foo_pfx: serde_json::Result<FooWithPfxLower> = serde_json::from_str(&hex_foo);
            // assert foo_pfx is Error, and contains "invalid prefix"
            assert!(foo_pfx.is_err());
            assert!(foo_pfx.unwrap_err().to_string().contains("invalid prefix"));
        }

        {
            let foo_lower = serde_json::to_string(&FooNoPfxLower { bar: src.into() }).unwrap();
            let foo_upper_result: serde_json::Result<FooNoPfxUpper> =
                serde_json::from_str(&foo_lower);
            if let Some((index, byte)) = hex::encode(src)
                .bytes()
                .enumerate()
                .find(|(_, byte)| byte.is_ascii_lowercase())
            {
                // FooNoPfxLower's foo field is lowercase, so we can't deserialize it to FooNoPfxUpper
                assert!(foo_upper_result.is_err());
                assert!(foo_upper_result
                    .unwrap_err()
                    .to_string()
                    .contains(&format!("invalid hex byte 0x{byte:02x} at index {index}")));
            }
        }
    }

    proptest! {
        #[test]
        fn test_serde_deserialize(ref s in ".*") {
            _test_serde_deserialize(s);
        }
    }
}
