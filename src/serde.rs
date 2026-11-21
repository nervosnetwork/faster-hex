#![warn(missing_docs)]

use core::iter::FromIterator;

mod internal {
    use crate::{
        decode::{hex_decode_vec_with_case, CheckCase},
        encode::encode,
    };
    use alloc::vec::Vec;
    use core::{fmt, mem::MaybeUninit};
    use serde::{
        de::{Error, Unexpected, Visitor},
        Deserializer, Serialize, Serializer,
    };

    // Defer hex diagnostics until the format has finished reading the whole
    // field, including its Option framing. A format error takes precedence.
    pub(super) type Field<T> = Result<T, FieldError>;

    #[derive(Clone, Copy)]
    pub(super) enum FieldError {
        Text(&'static str),
        Limit { max: usize, actual: usize },
        Hex(crate::Error),
    }

    impl fmt::Display for FieldError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Text(message) => f.write_str(message),
                Self::Limit { max, actual } => {
                    write!(f, "expected at most {max} decoded bytes, got {actual}")
                }
                Self::Hex(error) => error.fmt(f),
            }
        }
    }

    // The format determines how long each string lives. Short-lived values
    // must be consumed before their visit returns.
    enum Text<'de, T> {
        Borrowed(&'de str),
        Transient(T),
    }

    struct TextVisitor<F>(F);

    impl<'de, F: FnOnce(&str) -> T, T> Visitor<'de> for TextVisitor<F> {
        type Value = Text<'de, T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string")
        }
        #[inline(always)]
        fn visit_str<E: Error>(self, text: &str) -> Result<Self::Value, E> {
            Ok(Text::Transient((self.0)(text)))
        }
        #[inline(always)]
        fn visit_borrowed_str<E: Error>(self, text: &'de str) -> Result<Self::Value, E> {
            Ok(Text::Borrowed(text))
        }
        fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            match core::str::from_utf8(bytes) {
                Ok(s) => self.visit_str(s),
                Err(_) => Err(E::invalid_value(Unexpected::Bytes(bytes), &self)),
            }
        }
        fn visit_borrowed_bytes<E: Error>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
            match core::str::from_utf8(bytes) {
                Ok(s) => self.visit_borrowed_str(s),
                Err(_) => Err(E::invalid_value(Unexpected::Bytes(bytes), &self)),
            }
        }
    }

    pub(crate) fn serialize<S, T, P: Policy>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        let src = data.as_ref();
        let prefix: &[u8] = if P::PREFIX { b"0x" } else { b"" };
        let len = src
            .len()
            .checked_mul(2)
            .and_then(|len| len.checked_add(prefix.len()))
            .ok_or_else(|| serde::ser::Error::custom(crate::Error::Overflow))?;
        // Fixed values through 65 bytes (including H520) fit with the prefix.
        // Initialize only the storage selected for this call.
        let mut stack;
        let mut heap;
        let dst = if len <= 132 {
            stack = [MaybeUninit::uninit(); 132];
            &mut stack[..len]
        } else {
            heap = Vec::<u8>::with_capacity(len);
            &mut heap.spare_capacity_mut()[..len]
        };
        let (prefix_dst, body) = dst.split_at_mut(prefix.len());
        for (slot, &byte) in prefix_dst.iter_mut().zip(prefix) {
            slot.write(byte);
        }
        encode(src, body, P::CASE == CheckCase::Upper).map_err(serde::ser::Error::custom)?;
        // SAFETY: The prefix and encoder initialized all len bytes as ASCII.
        // MaybeUninit<u8> has u8's layout; unused capacity is excluded and the
        // backing stack buffer or allocation stays live throughout serialization.
        serializer.serialize_str(unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(dst.as_ptr().cast(), len))
        })
    }

    fn payload<E>(
        text: &str,
        with_prefix: bool,
        custom: impl Fn(&'static str) -> E,
    ) -> Result<&str, E> {
        let text = if with_prefix {
            text.strip_prefix("0x")
                .ok_or_else(|| custom("invalid prefix"))?
        } else {
            text
        };
        if !text.len().is_multiple_of(2) {
            return Err(custom("invalid length"));
        }
        Ok(text)
    }

    #[inline]
    pub(super) fn read<'de, D: Deserializer<'de>, T>(
        d: D,
        decode: impl Fn(&str) -> T,
    ) -> Result<T, D::Error> {
        match d.deserialize_string(TextVisitor(&decode))? {
            Text::Borrowed(text) => Ok(decode(text)),
            Text::Transient(field) => Ok(field),
        }
    }

    #[inline]
    pub(super) fn decode_bytes(
        text: &str,
        with_prefix: bool,
        case: CheckCase,
        max: usize,
    ) -> Field<Vec<u8>> {
        let src = payload(text, with_prefix, FieldError::Text)?.as_bytes();
        let actual = src.len() / 2;
        if actual > max {
            return Err(FieldError::Limit { max, actual });
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if actual <= 256 {
            #[expect(
                clippy::slow_vector_initialization,
                reason = "glibc handles small ordinary allocations faster than calloc"
            )]
            let mut bytes = Vec::with_capacity(actual);
            bytes.resize(actual, 0);
            crate::hex_decode_with_case(src, &mut bytes, case).map_err(FieldError::Hex)?;
            return Ok(bytes);
        }
        hex_decode_vec_with_case(src, case).map_err(FieldError::Hex)
    }

    // Keep storage for a large valid value off the wrong-length path.
    #[inline(never)]
    fn decode_payload<E: Error, const N: usize>(src: &[u8], case: CheckCase) -> Result<[u8; N], E> {
        crate::decode::decode_array_into(src, &mut MaybeUninit::uninit(), case)
            .copied()
            .map_err(E::custom)
    }

    pub(super) trait Policy {
        const PREFIX: bool;
        const CASE: CheckCase;

        #[inline(always)]
        fn fill<'a, const N: usize>(
            text: &str,
            storage: &'a mut MaybeUninit<[u8; N]>,
        ) -> Field<&'a [u8; N]> {
            let payload = payload(text, Self::PREFIX, FieldError::Text)?;
            crate::decode::decode_array_into(payload.as_bytes(), storage, Self::CASE)
                .map_err(FieldError::Hex)
        }

        #[inline(always)]
        fn decode<E: Error, const N: usize>(text: &str) -> Result<[u8; N], E> {
            let payload = payload(text, Self::PREFIX, E::custom)?;
            let actual = payload.len() / 2;
            if actual != N {
                return Err(E::custom(format_args!(
                    "expected {N} decoded bytes, got {actual}"
                )));
            }
            if N > 1024 {
                decode_payload(payload.as_bytes(), Self::CASE)
            } else {
                crate::decode::decode_array_into(
                    payload.as_bytes(),
                    &mut MaybeUninit::uninit(),
                    Self::CASE,
                )
                .copied()
                .map_err(E::custom)
            }
        }
    }

    #[inline(always)]
    fn with_array<'de, D: Deserializer<'de>, P: Policy, R, const N: usize>(
        d: D,
        finish: impl FnOnce(Text<'de, Field<&[u8; N]>>) -> Result<R, D::Error>,
    ) -> Result<R, D::Error> {
        let mut storage = MaybeUninit::uninit();
        let slot = &mut storage;
        let input = d.deserialize_string(TextVisitor(move |s: &str| {
            // Move this reference out of the one-shot visitor so the field can outlive the visit.
            let storage = slot;
            P::fill::<N>(s, storage)
        }))?;
        finish(input)
    }

    #[inline(always)]
    pub(super) fn array_field<'de, D: Deserializer<'de>, P: Policy, const N: usize>(
        d: D,
    ) -> Result<Field<[u8; N]>, D::Error> {
        with_array::<D, P, _, N>(d, |input| {
            Ok(match input {
                Text::Borrowed(text) => P::fill(text, &mut MaybeUninit::uninit()).copied(),
                Text::Transient(field) => field.copied(),
            })
        })
    }
    #[inline(always)]
    fn read_array<'de, D: Deserializer<'de>, P: Policy, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        with_array::<D, P, _, N>(d, |input| match input {
            Text::Borrowed(text) => P::decode(text),
            Text::Transient(field) => field.copied().map_err(D::Error::custom),
        })
    }

    // Keep a large returned array in one piece across the format boundary.
    #[inline(never)]
    fn read_large<T>(read: impl FnOnce() -> T) -> T {
        read()
    }

    #[inline(always)]
    pub(super) fn array_result<const N: usize, T>(read: impl FnOnce() -> T) -> T {
        if N > 1024 {
            read_large(read)
        } else {
            read()
        }
    }

    #[inline(always)]
    pub(crate) fn deserialize_array<'de, D: Deserializer<'de>, P: Policy, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        array_result::<N, _>(|| read_array::<D, P, N>(d))
    }

    pub(crate) fn serialize_option<S, T, P: Policy>(
        data: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        // Some serializers attach an Option tag before serializing its value.
        // Give them a hex representation that implements Serde's value protocol.
        struct HexValue<'a, P>(&'a [u8], core::marker::PhantomData<P>);

        impl<P: Policy> Serialize for HexValue<'_, P> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serialize::<_, _, P>(self.0, serializer)
            }
        }

        match data {
            Some(data) => {
                serializer.serialize_some(&HexValue::<P>(data.as_ref(), core::marker::PhantomData))
            }
            None => serializer.serialize_none(),
        }
    }
}

/// Serializes a byte view as lowercase hex with a `0x` prefix.
///
/// Available with `serde`. This is the default serializer used by
/// `#[serde(with = "faster_hex")]`. It accepts any [`AsRef<[u8]>`], reads that view
/// once, and writes a Serde string in every format, including binary formats.
/// Empty bytes serialize as `"0x"`. Use a named policy module to change the
/// prefix or letter case. Temporary storage may allocate; allocation failure
/// follows the allocator's error handling.
///
/// # Errors
///
/// Returns the serializer's error if writing the string fails, or if the encoded
/// length including the prefix cannot be represented as a `usize`.
///
/// # Panics
///
/// Panics if temporary output storage would exceed [`isize::MAX`] bytes.
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
/// Decoded bytes are collected into `T`, which implements [`FromIterator<u8>`],
/// for example [`Vec<u8>`](alloc::vec::Vec) or
/// [`VecDeque<u8>`](alloc::collections::VecDeque).
/// The adapter decodes directly from the text supplied by the format, including
/// transient strings. The format may buffer input such as escaped JSON.
/// Use [`array`](mod@crate::array) for `[u8; N]` fields, or
/// [`deserialize_bounded`] to limit decoded output.
/// Allocation failure follows the allocator's error handling.
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
/// This adapter does not provide fallible collection.
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
/// Allocation failure follows the allocator's error handling.
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
/// change its capacity or collection implementation.
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
                                    r###"
Use `#[serde(with = "...")]` for byte collections. Serialization reads one
[`AsRef<[u8]>`] view; deserialization collects into [`FromIterator<u8>`] after
validating the complete input. All formats use strings, including binary formats.

A required prefix is exactly `0x`. Payloads contain only ASCII hex digits;
empty payloads are accepted. For arrays use this module's [`array`] adapter;
for a decoded-byte limit use [`deserialize_bounded`].

# Examples

```
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Record {
    #[serde(with = "faster_hex::"###, stringify!($mod_name), r###"")]
    bytes: Vec<u8>,
}
let record = Record { bytes: vec![0x12, 0x34] };
let json = serde_json::to_string(&record)?;
assert_eq!(json, r#"{"bytes":""###, $prefix, r###"1234"}"#);
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

            pub(super) struct Format;

            impl internal::Policy for Format {
                const PREFIX: bool = $with_pfx;
                const CASE: CheckCase = $check_case;
            }

            pub(super) fn read_bytes<'de, const MAX: usize, D: serde::Deserializer<'de>>(
                d: D,
            ) -> Result<internal::Field<alloc::vec::Vec<u8>>, D::Error> {
                internal::read(d, |text| internal::decode_bytes(text, $with_pfx, $check_case, MAX))
            }

            /// Serializes a byte view using this module's prefix and case policy.
            ///
            /// Reads [`AsRef::as_ref`] once and sends a string to every serializer.
            /// Allocation behavior matches [`crate::serialize`].
            ///
            /// # Errors
            ///
            /// Returns an error if serialization fails or the encoded length overflows.
            ///
            /// # Panics
            ///
            /// Panics if temporary output storage would exceed [`isize::MAX`] bytes.
            ///
            /// # Examples
            ///
            /// See the [module example](self#examples).
            pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
                T: AsRef<[u8]>,
            {
                internal::serialize::<_, _, Format>(data, serializer)
            }

            /// Deserializes a hex string using this module's prefix and case policy.
            ///
            /// Decodes directly from the text supplied by the format.
            /// Allocation behavior matches [`crate::deserialize`].
            ///
            /// # Errors
            ///
            /// Propagates deserializer errors. Checks any required prefix, even payload
            /// length, then characters/case before collection. Positions exclude the prefix.
            ///
            /// # Panics
            ///
            /// A custom collector may panic, for example when its fixed capacity is exceeded.
            ///
            /// # Examples
            ///
            /// See the [module example](self#examples).
            pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: FromIterator<u8>,
            {
                deserialize_bounded::<{ usize::MAX }, _, _>(deserializer)
            }

            /// Deserializes at most `MAX` decoded bytes using this module's policy.
            ///
            /// The limit precedes decoded-output allocation and collection; it does not
            /// bound input, error or collector storage. `MAX == 0` accepts an empty payload.
            /// Allocation behavior matches [`crate::deserialize_bounded`].
            ///
            /// # Errors
            ///
            /// Propagates deserializer errors. Checks any required prefix, even length,
            /// decoded-byte limit, then characters/case. Byte positions exclude the prefix.
            ///
            /// # Panics
            ///
            /// A custom collector may still panic; the limit does not change its capacity.
            ///
            /// # Examples
            ///
            /// See [`crate::deserialize_bounded`] for the Serde field attributes.
            pub fn deserialize_bounded<'de, const MAX: usize, D, T>(
                deserializer: D,
            ) -> Result<T, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: FromIterator<u8>,
            {
                let bytes = read_bytes::<MAX, _>(deserializer)?
                    .map_err(serde::de::Error::custom)?;
                Ok(bytes.into_iter().collect())
            }

            /// Exact-length arrays using the parent module's prefix and case policy.
            ///
            /// Deserialization writes into `[u8; N]` without an intermediate byte vector.
            /// Input text is borrowed where possible; formats may need storage for
            /// escaped or transient text. Serialization uses the parent adapter's
            /// string representation, including any framing added by the format.
            #[doc = concat!(
                r###"
# Examples

```
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Record {
    #[serde(with = "faster_hex::"###, stringify!($mod_name), r###"::array")]
    id: [u8; 2],
}
let record = Record { id: [0x12, 0x34] };
let json = serde_json::to_string(&record)?;
assert_eq!(serde_json::from_str::<Record>(&json)?, record);
# Ok::<(), serde_json::Error>(())
```
"###
                                    )]
            pub mod array {
                use super::internal;

                pub use super::serialize;

                /// Deserializes exactly `N` bytes into an owned array.
                ///
                /// Empty payloads succeed only for `N == 0`.
                ///
                /// # Errors
                ///
                /// Checks any required prefix, even payload length, exact decoded length,
                /// then characters/case. Length errors count decoded bytes; invalid-byte
                /// positions exclude the prefix. Format errors propagate.
                ///
                /// # Examples
                ///
                /// See the [module example](self#examples).
                #[inline(always)]
                pub fn deserialize<'de, D, const N: usize>(
                    deserializer: D,
                ) -> Result<[u8; N], D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    internal::deserialize_array::<D, super::Format, N>(deserializer)
                }
            }
        }

        #[doc = concat!($description, " Optional values.")]
        #[doc = concat!(
                                    r###"
Present values follow [`"###, stringify!($mod_name), r###"`](crate::"###,
                                    stringify!($mod_name), r###"). Absent values use Serde's `None`
representation (`null` in JSON). Binary formats retain their normal [`Option`]
tags, so `Some(empty)` remains distinct from `None`.

Use `#[serde(default)]` to accept a missing struct field. For fixed arrays use
[`array`]; for a limit on present values use [`deserialize_bounded`].

# Examples

```
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Record {
    #[serde(default, with = "faster_hex::"###, stringify!($option_name), r###"")]
    bytes: Option<Vec<u8>>,
}
let record = Record { bytes: Some(vec![0x12, 0x34]) };
let json = serde_json::to_string(&record)?;
assert_eq!(serde_json::from_str::<Record>(&json)?, record);
assert_eq!(serde_json::from_str::<Record>("{}")?.bytes, None);
# Ok::<(), serde_json::Error>(())
```
"###
                                )]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        pub mod $option_name {
            use crate::serde::internal;
            use core::iter::FromIterator;

            /// Serializes an optional byte view, preserving Serde's [`Option`] tags.
            ///
            /// Present values use this module's hex string policy and read
            /// [`AsRef::as_ref`] once. `None` uses the format's absent-value representation.
            /// Allocation behavior matches [`crate::serialize`].
            ///
            /// # Errors
            ///
            /// Propagates serializer errors, including errors writing an Option tag.
            /// Present values also fail if their encoded length overflows.
            ///
            /// # Panics
            ///
            /// Panics if temporary output storage would exceed [`isize::MAX`] bytes.
            ///
            /// # Examples
            ///
            /// See the [module example](self#examples).
            pub fn serialize<S, T>(data: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
                T: AsRef<[u8]>,
            {
                internal::serialize_option::<_, _, super::$mod_name::Format>(data, serializer)
            }

            /// Deserializes an optional hex string into a byte collection.
            ///
            /// Present strings use this module's policy; an empty payload is `Some(empty)`.
            /// Allocation behavior matches [`crate::deserialize`].
            ///
            /// # Errors
            ///
            /// Propagates deserializer errors. Checks present text for any required prefix,
            /// even payload length, then characters/case before collection. Invalid input
            /// is an error, not `None`. Byte positions exclude the prefix.
            ///
            /// # Panics
            ///
            /// A custom collector may panic, for example when its fixed capacity is exceeded.
            ///
            /// # Examples
            ///
            /// See the [module example](self#examples).
            pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: FromIterator<u8>,
            {
                deserialize_bounded::<{ usize::MAX }, _, _>(deserializer)
            }

            /// Deserializes an optional collection of at most `MAX` decoded bytes.
            ///
            /// Accepts `None` and empty payloads even when `MAX == 0`. Storage limits
            /// and allocation behavior match [`crate::deserialize_bounded`].
            ///
            /// # Errors
            ///
            /// Propagates deserializer errors. Checks present text for any required prefix,
            /// even payload length, decoded-byte limit, then characters/case. Invalid or
            /// over-limit values are errors, not `None`. Byte positions exclude the prefix.
            ///
            /// # Panics
            ///
            /// A custom collector may still panic; the limit does not change its capacity.
            ///
            /// # Examples
            ///
            /// See [`crate::deserialize_bounded`] for the Serde field attributes.
            pub fn deserialize_bounded<'de, const MAX: usize, D, T>(
                deserializer: D,
            ) -> Result<Option<T>, D::Error>
            where
                D: serde::Deserializer<'de>,
                T: FromIterator<u8>,
            {
                use serde::Deserialize;
                Option::<Bytes<MAX>>::deserialize(deserializer)?
                    .map(|Bytes(bytes)| {
                        bytes.map(|bytes| bytes.into_iter().collect())
                            .map_err(serde::de::Error::custom)
                    })
                    .transpose()
            }

            // Use Serde's Option implementation for tagged and untagged formats.
            struct Bytes<const MAX: usize>(internal::Field<alloc::vec::Vec<u8>>);

            impl<'de, const MAX: usize> serde::Deserialize<'de> for Bytes<MAX> {
                fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    super::$mod_name::read_bytes::<MAX, _>(d).map(Self)
                }
            }

            /// Optional fixed-length arrays using this module's prefix and case policy.
            ///
            /// Present strings decode directly into `[u8; N]`. The format may need
            /// temporary input storage. `None` and `Some([])`
            /// remain distinct in every format. Add `#[serde(default)]` for missing fields.
            ///
            /// # Examples
            ///
            /// See the [crate example](crate#serde-adapters) for optional array fields.
            pub mod array {
                use super::super::$mod_name::Format;
                use super::internal;

                pub use super::serialize;

                struct Array<const N: usize>(internal::Field<[u8; N]>);

                impl<'de, const N: usize> serde::Deserialize<'de> for Array<N> {
                    #[inline(always)]
                    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                        internal::array_field::<D, Format, N>(d).map(Self)
                    }
                }

                /// Deserializes an optional array of exactly `N` bytes.
                ///
                /// An empty present payload requires `N == 0`.
                ///
                /// # Errors
                ///
                /// Checks present text for any required prefix, even payload length, exact
                /// decoded length, then characters/case. Format errors propagate; invalid input
                /// is an error, not `None`.
                /// Lengths count decoded bytes; invalid-byte positions exclude the prefix.
                ///
                /// # Examples
                ///
                /// See the [crate example](crate#serde-adapters) for optional array fields.
                #[inline(always)]
                pub fn deserialize<'de, D, const N: usize>(
                    deserializer: D,
                ) -> Result<Option<[u8; N]>, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    use serde::Deserialize;

                    internal::array_result::<N, _>(|| {
                        Option::<Array<N>>::deserialize(deserializer)?
                            .map(|Array(field)| field.map_err(serde::de::Error::custom))
                            .transpose()
                    })
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
