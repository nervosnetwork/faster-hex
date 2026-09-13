//! Compile as a downstream crate: rustdoc comparison cannot detect every
//! removed implementation of an external trait, especially handwritten ones.
#![no_std]

use core::{error, fmt, hash::Hash};
use faster_hex::{CheckCase, Error, Hex};

fn value<T: Copy + Eq + Hash + fmt::Debug + Send + Sync + Unpin>() {}
fn error<T: error::Error>() {}
fn formatting<T: Copy + fmt::Debug + fmt::Display + fmt::LowerHex + fmt::UpperHex>() {}

pub fn required_traits() {
    value::<Error>();
    value::<CheckCase>();
    error::<Error>();
    formatting::<Hex<'_>>();
    let _: CheckCase = Default::default();
}

pub const EMPTY: Hex<'static> = Hex::new(&[]);

// Preserve exact return types and independent source/destination lifetimes.
// Generic rustdoc lints do not catch every change between non-unit types.
type Encode = for<'src, 'dst> fn(&'src [u8], &'dst mut [u8]) -> Result<&'dst mut str, Error>;
type Decode = for<'src, 'dst> fn(&'src [u8], &'dst mut [u8]) -> Result<&'dst mut [u8], Error>;
type DecodeCase =
    for<'src, 'dst> fn(&'src [u8], &'dst mut [u8], CheckCase) -> Result<&'dst mut [u8], Error>;

const _: Encode = faster_hex::hex_encode;
const _: Encode = faster_hex::hex_encode_upper;
const _: Decode = faster_hex::hex_decode;
const _: DecodeCase = faster_hex::hex_decode_with_case;
const _: fn(&[u8]) -> bool = faster_hex::hex_check;
const _: fn(&[u8], CheckCase) -> bool = faster_hex::hex_check_with_case;
const _: fn(&[u8]) -> Result<[u8; 32], Error> = faster_hex::hex_decode_array::<32>;
const _: fn(&[u8], CheckCase) -> Result<[u8; 32], Error> =
    faster_hex::hex_decode_array_with_case::<32>;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub fn owned_output() {
    let mut string: alloc::string::String = faster_hex::hex_string(&[0]);
    faster_hex::hex_append_upper(&[255], &mut string);
    let _: alloc::vec::Vec<u8> = faster_hex::hex_decode_vec(b"ff").unwrap();
    let _: alloc::vec::Vec<u8> =
        faster_hex::hex_decode_vec_with_case(b"FF", CheckCase::Upper).unwrap();
}

#[cfg(feature = "heapless-08")]
pub fn heapless_output() {
    let _: heapless::String<2> = faster_hex::heapless_08::hex_string(&[0]).unwrap();
    let _: heapless::String<2> = faster_hex::heapless_08::hex_string_upper(&[255]).unwrap();
}

#[cfg(feature = "defmt-03")]
pub fn logging() {
    fn assert_defmt<T: defmt::Format>() {}
    assert_defmt::<Error>();
    assert_defmt::<CheckCase>();
}

#[cfg(feature = "serde")]
pub fn collections<'de, D: serde::Deserializer<'de>>(a: D, b: D, c: D) -> Result<(), D::Error> {
    let _: alloc::vec::Vec<u8> = faster_hex::deserialize(a)?;
    let _: alloc::vec::Vec<u8> = faster_hex::deserialize_bounded::<64, _, _>(b)?;
    let _: Option<alloc::vec::Vec<u8>> =
        faster_hex::option_nopfx_uppercase::deserialize_bounded::<64, _, _>(c)?;
    Ok(())
}

#[cfg(feature = "serde")]
pub fn arrays<'de, D: serde::Deserializer<'de>>(a: D, b: D) -> Result<(), D::Error> {
    let _: [u8; 64] = faster_hex::array::deserialize(a)?;
    let _: Option<[u8; 64]> = faster_hex::option_nopfx_uppercase::array::deserialize(b)?;
    Ok(())
}
