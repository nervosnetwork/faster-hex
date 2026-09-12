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
