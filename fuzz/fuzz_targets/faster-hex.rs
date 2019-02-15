#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate faster_hex;

use faster_hex::{hex_decode, hex_encode, hex_string};

fuzz_target!(|data: &[u8]| {
    let mut buffer = vec![0; data.len() * 2];
    let _ = hex_encode(data, &mut buffer);
    let _ = hex_string(data);
    let mut dst = Vec::with_capacity(data.len());
    dst.resize(data.len(), 0);
    let _ = hex_decode(&buffer, &mut dst);
});
