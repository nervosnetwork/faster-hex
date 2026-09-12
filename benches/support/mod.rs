// Shared across benchmark binaries which use different helpers.
#![allow(dead_code)]

pub const LENGTHS: &[usize] = &[
    0, 1, 2, 4, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128, 256, 1024, 4096, 65536, 1048576,
];

pub fn bytes(len: usize) -> Vec<u8> {
    let mut state = 0x243f_6a88u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}
pub const TEXT: &[u8] = b"and yesterday a deer,";
