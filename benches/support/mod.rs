pub const LENGTHS: &[usize] = &[1, 8, 10, 16, 32, 64, 65, 256, 4096, 65536];

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
