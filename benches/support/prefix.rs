#[inline]
pub fn to_buf<'a>(src: &[u8], digits: usize, dst: &'a mut [u8]) -> &'a mut str {
    faster_hex::Hex::new(src)
        .leading_digits(digits)
        .encode_to(dst)
        .unwrap()
}
