// gix-hash's Prefix::hex_to_buf has already bounded digits to 2 * src.len().
#[inline]
pub fn to_buf<'a>(src: &[u8], digits: usize, dst: &'a mut [u8]) -> &'a mut str {
    let pairs = digits / 2;
    if pairs != 0 {
        faster_hex::hex_encode(&src[..pairs], &mut dst[..pairs * 2]).unwrap();
    }
    if !digits.is_multiple_of(2) {
        dst[pairs * 2] = b"0123456789abcdef"[usize::from(src[pairs] >> 4)];
    }
    core::str::from_utf8_mut(&mut dst[..digits]).unwrap()
}
