#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

const NIL: u8 = u8::max_value();

pub(crate) static UNHEX: [u8; 256] = [
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, 10, 11, 12, 13, 14, 15, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, 10, 11, 12, 13,
    14, 15, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL,
];

pub(crate) static UNHEX4: [u8; 256] = [
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, 0, 16, 32, 48, 64, 80, 96, 112, 128, 144,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, 160, 176, 192, 208, 224, 240, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, 160, 176, 192, 208, 224, 240, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
    NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
];

const _0213: i32 = 0b11011000;

#[inline]
fn unhex_b(x: usize) -> u8 {
    UNHEX[x]
}

#[inline]
fn unhex_a(x: usize) -> u8 {
    UNHEX4[x]
}

#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn unhex_avx2(value: __m256i) -> __m256i {
    let sr6 = _mm256_srai_epi16(value, 6);
    let and15 = _mm256_and_si256(value, _mm256_set1_epi16(0xf));
    let mul = _mm256_maddubs_epi16(sr6, _mm256_set1_epi16(9));
    _mm256_add_epi16(mul, and15)
}

#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn nib2byte_avx2(a1: __m256i, b1: __m256i, a2: __m256i, b2: __m256i) -> __m256i {
    let a4_1 = _mm256_slli_epi16(a1, 4);
    let a4_2 = _mm256_slli_epi16(a2, 4);
    let a4orb_1 = _mm256_or_si256(a4_1, b1);
    let a4orb_2 = _mm256_or_si256(a4_2, b2);
    let pck1 = _mm256_packus_epi16(a4orb_1, a4orb_2); // lo1 lo2 hi1 hi2
    _mm256_permute4x64_epi64(pck1, _0213)
}

pub fn hex_decode(src: &[u8], dst: &mut [u8]) -> Result<(), usize> {
    let len = dst.len().checked_mul(2).unwrap();
    if src.len() < len {
        return Err(len);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe { hex_decode_avx2(src, dst) }?;
            return Ok(());
        }
    }

    hex_decode_fallback(src, dst)?;
    Ok(())
}

#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn hex_decode_avx2(mut src: &[u8], mut dst: &mut [u8]) -> Result<(), usize> {
    let mask_a = _mm256_setr_epi8(
        0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14, -1, 0, -1, 2, -1, 4, -1, 6, -1, 8,
        -1, 10, -1, 12, -1, 14, -1,
    );

    let mask_b = _mm256_setr_epi8(
        1, -1, 3, -1, 5, -1, 7, -1, 9, -1, 11, -1, 13, -1, 15, -1, 1, -1, 3, -1, 5, -1, 7, -1, 9,
        -1, 11, -1, 13, -1, 15, -1,
    );

    while dst.len() >= 32 {
        // 32 nibbles, 16 bytes
        let av1 = _mm256_loadu_si256(src.as_ptr() as *const _);
        let av2 = _mm256_loadu_si256(src[32..].as_ptr() as *const _);

        // Separate high and low nibbles and extend into 16-bit elements
        let mut a1 = _mm256_shuffle_epi8(av1, mask_a);
        let mut b1 = _mm256_shuffle_epi8(av1, mask_b);
        let mut a2 = _mm256_shuffle_epi8(av2, mask_a);
        let mut b2 = _mm256_shuffle_epi8(av2, mask_b);

        a1 = unhex_avx2(a1);
        a2 = unhex_avx2(a2);
        b1 = unhex_avx2(b1);
        b2 = unhex_avx2(b2);

        let bytes = nib2byte_avx2(a1, b1, a2, b2);

        _mm256_storeu_si256(dst.as_mut_ptr() as *mut _, bytes);
        dst = &mut dst[32..];
        src = &src[64..];
    }
    hex_decode_fallback(&src, &mut dst)
}

pub fn hex_decode_fallback(src: &[u8], dst: &mut [u8]) -> Result<(), usize> {
    for (idx, item) in dst.iter_mut().zip(src.chunks(2)).enumerate() {
        let a = unhex_a(item.1[0] as usize);
        let b = unhex_b(item.1[1] as usize);
        if a == NIL || b == NIL {
            return Err(idx);
        }
        *item.0 = a | b;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::decode::hex_decode_fallback;
    use crate::encode::hex_string;
    use proptest::{proptest, proptest_helper};

    fn _test_decode_fallback(s: &String) {
        let len = s.as_bytes().len();
        let mut dst = Vec::with_capacity(len);
        dst.resize(len, 0);

        let hex_string = hex_string(s.as_bytes()).unwrap();

        hex_decode_fallback(hex_string.as_bytes(), &mut dst).unwrap();

        assert_eq!(&dst[..], s.as_bytes());
    }

    proptest! {
        #[test]
        fn test_decode_fallback(ref s in ".*") {
            _test_decode_fallback(s);
        }
    }
}
