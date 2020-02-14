use crate::error::Error;

pub fn hex_decode(src: &[u8], dst: &mut [u8]) -> Result<(), Error> {
    validate_buffer_length(src, dst)?;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx2") && src.len() >= 64 {
            return unsafe { arch::avx2::hex_decode(src, dst) };
        }
    }
    arch::fallback::hex_decode(src, dst)
}

pub fn hex_decode_unchecked(src: &[u8], dst: &mut [u8]) {
    validate_buffer_length(src, dst).unwrap();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx2") && src.len() >= 64 {
            return unsafe {
                arch::avx2::hex_decode_unchecked(src, dst);
            };
        }
    }
    arch::fallback::hex_decode_unchecked(src, dst)
}

#[inline]
fn validate_buffer_length(src: &[u8], dst: &[u8]) -> Result<(), Error> {
    let decoded_len = src.len().checked_div(2).unwrap();
    if dst.len() < decoded_len || ((src.len() & 1) != 0) {
        return Err(Error::InvalidLength(src.len()));
    }
    Ok(())
}

struct Checked;
struct Unchecked;

pub mod arch {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub mod avx2 {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::*;

        use crate::decode::{Checked, Error, Unchecked};

        #[target_feature(enable = "avx2")]
        pub unsafe fn hex_decode(src: &[u8], dst: &mut [u8]) -> Result<(), Error> {
            _hex_decode::<Checked>(src, dst).map_err(|_| Error::InvalidChar)
        }

        #[target_feature(enable = "avx2")]
        pub unsafe fn hex_decode_unchecked(src: &[u8], dst: &mut [u8]) {
            let _ = _hex_decode::<Unchecked>(src, dst);
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn _hex_decode<V: IsValid>(
            mut src: &[u8],
            mut dst: &mut [u8],
        ) -> Result<(), ()> {
            // 0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14, -1,
            // 0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14, -1
            let mask_a = _mm256_setr_epi8(
                0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14, -1, 0, -1, 2, -1, 4, -1, 6,
                -1, 8, -1, 10, -1, 12, -1, 14, -1,
            );

            // 1, -1, 3, -1, 5, -1, 7, -1, 9, -1, 11, -1, 13, -1, 15, -1,
            // 1, -1, 3, -1, 5, -1, 7, -1, 9, -1, 11, -1, 13, -1, 15, -1
            let mask_b = _mm256_setr_epi8(
                1, -1, 3, -1, 5, -1, 7, -1, 9, -1, 11, -1, 13, -1, 15, -1, 1, -1, 3, -1, 5, -1, 7,
                -1, 9, -1, 11, -1, 13, -1, 15, -1,
            );

            while dst.len() >= 32 {
                let av1 = _mm256_loadu_si256(src.as_ptr() as *const _);
                let av2 = _mm256_loadu_si256(src[32..].as_ptr() as *const _);

                if !<V as IsValid>::is_valid(av1) && !<V as IsValid>::is_valid(av2) {
                    return Err(());
                }

                let mut a1 = _mm256_shuffle_epi8(av1, mask_a);
                let mut b1 = _mm256_shuffle_epi8(av1, mask_b);
                let mut a2 = _mm256_shuffle_epi8(av2, mask_a);
                let mut b2 = _mm256_shuffle_epi8(av2, mask_b);

                a1 = unhex(a1);
                a2 = unhex(a2);
                b1 = unhex(b1);
                b2 = unhex(b2);

                let bytes = nib2byte(a1, b1, a2, b2);

                //dst does not need to be aligned on any particular boundary
                _mm256_storeu_si256(dst.as_mut_ptr() as *mut _, bytes);
                dst = &mut dst[32..];
                src = &src[64..];
            }
            crate::decode::arch::fallback::_hex_decode::<V>(&src, &mut dst)
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn unhex(value: __m256i) -> __m256i {
            let sr6 = _mm256_srai_epi16(value, 6);
            let and15 = _mm256_and_si256(value, _mm256_set1_epi16(0xf));
            let mul = _mm256_maddubs_epi16(sr6, _mm256_set1_epi16(9));
            _mm256_add_epi16(mul, and15)
        }

        // (a << 4) | b;
        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn nib2byte(a1: __m256i, b1: __m256i, a2: __m256i, b2: __m256i) -> __m256i {
            let a4_1 = _mm256_slli_epi16(a1, 4);
            let a4_2 = _mm256_slli_epi16(a2, 4);
            let a4orb_1 = _mm256_or_si256(a4_1, b1);
            let a4orb_2 = _mm256_or_si256(a4_2, b2);
            let pck1 = _mm256_packus_epi16(a4orb_1, a4orb_2);
            _mm256_permute4x64_epi64(pck1, 0b11011000)
        }

        #[target_feature(enable = "avx2")]
        pub unsafe fn hex_check(mut src: &[u8]) -> bool {
            while src.len() >= 32 {
                let unchecked = _mm256_loadu_si256(src.as_ptr() as *const _);
                if !Checked::is_valid(unchecked) {
                    return false;
                }
                src = &src[32..];
            }
            crate::decode::arch::fallback::hex_check(src)
        }

        pub trait IsValid: crate::decode::arch::fallback::IsValid {
            unsafe fn is_valid(input: __m256i) -> bool;
        }

        impl IsValid for Checked {
            #[inline]
            #[target_feature(enable = "avx2")]
            unsafe fn is_valid(input: __m256i) -> bool {
                let hi_nibbles = _mm256_and_si256(_mm256_srli_epi32(input, 4), _mm256_set1_epi8(0x0f));
                let low_nibbles = _mm256_and_si256(input, _mm256_set1_epi8(0x0f));
                let mask_lut = _mm256_setr_epi8(
                    0b0000_1000, // 0
                    0b0101_1000, // 1 .. 6
                    0b0101_1000, //
                    0b0101_1000, //
                    0b0101_1000, //
                    0b0101_1000, //
                    0b0101_1000, //
                    0b0000_1000, // 7 .. 9
                    0b0000_1000, //
                    0b0000_1000, //
                    0b0000_0000, // 10 .. 15
                    0b0000_0000, //
                    0b0000_0000, //
                    0b0000_0000, //
                    0b0000_0000, //
                    0b0000_0000, //
                    //
                    0b0000_1000, // 0
                    0b0101_1000, // 1 .. 6
                    0b0101_1000, //
                    0b0101_1000, //
                    0b0101_1000, //
                    0b0101_1000, //
                    0b0101_1000, //
                    0b0000_1000, // 7 .. 9
                    0b0000_1000, //
                    0b0000_1000, //
                    0b0000_0000, // 10 .. 15
                    0b0000_0000, //
                    0b0000_0000, //
                    0b0000_0000, //
                    0b0000_0000, //
                    0b0000_0000, //
                );

                #[allow(overflowing_literals)]
                let bit_pos_lut = _mm256_setr_epi8(
                    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                );

                let m = _mm256_shuffle_epi8(mask_lut, low_nibbles);
                let bit = _mm256_shuffle_epi8(bit_pos_lut, hi_nibbles);
                let non_match = _mm256_cmpeq_epi8(_mm256_and_si256(m, bit), _mm256_setzero_si256());
                _mm256_movemask_epi8(non_match) == 0
            }
        }

        impl IsValid for Unchecked {
            #[inline]
            #[target_feature(enable = "avx2")]
            unsafe fn is_valid(_: __m256i) -> bool {
                true
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use proptest::{proptest, proptest_helper};

            fn _test_check_true(s: &String) {
                assert!(unsafe { hex_check(s.as_bytes()) });
            }

            proptest! {
                #[test]
                fn test_check_true(ref s in "([0-9a-fA-F][0-9a-fA-F])+") {
                    _test_check_true(s);
                }
            }

            fn _test_check_false(s: &String) {
                assert!(!unsafe { hex_check(s.as_bytes()) });
            }

            proptest! {
                #[test]
                fn test_check_false(ref s in ".{32}[^0-9a-fA-F]+") {
                    _test_check_false(s);
                }
            }
        }
    }

    pub mod fallback {
        use crate::decode::{Checked, Error, Unchecked};

        pub fn hex_check(src: &[u8]) -> bool {
            src.iter().cloned().all(|b| unhex_a(b) != 0xff)
        }

        #[inline]
        pub fn hex_decode(src: &[u8], dst: &mut [u8]) -> Result<(), Error> {
            _hex_decode::<Checked>(src, dst).map_err(|_| Error::InvalidChar)
        }

        #[inline]
        pub fn hex_decode_unchecked(src: &[u8], dst: &mut [u8]) {
            let _ = _hex_decode::<Unchecked>(src, dst);
        }

        #[inline]
        pub fn _hex_decode<V: IsValid>(src: &[u8], dst: &mut [u8]) -> Result<(), ()> {
            for (slot, bytes) in dst.iter_mut().zip(src.chunks(2)) {
                if !V::is_valid(bytes[0], bytes[1]) {
                    return Err(());
                }
                let a = unhex_a(bytes[0]);
                let b = unhex_b(bytes[1]);
                *slot = a | b;
            }
            Ok(())
        }

        pub trait IsValid {
            fn is_valid(a: u8, b: u8) -> bool;
        }

        impl IsValid for Checked {
            #[inline]
            fn is_valid(a: u8, b: u8) -> bool {
                (unhex_a(a) | unhex_a(b)) != 0xff
            }
        }

        impl IsValid for Unchecked {
            #[inline]
            fn is_valid(_: u8, _: u8) -> bool {
                return true;
            }
        }

        // lower nibble
        #[inline]
        fn unhex_b(x: u8) -> u8 {
            // ASCII -> hex
            static UNHEX: [u8; 256] = [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 10, 11, 12, 13, 14, 15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 10, 11, 12, 13, 14, 15, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ];
            UNHEX[x as usize]
        }

        // upper nibble, logically equivalent to unhex_b(x) << 4
        #[inline]
        fn unhex_a(x: u8) -> u8 {
            // ASCII -> hex << 4
            static UNHEX4: [u8; 256] = [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 160, 176, 192, 208, 224, 240, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 160, 176, 192, 208, 224, 240,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ];
            UNHEX4[x as usize]
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use proptest::{proptest, proptest_helper};

            fn _test_decode(s: &String) {
                let len = s.as_bytes().len();
                let mut dst = Vec::with_capacity(len);
                dst.resize(len, 0);

                let hex_string = crate::hex_string(s.as_bytes()).unwrap();

                hex_decode(hex_string.as_bytes(), &mut dst).unwrap();

                assert_eq!(&dst[..], s.as_bytes());
            }

            proptest! {
                #[test]
                fn test_decode(ref s in ".+") {
                    _test_decode(s);
                }
            }

            fn _test_check_true(s: &String) {
                assert!(hex_check(s.as_bytes()));
            }

            proptest! {
                #[test]
                fn test_check_true(ref s in "[0-9a-fA-F]+") {
                    _test_check_true(s);
                }
            }

            fn _test_check_false(s: &String) {
                assert!(!hex_check(s.as_bytes()));
            }

            proptest! {
                #[test]
                fn test_check_false(ref s in ".{16}[^0-9a-fA-F]+") {
                    _test_check_false(s);
                }
            }
        }
    }
}
