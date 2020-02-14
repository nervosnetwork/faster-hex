use crate::error::Error;

pub fn hex_decode(src: &[u8], dst: &mut [u8]) -> Result<(), Error> {
    let decoded_len = src.len().checked_div(2).unwrap();
    if dst.len() < decoded_len || ((src.len() & 1) != 0) {
        return Err(Error::InvalidLength(src.len()));
    }
    if !hex_check(src) {
        return Err(Error::InvalidChar);
    }
    hex_decode_unchecked(src, dst);
    Ok(())
}

pub fn hex_decode_unchecked(src: &[u8], dst: &mut [u8]) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { arch::avx2::hex_decode(src, dst) };
        }
    }

    arch::fallback::hex_decode(src, dst);
}

fn hex_check(src: &[u8]) -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("sse4.1") {
            return unsafe { arch::avx2::hex_check(src) };
        }
    }

    arch::fallback::hex_check(src)
}

pub mod arch {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub mod avx2 {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::*;

        #[target_feature(enable = "avx2")]
        pub unsafe fn hex_decode(mut src: &[u8], mut dst: &mut [u8]) {
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
            crate::decode::arch::fallback::hex_decode(&src, &mut dst)
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
        #[allow(overflowing_literals)]
        pub unsafe fn hex_check(mut src: &[u8]) -> bool {
            let ascii_zero = _mm256_set1_epi8((b'0' - 1) as i8);
            let ascii_nine = _mm256_set1_epi8((b'9' + 1) as i8);
            let ascii_ua = _mm256_set1_epi8((b'A' - 1) as i8);
            let ascii_uf = _mm256_set1_epi8((b'F' + 1) as i8);
            let ascii_la = _mm256_set1_epi8((b'a' - 1) as i8);
            let ascii_lf = _mm256_set1_epi8((b'f' + 1) as i8);

            while src.len() >= 32 {
                let unchecked = _mm256_loadu_si256(src.as_ptr() as *const _);

                let gt0 = _mm256_cmpgt_epi8(unchecked, ascii_zero);
                let lt9 = _mm256_cmpgt_epi8(ascii_nine, unchecked);
                let outside1 = _mm256_and_si256(gt0, lt9);

                let gtua = _mm256_cmpgt_epi8(unchecked, ascii_ua);
                let ltuf = _mm256_cmpgt_epi8(ascii_uf, unchecked);
                let outside2 = _mm256_and_si256(gtua, ltuf);

                let gtla = _mm256_cmpgt_epi8(unchecked, ascii_la);
                let ltlf = _mm256_cmpgt_epi8(ascii_lf, unchecked);
                let outside3 = _mm256_and_si256(gtla, ltlf);

                let tmp = _mm256_or_si256(outside1, outside2);
                let ret = _mm256_movemask_epi8(_mm256_or_si256(tmp, outside3));

                eprintln!("{:x}", ret);
                if ret != 0xffff_ffff {
                    return false;
                }

                src = &src[32..];
            }
            crate::decode::arch::fallback::hex_check(src)
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
        pub fn hex_check(src: &[u8]) -> bool {
            for byte in src {
                match byte {
                    b'A'..=b'F' | b'a'..=b'f' | b'0'..=b'9' => continue,
                    _ => {
                        return false;
                    }
                }
            }
            true
        }

        pub fn hex_decode(src: &[u8], dst: &mut [u8]) {
            for (slot, bytes) in dst.iter_mut().zip(src.chunks(2)) {
                let a = unhex_a(bytes[0] as usize);
                let b = unhex_b(bytes[1] as usize);
                *slot = a | b;
            }
        }

        // lower nibble
        #[inline]
        fn unhex_b(x: usize) -> u8 {
            const NIL: u8 = u8::max_value();
            // ASCII -> hex
            static UNHEX: [u8; 256] = [
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, 0,
                1, 2, 3, 4, 5, 6, 7, 8, 9, NIL, NIL, NIL, NIL, NIL, NIL, NIL, 10, 11, 12, 13, 14,
                15, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, 10, 11, 12, 13, 14, 15, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL,
            ];
            UNHEX[x]
        }

        // upper nibble, logically equivalent to unhex_b(x) << 4
        #[inline]
        fn unhex_a(x: usize) -> u8 {
            const NIL: u8 = u8::max_value();
            // ASCII -> hex
            // ASCII -> hex << 4
            static UNHEX4: [u8; 256] = [
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, 0,
                16, 32, 48, 64, 80, 96, 112, 128, 144, NIL, NIL, NIL, NIL, NIL, NIL, NIL, 160, 176,
                192, 208, 224, 240, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, 160, 176,
                192, 208, 224, 240, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
                NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL, NIL,
            ];
            UNHEX4[x]
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

                hex_decode(hex_string.as_bytes(), &mut dst);

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
