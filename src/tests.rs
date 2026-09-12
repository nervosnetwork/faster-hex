use crate::decode::{hex_check_fallback_with_case, hex_decode_fallback, hex_decode_unchecked};
use crate::encode::{hex_encode_fallback, hex_encode_upper_fallback};
use crate::{hex_check_with_case, hex_decode, hex_encode, hex_encode_upper, CheckCase};
use proptest::prelude::*;

#[cfg(all(unix, not(miri)))]
mod guarded;

proptest! {
    #[test]
    fn public_and_scalar_paths_agree(data in prop::collection::vec(any::<u8>(), 0..4097)) {
        for upper in [false, true] {
            let mut scalar = vec![0; data.len() * 2];
            let mut dispatched = scalar.clone();
            if upper {
                hex_encode_upper_fallback(&data, &mut scalar);
                hex_encode_upper(&data, &mut dispatched).unwrap();
            } else {
                hex_encode_fallback(&data, &mut scalar);
                hex_encode(&data, &mut dispatched).unwrap();
            }
            prop_assert_eq!(&scalar, &dispatched);
            let mut decoded = vec![0; data.len()];
            hex_decode_fallback(&scalar, &mut decoded);
            prop_assert_eq!(&decoded, &data);
            hex_decode(&scalar, &mut decoded).unwrap();
            prop_assert_eq!(&decoded, &data);
        }
    }

    #[test]
    fn arbitrary_character_checks_agree(data in prop::collection::vec(any::<u8>(), 0..4097)) {
        for case in [CheckCase::None, CheckCase::Lower, CheckCase::Upper] {
            prop_assert_eq!(hex_check_with_case(&data, case), hex_check_fallback_with_case(&data, case));
        }
    }
}

#[test]
fn internal_conversion_never_reads_past_short_source() {
    // Exercises the old AVX2 threshold with independently varying slice lengths.
    for source_len in [0, 1, 2, 31, 32, 33, 63, 64, 65] {
        let source = vec![b'0'; source_len];
        for target_len in [0, 1, 31, 32, 33, 64, 65] {
            let mut target = vec![0xa5; target_len];
            hex_decode_unchecked(&source, &mut target);
            let written = source_len.min(target_len * 2) / 2;
            assert!(target[..written].iter().all(|b| *b == 0));
            assert!(target[written..].iter().all(|b| *b == 0xa5));
        }
    }
}

#[test]
fn scalar_encoder_preserves_incomplete_destination_pairs() {
    for source_len in 0..18 {
        let source = vec![0xaf; source_len];
        for target_len in 0..36 {
            for upper in [false, true] {
                let mut destination = vec![0xa5; target_len];
                if upper {
                    hex_encode_upper_fallback(&source, &mut destination);
                } else {
                    hex_encode_fallback(&source, &mut destination);
                }
                let written = source_len.min(target_len / 2) * 2;
                let expected = if upper { b"AF" } else { b"af" };
                for pair in destination[..written].chunks_exact(2) {
                    assert_eq!(pair, expected);
                }
                assert!(destination[written..].iter().all(|&byte| byte == 0xa5));
            }
        }
    }
}

#[test]
#[cfg(all(
    not(miri),
    any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
))]
fn feature_detection_matches_host() {
    use crate::{vectorization_support, Vectorization};
    match vectorization_support() {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Vectorization::AVX2 => assert!(std::arch::is_x86_feature_detected!("avx2")),
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Vectorization::SSE41 => assert!(std::arch::is_x86_feature_detected!("sse4.1")),
        #[cfg(target_arch = "aarch64")]
        Vectorization::Neon => assert!(std::arch::is_aarch64_feature_detected!("neon")),
        Vectorization::None => {}
    }
}

#[cfg(all(not(miri), any(target_arch = "x86", target_arch = "x86_64")))]
mod x86 {
    use super::*;
    use crate::{decode, encode};

    type Encode = unsafe fn(&[u8], &mut [u8], bool);
    type Check = unsafe fn(&[u8], CheckCase) -> bool;
    type Decode = unsafe fn(&[u8], &mut [u8], CheckCase) -> Result<(), ()>;

    pub(super) fn backends() -> Vec<(&'static str, Encode, Check, Decode)> {
        let mut result: Vec<(&str, Encode, Check, Decode)> = Vec::new();
        let sse = std::arch::is_x86_feature_detected!("sse4.1");
        let avx2 = std::arch::is_x86_feature_detected!("avx2");
        eprintln!("forced x86 backends: SSE4.1={sse}, AVX2={avx2}");
        if sse {
            result.push((
                "SSE4.1",
                |src, dst, upper| {
                    // SAFETY: The caller checked the CPU and exact lengths. The backend
                    // initializes every destination element before this borrow ends.
                    unsafe {
                        let dst =
                            core::slice::from_raw_parts_mut(dst.as_mut_ptr().cast(), dst.len());
                        encode::hex_encode_sse41(src, dst, upper);
                    }
                },
                decode::hex_check_sse_with_case,
                decode::hex_decode_sse41_checked,
            ));
        }
        if avx2 {
            result.push((
                "AVX2",
                |src, dst, upper| {
                    // SAFETY: The caller checked the CPU and exact lengths. The backend
                    // initializes every destination element before this borrow ends.
                    unsafe {
                        let dst =
                            core::slice::from_raw_parts_mut(dst.as_mut_ptr().cast(), dst.len());
                        encode::hex_encode_avx2(src, dst, upper);
                    }
                },
                decode::hex_check_avx2_with_case,
                decode::hex_decode_avx2_checked,
            ));
        }
        result
    }

    #[test]
    fn forced_backends_preserve_order_at_independent_alignments() {
        for (name, encode, _, decode) in backends() {
            for len in [
                0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
            ] {
                for source_offset in 0..32 {
                    let binary: Vec<u8> = (0..len + 32).map(|i| (i * 73 + i / 7) as u8).collect();
                    let input = &binary[source_offset..][..len];
                    for upper in [false, true] {
                        let expected = if upper {
                            hex::encode_upper(input)
                        } else {
                            hex::encode(input)
                        };
                        let mut hex_source = vec![0; source_offset + len * 2];
                        hex_source[source_offset..].copy_from_slice(expected.as_bytes());
                        for target_offset in 0..32 {
                            let mut encoded = vec![0xa5; len * 2 + 64];
                            // SAFETY: backends() checked CPU support; output has the exact size.
                            unsafe {
                                encode(input, &mut encoded[target_offset..][..len * 2], upper)
                            };
                            assert_eq!(
                                &encoded[target_offset..][..len * 2],
                                expected.as_bytes(),
                                "{name}, len={len}"
                            );
                            assert!(encoded[..target_offset]
                                .iter()
                                .chain(&encoded[target_offset + len * 2..])
                                .all(|&b| b == 0xa5));
                            let mut decoded = vec![0xa5; len + 64];
                            // SAFETY: CPU support and the input/output length ratio are established.
                            unsafe {
                                decode(
                                    &hex_source[source_offset..],
                                    &mut decoded[target_offset..][..len],
                                    CheckCase::None,
                                )
                            }
                            .unwrap();
                            assert_eq!(
                                &decoded[target_offset..][..len],
                                input,
                                "{name}, len={len}"
                            );
                            assert!(decoded[..target_offset]
                                .iter()
                                .chain(&decoded[target_offset + len..])
                                .all(|&b| b == 0xa5));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn forced_backends_check_every_byte_in_every_lane_before_writing() {
        for (name, _, check, decode) in backends() {
            for len in [16, 32, 64, 66, 128] {
                for position in 0..len {
                    for byte in 0..=255 {
                        let mut input = vec![b'0'; len];
                        input[position] = byte;
                        for case in [CheckCase::None, CheckCase::Lower, CheckCase::Upper] {
                            let valid = hex_check_fallback_with_case(&input, case);
                            // SAFETY: backends() checked support and the checker bounds its loads.
                            let actual = unsafe { check(&input, case) };
                            assert_eq!(actual, valid, "{name}, {len}/{position}/{byte}/{case:?}");
                            let mut output = vec![0xa5; len / 2];
                            // SAFETY: CPU support and the exact 2:1 slice ratio are established.
                            let result = unsafe { decode(&input, &mut output, case) };
                            if valid {
                                let mut expected = vec![0; len / 2];
                                hex_decode_fallback(&input, &mut expected);
                                assert_eq!(result, Ok(()));
                                assert_eq!(output, expected, "{name}");
                            } else {
                                assert_eq!(result, Err(()));
                                assert!(output.iter().all(|&b| b == 0xa5), "{}", name);
                            }
                        }
                    }
                }
            }
        }
    }
}
