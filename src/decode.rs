// SIMD decoding includes work derived from fast-hex under the MIT license.
// See https://github.com/zbjornson/fast-hex and LICENSE-THIRD-PARTY/fast-hex.
// AVX nibble lookup is adapted from vsimd 0.8.0 (ALSW) under the MIT license;
// see LICENSE-THIRD-PARTY/vsimd.
// Saturating nibble mapping is adapted from const-hex under the MIT license;
// see LICENSE-THIRD-PARTY/const-hex.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::error::Error;

// SIMD callers must establish CPU/OS support. Character checkers accept any
// source length. Checked conversion kernels require even input and exactly
// half as much output space; they validate all characters before any write.
// Raw conversion kernels require that validation to have already succeeded.

const NIL: u8 = u8::MAX;

const fn init_unhex_array(check_case: CheckCase) -> [u8; 256] {
    let mut arr = [0; 256];
    let mut i = 0;
    while i < 256 {
        arr[i] = match i as u8 {
            b'0'..=b'9' => i as u8 - b'0',
            b'a'..=b'f' => match check_case {
                CheckCase::Lower | CheckCase::None => i as u8 - b'a' + 10,
                _ => NIL,
            },
            b'A'..=b'F' => match check_case {
                CheckCase::Upper | CheckCase::None => i as u8 - b'A' + 10,
                _ => NIL,
            },
            _ => NIL,
        };
        i += 1;
    }
    arr
}

const fn init_unhex4_array(check_case: CheckCase) -> [u8; 256] {
    let unhex_arr = init_unhex_array(check_case);

    let mut unhex4_arr = [NIL; 256];
    let mut i = 0;
    while i < 256 {
        if unhex_arr[i] != NIL {
            unhex4_arr[i] = unhex_arr[i] << 4;
        }
        i += 1;
    }
    unhex4_arr
}

// ASCII -> hex
static UNHEX: [u8; 256] = init_unhex_array(CheckCase::None);

// ASCII -> hex, lower case
static UNHEX_LOWER: [u8; 256] = init_unhex_array(CheckCase::Lower);

// ASCII -> hex, upper case
static UNHEX_UPPER: [u8; 256] = init_unhex_array(CheckCase::Upper);

// ASCII -> hex << 4
static UNHEX4: [u8; 256] = init_unhex4_array(CheckCase::None);

/// Returns whether every byte is an ASCII hex digit, accepting either letter case.
///
/// Accepts `0` through `9`, `a` through `f`, and `A` through `F`, including mixed
/// case. Prefixes, whitespace and non-ASCII bytes are rejected. This is a
/// character-only check: empty and odd-length inputs can pass. It does not
/// allocate or modify the input.
///
/// Use [`hex_decode`] to also require complete byte pairs. There is no need to
/// call this function before a checked decoder: decoding already validates input.
///
/// # Examples
///
/// ```
/// use faster_hex::hex_check;
///
/// assert!(hex_check(b"00aBcD"));
/// assert!(hex_check(b"a")); // Valid characters, but not a complete byte pair.
/// assert!(hex_check(b""));
/// assert!(!hex_check(b"0x01"));
/// assert!(!hex_check(b"00 01"));
/// ```
#[inline]
pub fn hex_check(src: &[u8]) -> bool {
    hex_check_with_case(src, CheckCase::None)
}

/// Checks ASCII hex digits against an explicit letter-case policy.
///
/// Digits are accepted under every [`CheckCase`] policy. Empty input succeeds;
/// odd lengths are allowed. Like [`hex_check`], this checks characters only and
/// neither allocates nor modifies the input.
///
/// # Examples
///
/// ```
/// use faster_hex::{hex_check_with_case, CheckCase};
///
/// assert!(hex_check_with_case(b"0123", CheckCase::Upper));
/// assert!(hex_check_with_case(b"ab01", CheckCase::Lower));
/// assert!(!hex_check_with_case(b"AB01", CheckCase::Lower));
/// assert!(hex_check_with_case(b"aB01", CheckCase::None));
/// ```
#[inline]
pub fn hex_check_with_case(src: &[u8], check_case: CheckCase) -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        match crate::vectorization_support() {
            crate::Vectorization::AVX512 => {
                // SAFETY: Dispatch checks AVX-512BW and its OS state.
                unsafe { hex_check_avx512_with_case(src, check_case) }
            }
            crate::Vectorization::AVX2 => {
                // SAFETY: Dispatch guarantees AVX2; the checker bounds every load.
                unsafe { hex_check_avx2_with_case(src, check_case) }
            }
            crate::Vectorization::SSE41 => {
                // SAFETY: Dispatch checks SSE4.1; the checker bounds every load.
                unsafe { hex_check_sse_with_case(src, check_case) }
            }
            crate::Vectorization::None => hex_check_fallback_with_case(src, check_case),
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        match crate::vectorization_support() {
            crate::Vectorization::Neon => {
                // SAFETY: Dispatch guarantees NEON; the checker bounds every load.
                unsafe { hex_check_neon_with_case(src, check_case) }
            }
            crate::Vectorization::None => hex_check_fallback_with_case(src, check_case),
        }
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    hex_check_fallback_with_case(src, check_case)
}

/// Check if the input is valid hex bytes slice with case check
pub(crate) fn hex_check_fallback_with_case(src: &[u8], check_case: CheckCase) -> bool {
    match check_case {
        CheckCase::None => src.iter().all(|&x| UNHEX[x as usize] != NIL),
        CheckCase::Lower => src.iter().all(|&x| UNHEX_LOWER[x as usize] != NIL),
        CheckCase::Upper => src.iter().all(|&x| UNHEX_UPPER[x as usize] != NIL),
    }
}

/// Which ASCII letter cases are accepted when checking or decoding hex.
///
/// [`None`](Self::None) is the default and accepts mixed case; it does not
/// disable character validation. All policies accept ASCII digits `0` through
/// `9` and reject prefixes, whitespace and non-ASCII characters. They do not
/// change the length rules of the operation using them.
///
/// Encoding selects lowercase or uppercase through separate functions, so an
/// encoding operation never needs this policy.
///
/// # Examples
///
/// ```
/// use faster_hex::{hex_decode_with_case, CheckCase};
///
/// let mut bytes = [0; 2];
/// assert_eq!(hex_decode_with_case(b"AB01", &mut bytes, CheckCase::Upper)?,
///            &[0xab, 1]);
/// assert!(hex_decode_with_case(b"ab01", &mut bytes, CheckCase::Upper).is_err());
/// # Ok::<(), faster_hex::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub enum CheckCase {
    /// Accept uppercase and lowercase, including a mixture of both.
    #[default]
    None,
    /// Accept digits and lowercase `a` through `f` only.
    Lower,
    /// Accept digits and uppercase `A` through `F` only.
    Upper,
}

// The ALSW hash separates digits, uppercase and lowercase ASCII ranges.
// Saturating addition with each range's negative start marks invalid bytes
// with a sign bit. Slots 5 and 7 select the uppercase and lowercase ranges.
// Non-ASCII bytes remain negative under signed saturating addition.
#[inline]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn decode_check_offsets(case: CheckCase) -> &'static [i8; 16] {
    const MIXED: [i8; 16] = [
        -128, -128, -128, -128, -48, -65, -128, -97, -128, -55, -128, -128, -128, -128, -128, -128,
    ];
    const LOWER: [i8; 16] = {
        let mut offsets = MIXED;
        offsets[5] = -128;
        offsets
    };
    const UPPER: [i8; 16] = {
        let mut offsets = MIXED;
        offsets[7] = -128;
        offsets
    };
    match case {
        CheckCase::None => &MIXED,
        CheckCase::Lower => &LOWER,
        CheckCase::Upper => &UPPER,
    }
}

// Add a wrapping bias so the accepted unsigned ASCII interval starts at -128.
// A signed comparison then rejects both bytes below the interval and above it.
#[inline]
#[target_feature(enable = "sse4.1")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn valid_sse(bytes: __m128i, case: CheckCase) -> __m128i {
    let digit = _mm_cmpgt_epi8(_mm_set1_epi8(-118), _mm_add_epi8(bytes, _mm_set1_epi8(80)));
    let fold = if case == CheckCase::None { 0x20 } else { 0 };
    let first = if case == CheckCase::Upper { b'A' } else { b'a' };
    let letters = _mm_or_si128(bytes, _mm_set1_epi8(fold));
    let letter = _mm_cmpgt_epi8(
        _mm_set1_epi8(-122),
        _mm_add_epi8(letters, _mm_set1_epi8(128u8.wrapping_sub(first) as i8)),
    );
    _mm_or_si128(digit, letter)
}

#[target_feature(enable = "sse4.1")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) unsafe fn hex_check_sse_with_case(src: &[u8], case: CheckCase) -> bool {
    if src.len() < 16 {
        return hex_check_fallback_with_case(src, case);
    }
    let (blocks, tail) = src.as_chunks::<16>();
    for block in blocks {
        if _mm_movemask_epi8(valid_sse(_mm_loadu_si128(block.as_ptr().cast()), case)) != 0xffff {
            return false;
        }
    }
    if !tail.is_empty() {
        if let Some(last) = src.last_chunk::<16>() {
            return _mm_movemask_epi8(valid_sse(_mm_loadu_si128(last.as_ptr().cast()), case))
                == 0xffff;
        }
    }
    true
}

// Add a wrapping bias so the accepted unsigned ASCII interval starts at -128.
// A signed comparison then rejects both bytes below the interval and above it.
#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn valid_avx2(bytes: __m256i, case: CheckCase) -> __m256i {
    let digit = _mm256_cmpgt_epi8(
        _mm256_set1_epi8(-118),
        _mm256_add_epi8(bytes, _mm256_set1_epi8(80)),
    );
    let fold = if case == CheckCase::None { 0x20 } else { 0 };
    let first = if case == CheckCase::Upper { b'A' } else { b'a' };
    let letters = _mm256_or_si256(bytes, _mm256_set1_epi8(fold));
    let letter = _mm256_cmpgt_epi8(
        _mm256_set1_epi8(-122),
        _mm256_add_epi8(letters, _mm256_set1_epi8(128u8.wrapping_sub(first) as i8)),
    );
    _mm256_or_si256(digit, letter)
}

#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
pub(crate) unsafe fn hex_check_avx2_with_case(src: &[u8], case: CheckCase) -> bool {
    if src.len() < 32 {
        return hex_check_sse_with_case(src, case);
    }
    // Reduce four vectors together so long inputs need fewer mask tests.
    let (batches, rest) = src.as_chunks::<128>();
    for batch in batches {
        let mut valid = _mm256_set1_epi8(-1);
        for block in batch.as_chunks::<32>().0 {
            valid = _mm256_and_si256(
                valid,
                valid_avx2(_mm256_loadu_si256(block.as_ptr().cast()), case),
            );
        }
        if _mm256_movemask_epi8(valid) != -1 {
            return false;
        }
    }
    let (blocks, tail) = rest.as_chunks::<32>();
    let mut valid = _mm256_set1_epi8(-1);
    for block in blocks {
        valid = _mm256_and_si256(
            valid,
            valid_avx2(_mm256_loadu_si256(block.as_ptr().cast()), case),
        );
    }
    if !tail.is_empty() {
        if let Some(last) = src.last_chunk::<32>() {
            valid = _mm256_and_si256(
                valid,
                valid_avx2(_mm256_loadu_si256(last.as_ptr().cast()), case),
            );
        }
    }
    _mm256_movemask_epi8(valid) == -1
}

#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn valid_avx512(bytes: __m512i, case: CheckCase) -> u64 {
    let digit = _mm512_cmple_epu8_mask(
        _mm512_sub_epi8(bytes, _mm512_set1_epi8(b'0' as i8)),
        _mm512_set1_epi8(9),
    );
    let fold = if case == CheckCase::None { 0x20 } else { 0 };
    let first = if case == CheckCase::Upper { b'A' } else { b'a' };
    let letters = _mm512_or_si512(bytes, _mm512_set1_epi8(fold));
    let letter = _mm512_cmple_epu8_mask(
        _mm512_sub_epi8(letters, _mm512_set1_epi8(first as i8)),
        _mm512_set1_epi8(5),
    );
    digit | letter
}

#[target_feature(enable = "avx512f,avx512bw")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
pub(crate) unsafe fn hex_check_avx512_with_case(src: &[u8], case: CheckCase) -> bool {
    if src.len() < 64 {
        return hex_check_avx2_with_case(src, case);
    }
    let (blocks, tail) = src.as_chunks::<64>();
    for block in blocks {
        if valid_avx512(_mm512_loadu_si512(block.as_ptr().cast()), case) != u64::MAX {
            return false;
        }
    }
    if !tail.is_empty() {
        if let Some(last) = src.last_chunk::<64>() {
            return valid_avx512(_mm512_loadu_si512(last.as_ptr().cast()), case) == u64::MAX;
        }
    }
    true
}

// Wrapping subtraction turns each ASCII range into one unsigned comparison.
// Only the either-case policy folds the ASCII case bit.
#[inline]
#[target_feature(enable = "neon")]
#[cfg(target_arch = "aarch64")]
unsafe fn valid_neon(bytes: uint8x16_t, case: CheckCase) -> uint8x16_t {
    let digit = vcleq_u8(vsubq_u8(bytes, vdupq_n_u8(b'0')), vdupq_n_u8(9));
    let fold = if case == CheckCase::None { 0x20 } else { 0 };
    let letters = vorrq_u8(bytes, vdupq_n_u8(fold));
    let first = if case == CheckCase::Upper { b'A' } else { b'a' };
    let letter = vcleq_u8(vsubq_u8(letters, vdupq_n_u8(first)), vdupq_n_u8(5));
    vorrq_u8(digit, letter)
}

// Map valid ASCII to 0..=15 and every invalid byte to >=16. This is the
// saturating-arithmetic idea in Muła and Langdale's hex parser, with a strict
// case policy and validation completed before any output is written:
// http://0x80.pl/notesen/2022-01-17-validating-hex-parse.html
// Wrapping (x - 58), saturating subtraction of 6, then wrapping +16 maps
// '0'..='9' to 0..=9 and everything else to >=16. The letter candidate maps
// its first six values to 10..=15; unsigned min chooses the valid candidate.
#[inline]
#[target_feature(enable = "sse4.1")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn decode_sse41_nibbles(bytes: __m128i, case: CheckCase) -> __m128i {
    let digit = _mm_sub_epi8(
        _mm_subs_epu8(_mm_add_epi8(bytes, _mm_set1_epi8(-58)), _mm_set1_epi8(6)),
        _mm_set1_epi8(-16),
    );
    let fold = if case == CheckCase::None { 0x20 } else { 0 };
    let first = if case == CheckCase::Upper { b'A' } else { b'a' };
    let letter = _mm_sub_epi8(
        _mm_or_si128(bytes, _mm_set1_epi8(fold)),
        _mm_set1_epi8(first as i8),
    );
    _mm_min_epu8(digit, _mm_adds_epu8(letter, _mm_set1_epi8(10)))
}

// Returns (nibbles, validity bytes). Nibbles are valid only when no validity
// byte has its sign bit set. Check the complete input before storing output.
// The word-sized shift leaves neighbor bits in the hash, but for ASCII they
// only affect index bits ignored by the 16-entry byte shuffles.
#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn decode_avx2_nibbles(bytes: __m256i, case: CheckCase) -> (__m256i, __m256i) {
    let hash_table = _mm256_broadcastsi128_si256(_mm_setr_epi8(
        1, 1, 1, 1, 1, 1, 1, 11, 11, 11, 15, 15, 15, 15, 15, 15,
    ));
    let check_offsets =
        _mm256_broadcastsi128_si256(_mm_loadu_si128(decode_check_offsets(case).as_ptr().cast()));
    let decode_offsets = _mm256_broadcastsi128_si256(_mm_setr_epi8(
        -128, -128, -128, -128, -48, -55, -128, -87, -128, -48, -128, -128, -128, -128, -128, -128,
    ));
    let hash = _mm256_avg_epu8(
        _mm256_srli_epi32::<3>(bytes),
        _mm256_shuffle_epi8(hash_table, bytes),
    );
    let checked = _mm256_adds_epi8(bytes, _mm256_shuffle_epi8(check_offsets, hash));
    let nibbles = _mm256_add_epi8(bytes, _mm256_shuffle_epi8(decode_offsets, hash));
    (nibbles, checked)
}

// Same nibble/validity contract as decode_avx2_nibbles, for 64 input bytes.
#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn decode_avx512_nibbles(bytes: __m512i, case: CheckCase) -> (__m512i, __m512i) {
    let hash_table = _mm512_broadcast_i32x4(_mm_setr_epi8(
        1, 1, 1, 1, 1, 1, 1, 11, 11, 11, 15, 15, 15, 15, 15, 15,
    ));
    let check_offsets =
        _mm512_broadcast_i32x4(_mm_loadu_si128(decode_check_offsets(case).as_ptr().cast()));
    let decode_offsets = _mm512_broadcast_i32x4(_mm_setr_epi8(
        -128, -128, -128, -128, -48, -55, -128, -87, -128, -48, -128, -128, -128, -128, -128, -128,
    ));
    let hash = _mm512_avg_epu8(
        _mm512_srli_epi32::<3>(bytes),
        _mm512_shuffle_epi8(hash_table, bytes),
    );
    let checked = _mm512_adds_epi8(bytes, _mm512_shuffle_epi8(check_offsets, hash));
    let nibbles = _mm512_add_epi8(bytes, _mm512_shuffle_epi8(decode_offsets, hash));
    (nibbles, checked)
}

#[inline]
#[target_feature(enable = "neon")]
#[cfg(target_arch = "aarch64")]
unsafe fn decode_neon_nibbles(bytes: uint8x16_t, case: CheckCase) -> uint8x16_t {
    let digit = vsubq_u8(
        vqsubq_u8(vaddq_u8(bytes, vdupq_n_u8(198)), vdupq_n_u8(6)),
        vdupq_n_u8(240),
    );
    let fold = if case == CheckCase::None { 0x20 } else { 0 };
    let first = if case == CheckCase::Upper { b'A' } else { b'a' };
    let letter = vsubq_u8(vorrq_u8(bytes, vdupq_n_u8(fold)), vdupq_n_u8(first));
    vminq_u8(digit, vqaddq_u8(letter, vdupq_n_u8(10)))
}

#[inline]
#[target_feature(enable = "neon")]
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn hex_check_neon_with_case(src: &[u8], check_case: CheckCase) -> bool {
    if src.len() < 64 {
        return hex_check_neon_short(src, check_case);
    }
    let (batches, rest) = src.as_chunks::<64>();
    for batch in batches {
        let a = valid_neon(vld1q_u8(batch.as_ptr()), check_case);
        let b = valid_neon(vld1q_u8(batch.as_ptr().add(16)), check_case);
        let c = valid_neon(vld1q_u8(batch.as_ptr().add(32)), check_case);
        let d = valid_neon(vld1q_u8(batch.as_ptr().add(48)), check_case);
        if vminvq_u8(vandq_u8(vandq_u8(a, b), vandq_u8(c, d))) == 0 {
            return false;
        }
    }
    rest.is_empty() || hex_check_neon_short(&src[src.len() - rest.len().max(16)..], check_case)
}

// At most 64 bytes. Overlapping blocks cover the complete input, with only
// one horizontal reduction. The caller handles longer inputs in 64-byte batches.
#[inline]
#[target_feature(enable = "neon")]
#[cfg(target_arch = "aarch64")]
unsafe fn hex_check_neon_short(src: &[u8], check_case: CheckCase) -> bool {
    if src.len() < 16 {
        return hex_check_fallback_with_case(src, check_case);
    }
    let a = valid_neon(vld1q_u8(src.as_ptr()), check_case);
    if src.len() == 16 {
        return vminvq_u8(a) != 0;
    }
    let b = valid_neon(vld1q_u8(src.as_ptr().add(src.len() - 16)), check_case);
    let valid = if src.len() <= 32 {
        vandq_u8(a, b)
    } else {
        let c = valid_neon(vld1q_u8(src.as_ptr().add(16)), check_case);
        let valid = vandq_u8(vandq_u8(a, b), c);
        if src.len() <= 48 {
            valid
        } else {
            let d = valid_neon(vld1q_u8(src.as_ptr().add(src.len() - 32)), check_case);
            vandq_u8(valid, d)
        }
    };
    vminvq_u8(valid) != 0
}

#[inline]
#[target_feature(enable = "neon")]
#[cfg(target_arch = "aarch64")]
unsafe fn decode_neon_block(high: uint8x16_t, low: uint8x16_t) -> uint8x16_t {
    // Valid ASCII hex letters need nine added to their low nibble. SLI packs
    // just those nibbles, discarding the ASCII high bits without separate masks.
    let adjust = |bytes| vmlaq_u8(bytes, vshrq_n_u8::<6>(bytes), vdupq_n_u8(9));
    vsliq_n_u8::<4>(adjust(low), adjust(high))
}

// 17..=32 decoded bytes fit in four input registers. Overlapping end
// blocks cover the complete input; validate all registers before either store.
#[inline]
#[target_feature(enable = "neon")]
#[cfg(target_arch = "aarch64")]
unsafe fn hex_decode_bounded_neon(src: &[u8], dst: &mut [u8], case: CheckCase) -> Result<(), ()> {
    let a = decode_neon_nibbles(vld1q_u8(src.as_ptr()), case);
    let b = decode_neon_nibbles(vld1q_u8(src.as_ptr().add(16)), case);
    let c = decode_neon_nibbles(vld1q_u8(src.as_ptr().add(src.len() - 32)), case);
    let d = decode_neon_nibbles(vld1q_u8(src.as_ptr().add(src.len() - 16)), case);
    if vmaxvq_u8(vorrq_u8(vorrq_u8(a, b), vorrq_u8(c, d))) > 15 {
        return Err(());
    }
    let pack = |hi, lo| vsliq_n_u8::<4>(vuzp2q_u8(hi, lo), vuzp1q_u8(hi, lo));
    vst1q_u8(dst.as_mut_ptr(), pack(a, b));
    vst1q_u8(dst.as_mut_ptr().add(dst.len() - 16), pack(c, d));
    Ok(())
}

#[inline]
#[target_feature(enable = "neon")]
#[cfg(target_arch = "aarch64")]
unsafe fn hex_decode_neon(src: &[u8], dst: &mut [u8]) {
    if src.len() < 32 {
        return hex_decode_fallback(src, dst);
    }
    let (batches, rest) = src.as_chunks::<128>();
    let (outputs, remaining) = dst.as_chunks_mut::<64>();
    for (input, output) in batches.iter().zip(outputs) {
        for (input, output) in input
            .as_chunks::<32>()
            .0
            .iter()
            .zip(output.as_chunks_mut::<16>().0)
        {
            let uint8x16x2_t(a, b) = vld2q_u8(input.as_ptr());
            vst1q_u8(output.as_mut_ptr(), decode_neon_block(a, b));
        }
    }
    let (blocks, tail) = rest.as_chunks::<32>();
    for (input, output) in blocks.iter().zip(remaining.as_chunks_mut::<16>().0) {
        let uint8x16x2_t(a, b) = vld2q_u8(input.as_ptr());
        vst1q_u8(output.as_mut_ptr(), decode_neon_block(a, b));
    }
    if !tail.is_empty() {
        // Input is already validated. An overlapping final block avoids scalar
        // tails while keeping every load and store within the original slices.
        match (src.last_chunk::<32>(), dst.last_chunk_mut::<16>()) {
            (Some(input), Some(output)) => {
                let uint8x16x2_t(a, b) = vld2q_u8(input.as_ptr());
                vst1q_u8(output.as_mut_ptr(), decode_neon_block(a, b));
            }
            _ => hex_decode_fallback(src, dst),
        }
    }
}

/// Decodes all of `src` into `dst` without allocation, accepting either letter case.
///
/// `src` must contain an even number of ASCII hex digits, without a prefix,
/// whitespace or separators. Uppercase and lowercase digits may be mixed. Leading
/// zeroes are preserved as bytes; this converts a byte sequence, not an integer.
///
/// `dst` must have at least `src.len() / 2` bytes. The returned mutable slice
/// covers exactly the written prefix and borrows only `dst`. Spare destination
/// bytes remain unchanged. Empty input returns an empty slice and changes nothing.
///
/// Use [`hex_decode_with_case`] to restrict letter case, or [`hex_decode_array`]
/// when the decoded size must match a fixed array exactly.
///
/// # Errors
///
/// Errors are checked in this order:
///
/// 1. [`Error::OddLength`] if the input has an odd number of bytes.
/// 2. [`Error::OutputTooSmall`] if the destination is too small. `required` counts
///    the full decoded output size in bytes.
/// 3. [`Error::InvalidChar`] for the first invalid input byte. `index` is a
///    zero-based byte offset in `src`, not a Unicode character position.
///
/// Every error leaves the **entire destination unchanged**, including when an
/// invalid byte occurs after a long valid prefix. A short destination never
/// causes silent prefix decoding; slice `src` explicitly if that is intended.
///
/// # Examples
///
/// ```
/// use faster_hex::hex_decode;
///
/// let mut destination = [0xa5; 5];
/// let bytes = {
///     let source = *b"00aBcD";
///     hex_decode(&source, &mut destination)?
/// }; // The source is no longer needed.
/// assert_eq!(bytes, &[0, 0xab, 0xcd]);
/// bytes[0] = 0xff;
/// assert_eq!(destination, [0xff, 0xab, 0xcd, 0xa5, 0xa5]);
/// # Ok::<(), faster_hex::Error>(())
/// ```
///
/// Invalid input does not commit a partial result:
///
/// ```
/// use faster_hex::{hex_decode, Error};
///
/// let mut destination = [0xa5; 3];
/// assert!(matches!(hex_decode(b"00ff0g", &mut destination),
///     Err(Error::InvalidChar { index: 5, byte: b'g', .. })));
/// assert_eq!(destination, [0xa5; 3]);
/// ```
#[inline]
pub fn hex_decode<'a>(src: &[u8], dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
    hex_decode_with_case(src, dst, CheckCase::None)
}

/// Decodes all of `src` into `dst` using an explicit letter-case policy.
///
/// The size, borrowing and destination-preservation guarantees are identical to
/// [`hex_decode`]. Digits are accepted under every policy; [`CheckCase::None`]
/// also accepts mixed-case letters. No allocation is performed.
///
/// # Errors
///
/// Returns the same errors in the same order as [`hex_decode`]. A letter rejected
/// by `check_case` is an [`Error::InvalidChar`], with its byte and zero-based
/// position in `src`. The first invalid byte wins, including when it is a case
/// violation before another non-hex byte. The entire destination remains unchanged.
///
/// # Examples
///
/// ```
/// use faster_hex::{hex_decode_with_case, CheckCase, Error};
///
/// let mut bytes = [0; 2];
/// hex_decode_with_case(b"ab01", &mut bytes, CheckCase::Lower)?;
/// assert_eq!(bytes, [0xab, 1]);
/// assert!(matches!(hex_decode_with_case(b"Ab01", &mut bytes, CheckCase::Lower),
///     Err(Error::InvalidChar { index: 0, byte: b'A', .. })));
/// assert_eq!(bytes, [0xab, 1]);
/// # Ok::<(), Error>(())
/// ```
#[inline(always)]
pub fn hex_decode_with_case<'a>(
    src: &[u8],
    dst: &'a mut [u8],
    check_case: CheckCase,
) -> Result<&'a mut [u8], Error> {
    if !src.len().is_multiple_of(2) {
        return Err(Error::OddLength);
    }
    let len = src.len() / 2;
    let dst = dst
        .get_mut(..len)
        .ok_or(Error::OutputTooSmall { required: len })?;
    if decode_checked(src, dst, check_case).is_err() {
        decode_diagnosed(src, dst, check_case)?;
    }
    Ok(dst)
}

/// Decodes exactly `N` bytes into an array without allocation, accepting either case.
///
/// The input grammar is the same as [`hex_decode`], but the decoded length must
/// equal `N`: both shorter and longer inputs are rejected. The result owns its
/// bytes independently of the input. Only `N == 0` accepts empty input.
///
/// Use [`hex_decode_array_with_case`] for a strict letter-case policy, or
/// [`hex_decode`] to write into a slice with spare capacity.
///
/// # Errors
///
/// Checks [`Error::OddLength`] first, [`Error::LengthMismatch`] second, and
/// [`Error::InvalidChar`] last. The mismatch's `expected` and `actual` fields
/// both count decoded bytes; character positions count source bytes. Prefixes,
/// whitespace and separators are rejected as invalid characters.
///
/// # Examples
///
/// ```
/// use faster_hex::hex_decode_array;
/// let bytes = hex_decode_array::<4>(b"0001aBff")?;
/// assert_eq!(bytes, [0, 1, 0xab, 0xff]);
/// assert!(hex_decode_array::<4>(b"0001").is_err());
/// assert_eq!(hex_decode_array::<0>(b"")?, []);
/// # Ok::<(), faster_hex::Error>(())
/// ```
#[inline]
pub fn hex_decode_array<const N: usize>(src: &[u8]) -> Result<[u8; N], Error> {
    hex_decode_array_with_case(src, CheckCase::None)
}

/// Decodes exactly `N` bytes into an array using an explicit letter-case policy.
///
/// This has the ownership, exact-length and allocation-free guarantees of
/// [`hex_decode_array`]. Only `N == 0` accepts empty input.
///
/// # Errors
///
/// Returns [`Error::OddLength`], [`Error::LengthMismatch`], then
/// [`Error::InvalidChar`] in that order. A disallowed letter case is an invalid
/// character. Mismatched lengths count decoded bytes; invalid-character indexes
/// count source bytes.
///
/// # Examples
///
/// ```
/// use faster_hex::{hex_decode_array_with_case, CheckCase};
///
/// let id = hex_decode_array_with_case::<2>(b"AB01", CheckCase::Upper)?;
/// assert_eq!(id, [0xab, 1]);
/// assert!(hex_decode_array_with_case::<2>(b"ab01", CheckCase::Upper).is_err());
/// # Ok::<(), faster_hex::Error>(())
/// ```
#[inline]
pub fn hex_decode_array_with_case<const N: usize>(
    src: &[u8],
    check_case: CheckCase,
) -> Result<[u8; N], Error> {
    if !src.len().is_multiple_of(2) {
        return Err(Error::OddLength);
    }
    let actual = src.len() / 2;
    if actual != N {
        return Err(Error::LengthMismatch {
            expected: N,
            actual,
        });
    }
    let mut bytes = [0; N];
    hex_decode_with_case(src, &mut bytes, check_case)?;
    Ok(bytes)
}

/// Decodes the complete input into a new vector, accepting either letter case.
///
/// Available with `alloc`. The result owns exactly `src.len() / 2` decoded bytes,
/// independently of the input. Empty input produces an empty vector. The same
/// strict ASCII grammar as [`hex_decode`] applies: no prefixes, whitespace or
/// separators. Use [`hex_decode_vec_with_case`] to restrict letter case.
///
/// # Errors
///
/// Returns [`Error::OddLength`] for odd input, before allocating output. Even
/// input is checked for [`Error::InvalidChar`] after allocation, so malformed
/// even-length input can allocate before its first invalid byte is reported.
///
/// There is no input-size limit or recoverable allocation-error result. The
/// vector uses the allocator's normal error handling. Apply an application limit
/// before calling when necessary, or use [`hex_decode`] with reusable storage.
///
/// # Examples
///
/// ```
/// assert_eq!(faster_hex::hex_decode_vec(b"00aBff")?, [0, 0xab, 0xff]);
/// assert!(faster_hex::hex_decode_vec(b"0x01").is_err());
/// # Ok::<(), faster_hex::Error>(())
/// ```
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[inline]
pub fn hex_decode_vec(src: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    hex_decode_vec_with_case(src, CheckCase::None)
}

/// Decodes the complete input into a new vector using a letter-case policy.
///
/// Available with `alloc`. Ownership, grammar and allocation behavior are the
/// same as [`hex_decode_vec`]. Digits are accepted under every policy.
///
/// # Errors
///
/// Returns [`Error::OddLength`] before allocation, then [`Error::InvalidChar`]
/// for the first invalid byte or disallowed letter. As with [`hex_decode_vec`],
/// allocation failure is not returned as a codec error and no size limit is imposed.
///
/// # Examples
///
/// ```
/// use faster_hex::{hex_decode_vec_with_case, CheckCase};
///
/// assert_eq!(hex_decode_vec_with_case(b"AB01", CheckCase::Upper)?, [0xab, 1]);
/// assert!(hex_decode_vec_with_case(b"ab01", CheckCase::Upper).is_err());
/// # Ok::<(), faster_hex::Error>(())
/// ```
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[inline]
pub fn hex_decode_vec_with_case(
    src: &[u8],
    check_case: CheckCase,
) -> Result<alloc::vec::Vec<u8>, Error> {
    if !src.len().is_multiple_of(2) {
        return Err(Error::OddLength);
    }
    let mut bytes = alloc::vec![0; src.len() / 2];
    hex_decode_with_case(src, &mut bytes, check_case)?;
    Ok(bytes)
}

// Inline the boundary and dispatch together so short decodes can keep their
// result and SIMD constants in the caller instead of a separate stack frame.
#[inline(always)]
pub(crate) fn decode_checked(src: &[u8], dst: &mut [u8], check_case: CheckCase) -> Result<(), ()> {
    if dst.len() < 8 {
        return hex_decode_short_scalar(src, dst, check_case);
    }
    #[cfg(target_arch = "aarch64")]
    let len = dst.len();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        match crate::vectorization_support() {
            crate::Vectorization::AVX512 => {
                // SAFETY: Dispatch checked AVX2 and AVX-512BW with its OS state;
                // dst has exactly src.len() / 2 bytes.
                unsafe { hex_decode_avx512_checked(src, dst, check_case) }
            }
            crate::Vectorization::AVX2 => {
                // SAFETY: AVX2 is available and the slices have the exact 2:1 ratio.
                unsafe { hex_decode_avx2_checked(src, dst, check_case) }
            }
            crate::Vectorization::SSE41 => {
                // SAFETY: SSE4.1 is available and the slice lengths have the exact ratio.
                unsafe { hex_decode_sse41_checked(src, dst, check_case) }
            }
            crate::Vectorization::None => {
                if !hex_check_fallback_with_case(src, check_case) {
                    return Err(());
                }
                hex_decode_fallback(src, dst);
                Ok(())
            }
        }
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        #[cfg(target_arch = "aarch64")]
        if (17..=32).contains(&len) && crate::vectorization_support() == crate::Vectorization::Neon
        {
            // SAFETY: NEON is available; src has 34..=64 bytes and dst is its exact half.
            return unsafe { hex_decode_bounded_neon(src, dst, check_case) };
        }

        #[cfg(target_arch = "aarch64")]
        if (8..=16).contains(&len) && crate::vectorization_support() == crate::Vectorization::Neon {
            // SAFETY: Each complete 16-byte load and 8-byte store stays in its slice.
            return unsafe { hex_decode_short_neon(src, dst, check_case) };
        }
        if !hex_check_with_case(src, check_case) {
            return Err(());
        }
        hex_decode_unchecked(src, dst);
        Ok(())
    }
}

// Fewer than eight output bytes fit in one word. Decode each pair once
// and commit only after the complete input has passed validation.
#[inline]
pub(crate) fn hex_decode_short_scalar(
    src: &[u8],
    dst: &mut [u8],
    case: CheckCase,
) -> Result<(), ()> {
    let table = match case {
        CheckCase::None => &UNHEX,
        CheckCase::Lower => &UNHEX_LOWER,
        CheckCase::Upper => &UNHEX_UPPER,
    };
    let mut decoded = 0u64;
    for pair in src.as_chunks::<2>().0 {
        let high = table[usize::from(pair[0])];
        let low = table[usize::from(pair[1])];
        if high | low == NIL {
            return Err(());
        }
        decoded = decoded << 8 | u64::from(high << 4 | low);
    }
    // The word is built in input order, so its low byte belongs in the last slot.
    for slot in dst.iter_mut().rev() {
        *slot = decoded as u8;
        decoded >>= 8;
    }
    Ok(())
}

// Backends report validity; diagnostics belong to the public boundary. The
// successful SIMD path does not track byte positions or construct an error.
#[cold]
fn decode_diagnosed(src: &[u8], dst: &mut [u8], case: CheckCase) -> Result<(), Error> {
    let table = match case {
        CheckCase::None => &UNHEX,
        CheckCase::Lower => &UNHEX_LOWER,
        CheckCase::Upper => &UNHEX_UPPER,
    };
    // Skip valid blocks so locating a late error retains SIMD throughput.
    // Short inputs go directly to the byte scan.
    let skipped = if src.len() > 64 {
        src.chunks_exact(64)
            .take_while(|chunk| hex_check_with_case(chunk, case))
            .count()
            * 64
    } else {
        0
    };
    for (offset, &byte) in src[skipped..].iter().enumerate() {
        let index = skipped + offset;
        if table[usize::from(byte)] == NIL {
            return Err(Error::InvalidChar { index, byte });
        }
    }
    // Every byte was validated. A scalar conversion also handles a backend
    // rejecting valid input; never return an unwritten output prefix.
    hex_decode_fallback(src, dst);
    Ok(())
}

// Internal conversion only. Even if miscalled with short input, never pass an
// undersized source to a SIMD kernel. Public callers must use checked decode.
#[cfg(any(test, not(any(target_arch = "x86", target_arch = "x86_64"))))]
pub(crate) fn hex_decode_unchecked(src: &[u8], dst: &mut [u8]) {
    let len = core::cmp::min(src.len() / 2, dst.len());
    let src = &src[..len * 2];
    let dst = &mut dst[..len];
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        match crate::vectorization_support() {
            crate::Vectorization::AVX512 => {
                // SAFETY: Dispatch checks AVX-512BW; the slices have a 2:1 length ratio.
                unsafe { hex_decode_avx512(src, dst) }
            }
            crate::Vectorization::AVX2 => {
                // SAFETY: Dispatch guarantees AVX2 and the slices have a 2:1 length ratio.
                unsafe { hex_decode_avx2(src, dst) }
            }
            crate::Vectorization::SSE41 => {
                // SAFETY: Dispatch guarantees SSE4.1 and the slices have a 2:1 length ratio.
                unsafe { hex_decode_sse41(src, dst) }
            }
            crate::Vectorization::None => hex_decode_fallback(src, dst),
        }
    }
    #[cfg(target_arch = "aarch64")]
    match crate::vectorization_support() {
        crate::Vectorization::Neon => {
            // SAFETY: Dispatch guarantees NEON; both slices have the exact 2:1 ratio.
            unsafe { hex_decode_neon(src, dst) }
        }
        crate::Vectorization::None => hex_decode_fallback(src, dst),
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    hex_decode_fallback(src, dst);
}

// Called after public length checks. Bounded inputs stay in registers until
// every byte is validated; the general path validates the complete input first.
#[target_feature(enable = "sse4.1")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) unsafe fn hex_decode_sse41_checked(
    src: &[u8],
    dst: &mut [u8],
    case: CheckCase,
) -> Result<(), ()> {
    if (16..=32).contains(&src.len()) {
        let a = decode_sse41_nibbles(_mm_loadu_si128(src.as_ptr().cast()), case);
        // An eight-byte output fits in this one load; no overlapping tail is needed.
        if src.len() == 16 {
            if _mm_testz_si128(a, _mm_set1_epi8(-16)) == 0 {
                return Err(());
            }
            _mm_storel_epi64(dst.as_mut_ptr().cast(), pack_sse41(a, a));
            return Ok(());
        }
        let b = decode_sse41_nibbles(
            _mm_loadu_si128(src.as_ptr().add(src.len() - 16).cast()),
            case,
        );
        if _mm_testz_si128(_mm_or_si128(a, b), _mm_set1_epi8(-16)) == 0 {
            return Err(());
        }
        let decoded = pack_sse41(a, b);
        _mm_storel_epi64(dst.as_mut_ptr().cast(), decoded);
        _mm_storel_epi64(
            dst.as_mut_ptr().add(dst.len() - 8).cast(),
            _mm_srli_si128::<8>(decoded),
        );
    } else if (32..=64).contains(&src.len()) {
        let a = decode_sse41_nibbles(_mm_loadu_si128(src.as_ptr().cast()), case);
        let b = decode_sse41_nibbles(_mm_loadu_si128(src.as_ptr().add(16).cast()), case);
        let c = decode_sse41_nibbles(
            _mm_loadu_si128(src.as_ptr().add(src.len() - 32).cast()),
            case,
        );
        let d = decode_sse41_nibbles(
            _mm_loadu_si128(src.as_ptr().add(src.len() - 16).cast()),
            case,
        );
        let combined = _mm_or_si128(_mm_or_si128(a, b), _mm_or_si128(c, d));
        if _mm_testz_si128(combined, _mm_set1_epi8(-16)) == 0 {
            return Err(());
        }
        _mm_storeu_si128(dst.as_mut_ptr().cast(), pack_sse41(a, b));
        _mm_storeu_si128(
            dst.as_mut_ptr().add(dst.len() - 16).cast(),
            pack_sse41(c, d),
        );
    } else {
        if !hex_check_sse_with_case(src, case) {
            return Err(());
        }
        hex_decode_sse41(src, dst);
    }
    Ok(())
}

#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
pub(crate) unsafe fn hex_decode_avx2_checked(
    src: &[u8],
    dst: &mut [u8],
    case: CheckCase,
) -> Result<(), ()> {
    // Common fixed sizes use constant offsets and avoid duplicate tail loads.
    // Every branch validates the complete input before its first store.
    if src.len() == 64 {
        let (a, a_checked) = decode_avx2_nibbles(_mm256_loadu_si256(src.as_ptr().cast()), case);
        let (b, b_checked) =
            decode_avx2_nibbles(_mm256_loadu_si256(src.as_ptr().add(32).cast()), case);
        if _mm256_movemask_epi8(_mm256_or_si256(a_checked, b_checked)) != 0 {
            return Err(());
        }
        _mm256_storeu_si256(dst.as_mut_ptr().cast(), pack_avx2(a, b));
        return Ok(());
    }
    if src.len() == 32 {
        let (nibbles, checked) = decode_avx2_nibbles(_mm256_loadu_si256(src.as_ptr().cast()), case);
        if _mm256_movemask_epi8(checked) != 0 {
            return Err(());
        }
        _mm_storeu_si128(
            dst.as_mut_ptr().cast(),
            _mm256_castsi256_si128(pack_avx2(nibbles, nibbles)),
        );
        return Ok(());
    }
    if src.len() < 32 {
        return hex_decode_sse41_checked(src, dst, case);
    }
    if src.len() < 64 {
        let (a, a_checked) = decode_avx2_nibbles(_mm256_loadu_si256(src.as_ptr().cast()), case);
        let (b, b_checked) = decode_avx2_nibbles(
            _mm256_loadu_si256(src.as_ptr().add(src.len() - 32).cast()),
            case,
        );
        if _mm256_movemask_epi8(_mm256_or_si256(a_checked, b_checked)) != 0 {
            return Err(());
        }
        let packed = pack_avx2(a, b);
        _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm256_castsi256_si128(packed));
        _mm_storeu_si128(
            dst.as_mut_ptr().add(dst.len() - 16).cast(),
            _mm256_extracti128_si256::<1>(packed),
        );
    } else if src.len() <= 128 {
        let (a, a_checked) = decode_avx2_nibbles(_mm256_loadu_si256(src.as_ptr().cast()), case);
        let (b, b_checked) =
            decode_avx2_nibbles(_mm256_loadu_si256(src.as_ptr().add(32).cast()), case);
        let (c, c_checked) = decode_avx2_nibbles(
            _mm256_loadu_si256(src.as_ptr().add(src.len() - 64).cast()),
            case,
        );
        let (d, d_checked) = decode_avx2_nibbles(
            _mm256_loadu_si256(src.as_ptr().add(src.len() - 32).cast()),
            case,
        );
        let checked = _mm256_or_si256(
            _mm256_or_si256(a_checked, b_checked),
            _mm256_or_si256(c_checked, d_checked),
        );
        if _mm256_movemask_epi8(checked) != 0 {
            return Err(());
        }
        _mm256_storeu_si256(dst.as_mut_ptr().cast(), pack_avx2(a, b));
        _mm256_storeu_si256(dst.as_mut_ptr().add(dst.len() - 32).cast(), pack_avx2(c, d));
    } else {
        if !hex_check_avx2_with_case(src, case) {
            return Err(());
        }
        hex_decode_avx2(src, dst);
    }
    Ok(())
}

#[target_feature(enable = "avx512f,avx512bw")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
pub(crate) unsafe fn hex_decode_avx512_checked(
    src: &[u8],
    dst: &mut [u8],
    case: CheckCase,
) -> Result<(), ()> {
    if src.len() < 64 {
        return hex_decode_avx2_checked(src, dst, case);
    }
    if src.len() == 64 {
        let (nibbles, checked) =
            decode_avx512_nibbles(_mm512_loadu_si512(src.as_ptr().cast()), case);
        if _mm512_movepi8_mask(checked) != 0 {
            return Err(());
        }
        _mm256_storeu_si256(dst.as_mut_ptr().cast(), pack_avx512(nibbles));
    } else if src.len() <= 128 {
        let (a, a_checked) = decode_avx512_nibbles(_mm512_loadu_si512(src.as_ptr().cast()), case);
        let (b, b_checked) = decode_avx512_nibbles(
            _mm512_loadu_si512(src.as_ptr().add(src.len() - 64).cast()),
            case,
        );
        if _mm512_movepi8_mask(_mm512_or_si512(a_checked, b_checked)) != 0 {
            return Err(());
        }
        _mm256_storeu_si256(dst.as_mut_ptr().cast(), pack_avx512(a));
        _mm256_storeu_si256(dst.as_mut_ptr().add(dst.len() - 32).cast(), pack_avx512(b));
    } else {
        if !hex_check_avx512_with_case(src, case) {
            return Err(());
        }
        hex_decode_avx512(src, dst);
    }
    Ok(())
}

#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn pack_avx512(nibbles: __m512i) -> __m256i {
    _mm512_cvtepi16_epi8(_mm512_maddubs_epi16(nibbles, _mm512_set1_epi16(0x0110)))
}

#[target_feature(enable = "avx512f,avx512bw")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) unsafe fn hex_decode_avx512(src: &[u8], dst: &mut [u8]) {
    if src.len() < 64 {
        return hex_decode_avx2(src, dst);
    }
    let convert = |input: &[u8; 64], output: &mut [u8; 32]| {
        let bytes = _mm512_loadu_si512(input.as_ptr().cast());
        let low = _mm512_and_si512(bytes, _mm512_set1_epi8(15));
        let letters = _mm512_cmpgt_epu8_mask(bytes, _mm512_set1_epi8(b'9' as i8));
        let nibbles = _mm512_mask_add_epi8(low, letters, low, _mm512_set1_epi8(9));
        _mm256_storeu_si256(output.as_mut_ptr().cast(), pack_avx512(nibbles));
    };
    let (blocks, tail) = src.as_chunks::<64>();
    for (input, output) in blocks.iter().zip(dst.as_chunks_mut::<32>().0) {
        convert(input, output);
    }
    if !tail.is_empty() {
        if let (Some(input), Some(output)) = (src.last_chunk::<64>(), dst.last_chunk_mut::<32>()) {
            convert(input, output);
        }
    }
}

#[inline]
#[target_feature(enable = "sse4.1")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn decode_sse41_block(a: __m128i, b: __m128i) -> __m128i {
    let nibble = |bytes| {
        // Valid ASCII letters add nine to their low nibble.
        _mm_add_epi8(
            _mm_and_si128(bytes, _mm_set1_epi8(15)),
            _mm_and_si128(
                _mm_cmpgt_epi8(bytes, _mm_set1_epi8(b'9' as i8)),
                _mm_set1_epi8(9),
            ),
        )
    };
    pack_sse41(nibble(a), nibble(b))
}

#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn decode_avx2_block(a: __m256i, b: __m256i) -> __m256i {
    let nibble = |bytes| {
        _mm256_add_epi8(
            _mm256_and_si256(bytes, _mm256_set1_epi8(15)),
            _mm256_and_si256(
                _mm256_cmpgt_epi8(bytes, _mm256_set1_epi8(b'9' as i8)),
                _mm256_set1_epi8(9),
            ),
        )
    };
    pack_avx2(nibble(a), nibble(b))
}

#[inline]
#[target_feature(enable = "sse4.1")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn pack_sse41(a: __m128i, b: __m128i) -> __m128i {
    // PMADDUBSW combines adjacent nibbles with [16, 1]; no result exceeds 255.
    let weights = _mm_set1_epi16(0x0110);
    _mm_packus_epi16(_mm_maddubs_epi16(a, weights), _mm_maddubs_epi16(b, weights))
}

#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn pack_avx2(a: __m256i, b: __m256i) -> __m256i {
    let weights = _mm256_set1_epi16(0x0110);
    // Packing is lane-local; restore the original order of the four 8-byte groups.
    _mm256_permute4x64_epi64::<0xd8>(_mm256_packus_epi16(
        _mm256_maddubs_epi16(a, weights),
        _mm256_maddubs_epi16(b, weights),
    ))
}

#[target_feature(enable = "sse4.1")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) unsafe fn hex_decode_sse41(src: &[u8], dst: &mut [u8]) {
    if src.len() < 32 {
        return hex_decode_fallback(src, dst);
    }
    let convert = |input: &[u8; 32], output: &mut [u8; 16]| {
        let a = _mm_loadu_si128(input.as_ptr().cast());
        let b = _mm_loadu_si128(input.as_ptr().add(16).cast());
        _mm_storeu_si128(output.as_mut_ptr().cast(), decode_sse41_block(a, b));
    };
    let (blocks, tail) = src.as_chunks::<32>();
    for (input, output) in blocks.iter().zip(dst.as_chunks_mut::<16>().0) {
        convert(input, output);
    }
    if !tail.is_empty() {
        if let (Some(input), Some(output)) = (src.last_chunk::<32>(), dst.last_chunk_mut::<16>()) {
            convert(input, output);
        }
    }
}

#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) unsafe fn hex_decode_avx2(src: &[u8], dst: &mut [u8]) {
    if src.len() < 64 {
        return hex_decode_sse41(src, dst);
    }
    let convert = |input: &[u8; 64], output: &mut [u8; 32]| {
        let a = _mm256_loadu_si256(input.as_ptr().cast());
        let b = _mm256_loadu_si256(input.as_ptr().add(32).cast());
        _mm256_storeu_si256(output.as_mut_ptr().cast(), decode_avx2_block(a, b));
    };
    let (blocks, tail) = src.as_chunks::<64>();
    for (input, output) in blocks.iter().zip(dst.as_chunks_mut::<32>().0) {
        convert(input, output);
    }
    if !tail.is_empty() {
        if let (Some(input), Some(output)) = (src.last_chunk::<64>(), dst.last_chunk_mut::<32>()) {
            convert(input, output);
        }
    }
}

#[inline]
pub(crate) fn hex_decode_fallback(src: &[u8], dst: &mut [u8]) {
    for (slot, bytes) in dst.iter_mut().zip(src.chunks_exact(2)) {
        let a = UNHEX4[bytes[0] as usize];
        let b = UNHEX[bytes[1] as usize];
        *slot = a | b;
    }
}

#[inline]
#[target_feature(enable = "neon")]
#[cfg(target_arch = "aarch64")]
unsafe fn hex_decode_short_neon(src: &[u8], dst: &mut [u8], case: CheckCase) -> Result<(), ()> {
    let pack = |a, b| vsliq_n_u8::<4>(vuzp2q_u8(a, b), vuzp1q_u8(a, b));
    let a = decode_neon_nibbles(vld1q_u8(src.as_ptr()), case);
    if src.len() == 16 {
        if vmaxvq_u8(a) > 15 {
            return Err(());
        }
        vst1_u8(dst.as_mut_ptr(), vget_low_u8(pack(a, a)));
        return Ok(());
    }
    let b = decode_neon_nibbles(vld1q_u8(src.as_ptr().add(src.len() - 16)), case);
    if vmaxvq_u8(vorrq_u8(a, b)) > 15 {
        return Err(());
    }
    let decoded = pack(a, b);
    vst1_u8(dst.as_mut_ptr(), vget_low_u8(decoded));
    vst1_u8(dst.as_mut_ptr().add(dst.len() - 8), vget_high_u8(decoded));
    Ok(())
}
