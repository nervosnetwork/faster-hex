//! Mixed-case validation and first-error diagnosis for `hex_validate`.
//!
//! Kept separate from 2.0's `hex_check` and parameterized on width so 2.0-only
//! callers never instantiate new rlib symbols, while x86 validation drops
//! runtime case selection and handles 32..=64-byte hashes without loops.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::error::Error;

use super::{hex_check_fallback_with_case, CheckCase, NIL, UNHEX};

#[inline]
pub(super) fn check_mixed(src: &[u8]) -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        match crate::vectorization_support() {
            crate::Vectorization::AVX512 => {
                // SAFETY: Dispatch checked AVX-512F and AVX-512BW.
                unsafe { check_mixed_avx512::<64>(src) }
            }
            crate::Vectorization::AVX2 => {
                // SAFETY: Dispatch checked AVX2.
                unsafe { check_mixed_avx2::<32>(src) }
            }
            crate::Vectorization::SSE41 => {
                // SAFETY: Dispatch checked SSE4.1 (which implies SSE2).
                unsafe { check_mixed_sse::<16>(src) }
            }
            crate::Vectorization::None => check_mixed_fallback::<1>(src),
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if crate::vectorization_support() == crate::Vectorization::Neon {
            // SAFETY: Dispatch checked NEON.
            unsafe { check_mixed_neon(src) }
        } else {
            check_mixed_fallback::<1>(src)
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        hex_check_fallback_with_case(src, CheckCase::None)
    }
}

// Generic so 2.0-only callers never emit it, and `#[cold] #[inline(never)]` so
// valid SIMD loops never hoist `UNHEX` GOT loads onto hot branches.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
#[cold]
#[inline(never)]
fn check_mixed_fallback<const _WIDTH: usize>(src: &[u8]) -> bool {
    hex_check_fallback_with_case(src, CheckCase::None)
}

// Inline into `hex_validate` as a cold branch with plain loops so valid caller
// loops keep `UNHEX` out of hot branches without emitting `TakeWhile::fold`
// call frames or register spills, while late-error diagnosis stays inlined.
#[cold]
#[inline(always)]
pub(super) fn diagnose_invalid(src: &[u8]) -> Result<(), Error> {
    const CHUNK: usize = 64;
    let table = &UNHEX;
    // Report a malformed first pair before scanning any SIMD blocks.
    for (index, &byte) in src.iter().take(2).enumerate() {
        if table[usize::from(byte)] == NIL {
            return Err(Error::InvalidChar { index, byte });
        }
    }
    // Skip valid blocks so locating a late error retains SIMD throughput.
    let mut skipped = 0;
    if src.len() > CHUNK {
        for chunk in src.chunks_exact(CHUNK) {
            if !check_mixed(chunk) {
                break;
            }
            skipped += CHUNK;
        }
    }
    // Four independent lookups skip valid digits before the exact byte scan.
    // A rejected digit sets all bits. Valid entries use only the low nibble.
    let mut start = skipped;
    for group in src[skipped..].as_chunks::<4>().0 {
        if (table[usize::from(group[0])]
            | table[usize::from(group[1])]
            | table[usize::from(group[2])]
            | table[usize::from(group[3])])
            == NIL
        {
            break;
        }
        start += 4;
    }
    for (offset, &byte) in src[start..].iter().enumerate() {
        if table[usize::from(byte)] == NIL {
            return Err(Error::InvalidChar {
                index: start + offset,
                byte,
            });
        }
    }
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn valid_sse_mixed(bytes: __m128i) -> __m128i {
    let digit = _mm_cmpgt_epi8(_mm_set1_epi8(-118), _mm_add_epi8(bytes, _mm_set1_epi8(80)));
    let letters = _mm_or_si128(bytes, _mm_set1_epi8(0x20));
    let letter = _mm_cmpgt_epi8(
        _mm_set1_epi8(-122),
        _mm_add_epi8(letters, _mm_set1_epi8(128u8.wrapping_sub(b'a') as i8)),
    );
    _mm_or_si128(digit, letter)
}

// Keep SSE checking out of AVX2/AVX-512 caller loops so `UNHEX` and XMM
// constants do not increase caller register pressure when SSE2 is baseline.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(never)]
#[target_feature(enable = "sse2")]
unsafe fn check_mixed_sse<const _WIDTH: usize>(src: &[u8]) -> bool {
    let len = src.len();
    if len < 16 {
        return hex_check_fallback_with_case(src, CheckCase::None);
    }
    if len <= 32 {
        // SAFETY: `16 <= len <= 32`, so both 16-byte windows stay in bounds and SSE2 is active.
        return unsafe {
            let a = valid_sse_mixed(_mm_loadu_si128(src.as_ptr().cast()));
            let b = valid_sse_mixed(_mm_loadu_si128(src.as_ptr().add(len - 16).cast()));
            _mm_movemask_epi8(_mm_and_si128(a, b)) == 0xffff
        };
    }
    let (blocks, tail) = src.as_chunks::<16>();
    for block in blocks {
        // SAFETY: `block` is a 16-byte array and SSE2 is active.
        let mask =
            unsafe { _mm_movemask_epi8(valid_sse_mixed(_mm_loadu_si128(block.as_ptr().cast()))) };
        if mask != 0xffff {
            return false;
        }
    }
    // SAFETY: `len > 32`, so the trailing 16-byte window stays in bounds and SSE2 is active.
    tail.is_empty()
        || unsafe {
            _mm_movemask_epi8(valid_sse_mixed(_mm_loadu_si128(
                src.as_ptr().add(len - 16).cast(),
            ))) == 0xffff
        }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn valid_avx2_mixed(bytes: __m256i) -> __m256i {
    let digit = _mm256_cmpgt_epi8(
        _mm256_set1_epi8(-118),
        _mm256_add_epi8(bytes, _mm256_set1_epi8(80)),
    );
    let letters = _mm256_or_si256(bytes, _mm256_set1_epi8(0x20));
    let letter = _mm256_cmpgt_epi8(
        _mm256_set1_epi8(-122),
        _mm256_add_epi8(letters, _mm256_set1_epi8(128u8.wrapping_sub(b'a') as i8)),
    );
    _mm256_or_si256(digit, letter)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn check_mixed_avx2<const _WIDTH: usize>(src: &[u8]) -> bool {
    let len = src.len();
    if len < 32 {
        // SAFETY: AVX2 implies SSE2.
        return unsafe { check_mixed_sse::<16>(src) };
    }
    if len <= 64 {
        // Two overlapping 32-byte vectors cover 32..=64 bytes (SHA-1/SHA-256) without a loop.
        // SAFETY: `32 <= len <= 64`, so both 32-byte windows stay in bounds and AVX2 is active.
        return unsafe {
            let a = valid_avx2_mixed(_mm256_loadu_si256(src.as_ptr().cast()));
            let b = valid_avx2_mixed(_mm256_loadu_si256(src.as_ptr().add(len - 32).cast()));
            _mm256_movemask_epi8(_mm256_and_si256(a, b)) == -1
        };
    }
    let (batches, rest) = src.as_chunks::<128>();
    for batch in batches {
        let mut valid = _mm256_set1_epi8(-1);
        for block in batch.as_chunks::<32>().0 {
            // SAFETY: `block` is a 32-byte array and AVX2 is active.
            valid = _mm256_and_si256(valid, unsafe {
                valid_avx2_mixed(_mm256_loadu_si256(block.as_ptr().cast()))
            });
        }
        if _mm256_movemask_epi8(valid) != -1 {
            return false;
        }
    }
    let (blocks, tail) = rest.as_chunks::<32>();
    let mut valid = _mm256_set1_epi8(-1);
    for block in blocks {
        // SAFETY: `block` is a 32-byte array and AVX2 is active.
        valid = _mm256_and_si256(valid, unsafe {
            valid_avx2_mixed(_mm256_loadu_si256(block.as_ptr().cast()))
        });
    }
    if !tail.is_empty() {
        // SAFETY: `len > 64`, so the trailing 32-byte window stays in bounds and AVX2 is active.
        valid = _mm256_and_si256(valid, unsafe {
            valid_avx2_mixed(_mm256_loadu_si256(src.as_ptr().add(len - 32).cast()))
        });
    }
    _mm256_movemask_epi8(valid) == -1
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn valid_avx512_mixed(bytes: __m512i) -> bool {
    let digit = _mm512_cmple_epu8_mask(
        _mm512_sub_epi8(bytes, _mm512_set1_epi8(b'0' as i8)),
        _mm512_set1_epi8(9),
    );
    let letters = _mm512_or_si512(bytes, _mm512_set1_epi8(0x20));
    let letter = _mm512_cmple_epu8_mask(
        _mm512_sub_epi8(letters, _mm512_set1_epi8(b'a' as i8)),
        _mm512_set1_epi8(5),
    );
    (digit | letter) == u64::MAX
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn check_mixed_avx512<const _WIDTH: usize>(src: &[u8]) -> bool {
    let len = src.len();
    if len == 64 {
        // SAFETY: `len == 64` and AVX-512F/BW are active.
        return unsafe { valid_avx512_mixed(_mm512_loadu_si512(src.as_ptr().cast())) };
    }
    if len < 64 {
        // SAFETY: AVX-512F implies AVX2.
        return unsafe { check_mixed_avx2::<32>(src) };
    }
    let (blocks, tail) = src.as_chunks::<64>();
    for block in blocks {
        // SAFETY: `block` is a 64-byte array and AVX-512F/BW are active.
        if !unsafe { valid_avx512_mixed(_mm512_loadu_si512(block.as_ptr().cast())) } {
            return false;
        }
    }
    // SAFETY: `len > 64`, so the trailing 64-byte window stays in bounds and AVX-512F/BW are active.
    tail.is_empty()
        || unsafe { valid_avx512_mixed(_mm512_loadu_si512(src.as_ptr().add(len - 64).cast())) }
}

// Force inlining when NEON is baseline so `#[cold] diagnose_invalid` still
// inlines chunk-skipping instead of emitting per-64B calls.
#[cfg(target_arch = "aarch64")]
#[cfg_attr(target_feature = "neon", inline(always))]
#[cfg_attr(not(target_feature = "neon"), inline, target_feature(enable = "neon"))]
unsafe fn valid_neon_mixed(bytes: uint8x16_t) -> uint8x16_t {
    // SAFETY: Caller guarantees NEON support (either baseline or via runtime dispatch).
    unsafe {
        let digit = vcleq_u8(vsubq_u8(bytes, vdupq_n_u8(b'0')), vdupq_n_u8(9));
        let letters = vorrq_u8(bytes, vdupq_n_u8(0x20));
        let letter = vcleq_u8(vsubq_u8(letters, vdupq_n_u8(b'a')), vdupq_n_u8(5));
        vorrq_u8(digit, letter)
    }
}

#[cfg(target_arch = "aarch64")]
#[cfg_attr(target_feature = "neon", inline(always))]
#[cfg_attr(not(target_feature = "neon"), inline, target_feature(enable = "neon"))]
unsafe fn check_mixed_neon(src: &[u8]) -> bool {
    if src.len() < 64 {
        // SAFETY: NEON is enabled by this function's contract.
        return unsafe { check_mixed_neon_short(src) };
    }
    let (batches, rest) = src.as_chunks::<64>();
    for batch in batches {
        // SAFETY: `batch` is a 64-byte array and NEON is active.
        let valid = unsafe {
            let a = valid_neon_mixed(vld1q_u8(batch.as_ptr()));
            let b = valid_neon_mixed(vld1q_u8(batch.as_ptr().add(16)));
            let c = valid_neon_mixed(vld1q_u8(batch.as_ptr().add(32)));
            let d = valid_neon_mixed(vld1q_u8(batch.as_ptr().add(48)));
            vminvq_u8(vandq_u8(vandq_u8(a, b), vandq_u8(c, d)))
        };
        if valid == 0 {
            return false;
        }
    }
    // SAFETY: `src.len() >= 64` and `rest.len() < 64`, so the trailing slice is in bounds and NEON is active.
    rest.is_empty() || unsafe { check_mixed_neon_short(&src[src.len() - rest.len().max(16)..]) }
}

#[cfg(target_arch = "aarch64")]
#[cfg_attr(target_feature = "neon", inline(always))]
#[cfg_attr(not(target_feature = "neon"), inline, target_feature(enable = "neon"))]
unsafe fn check_mixed_neon_short(src: &[u8]) -> bool {
    debug_assert!(src.len() < 64);
    let len = src.len();
    if len < 16 {
        return hex_check_fallback_with_case(src, CheckCase::None);
    }
    // SAFETY: `16 <= len < 64`, so each bounded 16-byte load stays in `src` and NEON is active.
    unsafe {
        let a = valid_neon_mixed(vld1q_u8(src.as_ptr()));
        if len == 16 {
            return vminvq_u8(a) != 0;
        }
        let b = valid_neon_mixed(vld1q_u8(src.as_ptr().add(len - 16)));
        let valid = if len <= 32 {
            vandq_u8(a, b)
        } else {
            // `32 < len < 64`, so offsets `16` and (when `len > 48`) `len - 32` fit.
            let c = valid_neon_mixed(vld1q_u8(src.as_ptr().add(16)));
            let valid = vandq_u8(vandq_u8(a, b), c);
            if len <= 48 {
                valid
            } else {
                let d = valid_neon_mixed(vld1q_u8(src.as_ptr().add(len - 32)));
                vandq_u8(valid, d)
            }
        };
        vminvq_u8(valid) != 0
    }
}

#[cfg(all(any(test, fuzzing), any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) unsafe fn fuzz_check_mixed_sse(src: &[u8]) -> bool {
    // SAFETY: Caller guarantees SSE2 support.
    unsafe { check_mixed_sse::<16>(src) }
}

#[cfg(all(any(test, fuzzing), any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) unsafe fn fuzz_check_mixed_avx2(src: &[u8]) -> bool {
    // SAFETY: Caller guarantees AVX2 support.
    unsafe { check_mixed_avx2::<32>(src) }
}

#[cfg(all(any(test, fuzzing), any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) unsafe fn fuzz_check_mixed_avx512(src: &[u8]) -> bool {
    // SAFETY: Caller guarantees AVX-512F and AVX-512BW support.
    unsafe { check_mixed_avx512::<64>(src) }
}

#[cfg(all(any(test, fuzzing), target_arch = "aarch64"))]
pub(crate) unsafe fn fuzz_check_mixed_neon(src: &[u8]) -> bool {
    // SAFETY: Caller guarantees NEON support.
    unsafe { check_mixed_neon(src) }
}
