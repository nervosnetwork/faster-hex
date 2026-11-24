//! Spare-capacity decoding for [`crate::hex_decode_append`].
//!
//! Writes decoded bytes directly into uninitialized destination capacity without
//! zero-filling first, returning the starting input offset of the first failing
//! block on error so diagnostics skip already-validated prefixes.

use core::mem::MaybeUninit;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::error::Error;

#[cfg(target_arch = "aarch64")]
use super::{aarch64, CheckCase};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::{x86, CheckCase};
use super::{NIL, UNHEX};

// Decodes `src` into `dst` (where `src.len() == dst.len() * 2`).
// Returns `Ok(())` only after initializing every element of `dst`.
// On `Err(from)`, `from` is even, `from <= src.len()`, `src[..from]` is valid,
// and `dst[..from / 2]` is already initialized.
#[inline]
pub(super) fn decode_uninit(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<(), usize> {
    debug_assert_eq!(dst.len().checked_mul(2), Some(src.len()));
    if dst.len() < 8 {
        return decode_scalar_uninit(src, dst);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        match crate::vectorization_support() {
            crate::Vectorization::AVX512 => {
                // SAFETY: Dispatch verified AVX-512BW and OS state; `src.len() == dst.len() * 2 >= 16`.
                unsafe { decode_avx512_uninit(src, dst) }
            }
            crate::Vectorization::AVX2 => {
                // SAFETY: Dispatch verified AVX2 and OS state; `src.len() == dst.len() * 2 >= 16`.
                unsafe { decode_avx2_uninit(src, dst) }
            }
            crate::Vectorization::SSE41 => {
                // SAFETY: Dispatch verified SSE4.1; `src.len() == dst.len() * 2 >= 16`.
                unsafe { decode_sse41_uninit::<64>(src, dst) }
            }
            crate::Vectorization::None => decode_scalar_uninit(src, dst),
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if crate::vectorization_support() == crate::Vectorization::Neon {
            if dst.len() <= 16 {
                // SAFETY: NEON is available and `16 <= src.len() <= 32` with exact 2:1 ratio.
                unsafe { decode_short_neon_uninit(src, dst) }
            } else if dst.len() <= 32 {
                // SAFETY: NEON is available and `34 <= src.len() <= 64` with exact 2:1 ratio.
                unsafe { decode_bounded_neon_uninit(src, dst) }
            } else {
                // SAFETY: NEON is available and `src.len() > 64` with exact 2:1 ratio.
                unsafe { decode_large_neon_uninit(src, dst) }
            }
        } else {
            decode_scalar_uninit(src, dst)
        }
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        decode_scalar_uninit(src, dst)
    }
}

#[inline]
fn decode_scalar_uninit(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<(), usize> {
    for (slot, pair) in dst.iter_mut().zip(src.as_chunks::<2>().0) {
        let high = UNHEX[usize::from(pair[0])];
        let low = UNHEX[usize::from(pair[1])];
        if high | low == NIL {
            return Err(pair.as_ptr() as usize - src.as_ptr() as usize);
        }
        slot.write(high << 4 | low);
    }
    Ok(())
}

// Shifts `UNHEX` instead of referencing `UNHEX4` so 2.0's internal `UNHEX4`
// table stays a local symbol in the rlib and does not shift AArch64 `.text`.
#[inline]
fn decode_fallback_uninit(src: &[u8], dst: &mut [MaybeUninit<u8>]) {
    for (slot, pair) in dst.iter_mut().zip(src.as_chunks::<2>().0) {
        slot.write((UNHEX[usize::from(pair[0])] << 4) | UNHEX[usize::from(pair[1])]);
    }
}

// Macro rather than closure so each caller retains its `#[target_feature]`
// attributes and inlines the block kernel directly into the SIMD loop.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! decode_blocks_uninit {
    ($src:expr, $dst:expr, $src_block:literal, $dst_block:literal, $decode:path) => {{
        let (blocks, tail) = $src.as_chunks::<$src_block>();
        let (outputs, _) = $dst.as_chunks_mut::<$dst_block>();
        for (input, output) in blocks.iter().zip(outputs) {
            if $decode(input, output).is_err() {
                return Err(input.as_ptr() as usize - $src.as_ptr() as usize);
            }
        }
        if !tail.is_empty() {
            let Some(input) = $src.last_chunk::<$src_block>() else {
                return Err(blocks.len() * $src_block);
            };
            let Some(output) = $dst.last_chunk_mut::<$dst_block>() else {
                return Err(blocks.len() * $src_block);
            };
            if $decode(input, output).is_err() {
                return Err(blocks.len() * $src_block);
            }
        }
        Ok(())
    }};
}

// Locates the first invalid byte starting from `from`, where `src[..from]` has
// already been validated and `dst[..from / 2]` has already been initialized.
// Generic on chunk width so 2.0-only callers never pull this into rlib CGUs,
// while `#[inline(never)]` keeps error diagnostics out of caller hot loops.
#[cold]
#[inline(never)]
pub(super) fn diagnose_append_error<const CHUNK: usize>(
    src: &[u8],
    dst: &mut [MaybeUninit<u8>],
    from: usize,
) -> Result<(), Error> {
    let rest = &src[from..];
    // Report a malformed first pair of the failing region before wider scans.
    for (offset, &byte) in rest.iter().take(2).enumerate() {
        if UNHEX[usize::from(byte)] == NIL {
            return Err(Error::InvalidChar {
                index: from + offset,
                byte,
            });
        }
    }
    // Skip valid chunks when a wider block (e.g. 128-byte AVX-512) failed.
    let skipped = if rest.len() > CHUNK {
        rest.chunks_exact(CHUNK)
            .take_while(|chunk| crate::hex_check(chunk))
            .count()
            * CHUNK
    } else {
        0
    };
    // Four independent lookups skip valid digits before the exact byte scan.
    // A rejected digit sets all bits (0xff); valid entries use only the low nibble.
    let groups = rest[skipped..].as_chunks::<4>().0;
    let valid_groups = groups
        .iter()
        .take_while(|group| {
            group
                .iter()
                .fold(0, |bits, &byte| bits | UNHEX[usize::from(byte)])
                != NIL
        })
        .count();
    let start = skipped + 4 * valid_groups;
    for (offset, &byte) in rest[start..].iter().enumerate() {
        if UNHEX[usize::from(byte)] == NIL {
            return Err(Error::InvalidChar {
                index: from + start + offset,
                byte,
            });
        }
    }
    // Defensive recovery: if every remaining byte is valid, finish initializing `dst`.
    decode_fallback_uninit(rest, &mut dst[from / 2..]);
    Ok(())
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon")]
unsafe fn decode_short_neon_uninit(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<(), usize> {
    debug_assert!((16..=32).contains(&src.len()) && dst.len() * 2 == src.len());
    let pack = |a, b| vsliq_n_u8::<4>(vuzp2q_u8(a, b), vuzp1q_u8(a, b));
    let a = aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr()), CheckCase::None);
    if src.len() == 16 {
        if vmaxvq_u8(a) > 15 {
            return Err(0);
        }
        vst1_u8(dst.as_mut_ptr().cast(), vget_low_u8(pack(a, a)));
        return Ok(());
    }
    let b =
        aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr().add(src.len() - 16)), CheckCase::None);
    if vmaxvq_u8(vorrq_u8(a, b)) > 15 {
        return Err(0);
    }
    let decoded = pack(a, b);
    vst1_u8(dst.as_mut_ptr().cast(), vget_low_u8(decoded));
    vst1_u8(
        dst.as_mut_ptr().add(dst.len() - 8).cast(),
        vget_high_u8(decoded),
    );
    Ok(())
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon")]
unsafe fn decode_bounded_neon_uninit(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<(), usize> {
    debug_assert!((34..=64).contains(&src.len()) && dst.len() * 2 == src.len());
    let a = aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr()), CheckCase::None);
    let b = aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr().add(16)), CheckCase::None);
    let c =
        aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr().add(src.len() - 32)), CheckCase::None);
    let d =
        aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr().add(src.len() - 16)), CheckCase::None);
    if vmaxvq_u8(vorrq_u8(vorrq_u8(a, b), vorrq_u8(c, d))) > 15 {
        return Err(0);
    }
    let pack = |hi, lo| vsliq_n_u8::<4>(vuzp2q_u8(hi, lo), vuzp1q_u8(hi, lo));
    vst1q_u8(dst.as_mut_ptr().cast(), pack(a, b));
    vst1q_u8(dst.as_mut_ptr().add(dst.len() - 16).cast(), pack(c, d));
    Ok(())
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon")]
unsafe fn decode_neon_64_uninit(src: &[u8; 64], dst: &mut [MaybeUninit<u8>; 32]) -> Result<(), ()> {
    let a = aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr()), CheckCase::None);
    let b = aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr().add(16)), CheckCase::None);
    let c = aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr().add(32)), CheckCase::None);
    let d = aarch64::decode_neon_nibbles(vld1q_u8(src.as_ptr().add(48)), CheckCase::None);
    if vmaxvq_u8(vorrq_u8(vorrq_u8(a, b), vorrq_u8(c, d))) > 15 {
        return Err(());
    }
    let pack = |hi, lo| vsliq_n_u8::<4>(vuzp2q_u8(hi, lo), vuzp1q_u8(hi, lo));
    vst1q_u8(dst.as_mut_ptr().cast(), pack(a, b));
    vst1q_u8(dst.as_mut_ptr().add(16).cast(), pack(c, d));
    Ok(())
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "neon")]
unsafe fn decode_large_neon_uninit(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<(), usize> {
    debug_assert!(src.len() > 64 && dst.len() * 2 == src.len());
    decode_blocks_uninit!(src, dst, 64, 32, decode_neon_64_uninit)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "sse4.1")]
unsafe fn decode_short_sse41_uninit(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<(), usize> {
    debug_assert!((16..=32).contains(&src.len()) && dst.len() * 2 == src.len());
    let a = x86::decode_sse41_nibbles(_mm_loadu_si128(src.as_ptr().cast()), CheckCase::None);
    if src.len() == 16 {
        if _mm_testz_si128(a, _mm_set1_epi8(-16)) == 0 {
            return Err(0);
        }
        _mm_storel_epi64(dst.as_mut_ptr().cast(), x86::pack_sse41(a, a));
        return Ok(());
    }
    let b = x86::decode_sse41_nibbles(
        _mm_loadu_si128(src.as_ptr().add(src.len() - 16).cast()),
        CheckCase::None,
    );
    if _mm_testz_si128(_mm_or_si128(a, b), _mm_set1_epi8(-16)) == 0 {
        return Err(0);
    }
    let decoded = x86::pack_sse41(a, b);
    _mm_storel_epi64(dst.as_mut_ptr().cast(), decoded);
    _mm_storel_epi64(
        dst.as_mut_ptr().add(dst.len() - 8).cast(),
        _mm_srli_si128::<8>(decoded),
    );
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "sse4.1")]
unsafe fn decode_sse41_64_uninit(
    src: &[u8; 64],
    dst: &mut [MaybeUninit<u8>; 32],
) -> Result<(), ()> {
    let a = x86::decode_sse41_nibbles(_mm_loadu_si128(src.as_ptr().cast()), CheckCase::None);
    let b = x86::decode_sse41_nibbles(
        _mm_loadu_si128(src.as_ptr().add(16).cast()),
        CheckCase::None,
    );
    let c = x86::decode_sse41_nibbles(
        _mm_loadu_si128(src.as_ptr().add(32).cast()),
        CheckCase::None,
    );
    let d = x86::decode_sse41_nibbles(
        _mm_loadu_si128(src.as_ptr().add(48).cast()),
        CheckCase::None,
    );
    let combined = _mm_or_si128(_mm_or_si128(a, b), _mm_or_si128(c, d));
    if _mm_testz_si128(combined, _mm_set1_epi8(-16)) == 0 {
        return Err(());
    }
    _mm_storeu_si128(dst.as_mut_ptr().cast(), x86::pack_sse41(a, b));
    _mm_storeu_si128(dst.as_mut_ptr().add(16).cast(), x86::pack_sse41(c, d));
    Ok(())
}

// Generic on block width so crates that never call `hex_decode_append` do not
// materialize this function in `faster-hex`'s rlib CGUs, while targets with
// static SSE4.1 (such as x86_64 macOS) still keep it out of AVX2 hot loops.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(never)]
#[target_feature(enable = "sse4.1")]
unsafe fn decode_sse41_uninit<const BLOCK: usize>(
    src: &[u8],
    dst: &mut [MaybeUninit<u8>],
) -> Result<(), usize> {
    debug_assert!(BLOCK == 64 && src.len() >= 16 && dst.len() * 2 == src.len());
    if src.len() <= 32 {
        return decode_short_sse41_uninit(src, dst);
    }
    if src.len() < 64 {
        let a = x86::decode_sse41_nibbles(_mm_loadu_si128(src.as_ptr().cast()), CheckCase::None);
        let b = x86::decode_sse41_nibbles(
            _mm_loadu_si128(src.as_ptr().add(16).cast()),
            CheckCase::None,
        );
        let c = x86::decode_sse41_nibbles(
            _mm_loadu_si128(src.as_ptr().add(src.len() - 32).cast()),
            CheckCase::None,
        );
        let d = x86::decode_sse41_nibbles(
            _mm_loadu_si128(src.as_ptr().add(src.len() - 16).cast()),
            CheckCase::None,
        );
        let combined = _mm_or_si128(_mm_or_si128(a, b), _mm_or_si128(c, d));
        if _mm_testz_si128(combined, _mm_set1_epi8(-16)) == 0 {
            return Err(0);
        }
        _mm_storeu_si128(dst.as_mut_ptr().cast(), x86::pack_sse41(a, b));
        _mm_storeu_si128(
            dst.as_mut_ptr().add(dst.len() - 16).cast(),
            x86::pack_sse41(c, d),
        );
        return Ok(());
    }
    decode_blocks_uninit!(src, dst, 64, 32, decode_sse41_64_uninit)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn decode_avx2_64_uninit(src: &[u8; 64], dst: &mut [MaybeUninit<u8>; 32]) -> Result<(), ()> {
    let (a, a_checked) =
        x86::decode_avx2_nibbles(_mm256_loadu_si256(src.as_ptr().cast()), CheckCase::None);
    let (b, b_checked) = x86::decode_avx2_nibbles(
        _mm256_loadu_si256(src.as_ptr().add(32).cast()),
        CheckCase::None,
    );
    if _mm256_movemask_epi8(_mm256_or_si256(a_checked, b_checked)) != 0 {
        return Err(());
    }
    _mm256_storeu_si256(dst.as_mut_ptr().cast(), x86::pack_avx2(a, b));
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn decode_avx2_uninit(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<(), usize> {
    debug_assert!(src.len() >= 16 && dst.len() * 2 == src.len());
    if src.len() == 64 {
        let (Some(input), Some(output)) = (src.first_chunk::<64>(), dst.first_chunk_mut::<32>())
        else {
            return Err(0);
        };
        return decode_avx2_64_uninit(input, output).map_err(|()| 0);
    }
    if src.len() > 64 {
        return decode_blocks_uninit!(src, dst, 64, 32, decode_avx2_64_uninit);
    }
    if src.len() == 32 {
        let (nibbles, checked) =
            x86::decode_avx2_nibbles(_mm256_loadu_si256(src.as_ptr().cast()), CheckCase::None);
        if _mm256_movemask_epi8(checked) != 0 {
            return Err(0);
        }
        _mm_storeu_si128(
            dst.as_mut_ptr().cast(),
            _mm256_castsi256_si128(x86::pack_avx2(nibbles, nibbles)),
        );
        return Ok(());
    }
    if src.len() < 32 {
        return decode_short_sse41_uninit(src, dst);
    }
    let (a, a_checked) =
        x86::decode_avx2_nibbles(_mm256_loadu_si256(src.as_ptr().cast()), CheckCase::None);
    let (b, b_checked) = x86::decode_avx2_nibbles(
        _mm256_loadu_si256(src.as_ptr().add(src.len() - 32).cast()),
        CheckCase::None,
    );
    if _mm256_movemask_epi8(_mm256_or_si256(a_checked, b_checked)) != 0 {
        return Err(0);
    }
    let packed = x86::pack_avx2(a, b);
    _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm256_castsi256_si128(packed));
    _mm_storeu_si128(
        dst.as_mut_ptr().add(dst.len() - 16).cast(),
        _mm256_extracti128_si256::<1>(packed),
    );
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn decode_avx512_128_uninit(
    src: &[u8; 128],
    dst: &mut [MaybeUninit<u8>; 64],
) -> Result<(), ()> {
    let (a, a_checked) =
        x86::decode_avx512_nibbles(_mm512_loadu_si512(src.as_ptr().cast()), CheckCase::None);
    let (b, b_checked) = x86::decode_avx512_nibbles(
        _mm512_loadu_si512(src.as_ptr().add(64).cast()),
        CheckCase::None,
    );
    if _mm512_movepi8_mask(_mm512_or_si512(a_checked, b_checked)) != 0 {
        return Err(());
    }
    _mm256_storeu_si256(dst.as_mut_ptr().cast(), x86::pack_avx512(a));
    _mm256_storeu_si256(dst.as_mut_ptr().add(32).cast(), x86::pack_avx512(b));
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn decode_avx512_uninit(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<(), usize> {
    debug_assert!(src.len() >= 16 && dst.len() * 2 == src.len());
    if src.len() >= 128 {
        return decode_blocks_uninit!(src, dst, 128, 64, decode_avx512_128_uninit);
    }
    if src.len() == 64 {
        let (nibbles, checked) =
            x86::decode_avx512_nibbles(_mm512_loadu_si512(src.as_ptr().cast()), CheckCase::None);
        if _mm512_movepi8_mask(checked) != 0 {
            return Err(0);
        }
        _mm256_storeu_si256(dst.as_mut_ptr().cast(), x86::pack_avx512(nibbles));
        return Ok(());
    }
    if src.len() < 64 {
        return decode_avx2_uninit(src, dst);
    }
    let (a, a_checked) =
        x86::decode_avx512_nibbles(_mm512_loadu_si512(src.as_ptr().cast()), CheckCase::None);
    let (b, b_checked) = x86::decode_avx512_nibbles(
        _mm512_loadu_si512(src.as_ptr().add(src.len() - 64).cast()),
        CheckCase::None,
    );
    if _mm512_movepi8_mask(_mm512_or_si512(a_checked, b_checked)) != 0 {
        return Err(0);
    }
    _mm256_storeu_si256(dst.as_mut_ptr().cast(), x86::pack_avx512(a));
    _mm256_storeu_si256(
        dst.as_mut_ptr().add(dst.len() - 32).cast(),
        x86::pack_avx512(b),
    );
    Ok(())
}

#[cfg(any(test, fuzzing))]
pub(crate) fn fuzz_decode_scalar_uninit(
    src: &[u8],
    dst: &mut [MaybeUninit<u8>],
) -> Result<(), usize> {
    decode_scalar_uninit(src, dst)
}

#[cfg(all(any(test, fuzzing), any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) unsafe fn fuzz_decode_sse41_uninit(
    src: &[u8],
    dst: &mut [MaybeUninit<u8>],
) -> Result<(), usize> {
    if dst.len() < 8 {
        return decode_scalar_uninit(src, dst);
    }
    decode_sse41_uninit::<64>(src, dst)
}

#[cfg(all(any(test, fuzzing), any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) unsafe fn fuzz_decode_avx2_uninit(
    src: &[u8],
    dst: &mut [MaybeUninit<u8>],
) -> Result<(), usize> {
    if dst.len() < 8 {
        return decode_scalar_uninit(src, dst);
    }
    decode_avx2_uninit(src, dst)
}

#[cfg(all(any(test, fuzzing), any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) unsafe fn fuzz_decode_avx512_uninit(
    src: &[u8],
    dst: &mut [MaybeUninit<u8>],
) -> Result<(), usize> {
    if dst.len() < 8 {
        return decode_scalar_uninit(src, dst);
    }
    decode_avx512_uninit(src, dst)
}

#[cfg(all(any(test, fuzzing), target_arch = "aarch64"))]
pub(crate) unsafe fn fuzz_decode_neon_uninit(
    src: &[u8],
    dst: &mut [MaybeUninit<u8>],
) -> Result<(), usize> {
    if dst.len() < 8 {
        return decode_scalar_uninit(src, dst);
    }
    if dst.len() <= 16 {
        decode_short_neon_uninit(src, dst)
    } else if dst.len() <= 32 {
        decode_bounded_neon_uninit(src, dst)
    } else {
        decode_large_neon_uninit(src, dst)
    }
}
