//! Safe adapters to the real kernels, compiled only with `--cfg fuzzing`.
//!
//! Keep input generation and assertions in fuzz/core.rs. This module only checks
//! memory/CPU preconditions; character validation belongs to the checked kernel.

use crate::{decode, encode, CheckCase};

#[derive(Clone, Copy)]
enum Kind {
    Scalar,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Sse41,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Avx2,
    #[cfg(target_arch = "aarch64")]
    Neon,
}

// A caller cannot construct an adapter for an unsupported instruction set.
#[derive(Clone, Copy)]
pub struct Backend(Kind);

pub fn backends() -> impl Iterator<Item = Backend> {
    IntoIterator::into_iter([
        Some(Backend(Kind::Scalar)),
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        matches!(
            crate::vectorization_support(),
            crate::Vectorization::SSE41 | crate::Vectorization::AVX2
        )
        .then_some(Backend(Kind::Sse41)),
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        (crate::vectorization_support() == crate::Vectorization::AVX2)
            .then_some(Backend(Kind::Avx2)),
        #[cfg(target_arch = "aarch64")]
        (crate::vectorization_support() == crate::Vectorization::Neon)
            .then_some(Backend(Kind::Neon)),
    ])
    .flatten()
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self.0 {
            Kind::Scalar => "scalar",
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Kind::Sse41 => "sse41",
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Kind::Avx2 => "avx2",
            #[cfg(target_arch = "aarch64")]
            Kind::Neon => "neon",
        }
    }

    pub fn encode(self, src: &[u8], dst: &mut [u8], upper: bool) {
        assert_eq!(src.len().checked_mul(2), Some(dst.len()));
        // SAFETY: backends() checked the ISA, and the assertion establishes the
        // exact 1:2 ratio. The kernels only write initialized ASCII, so casting
        // the destination to MaybeUninit never invalidates initialized storage.
        unsafe {
            let dst = core::slice::from_raw_parts_mut(dst.as_mut_ptr().cast(), dst.len());
            match self.0 {
                Kind::Scalar => encode::hex_encode_custom_case_fallback(src, dst, upper),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                Kind::Sse41 => encode::hex_encode_sse41(src, dst, upper),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                Kind::Avx2 => encode::hex_encode_avx2(src, dst, upper),
                #[cfg(target_arch = "aarch64")]
                Kind::Neon => encode::hex_encode_neon(src, dst, upper),
            }
        }
    }

    pub fn check(self, src: &[u8], case: CheckCase) -> bool {
        #[allow(unused_unsafe)] // Non-SIMD targets only compile the safe fallback.
        // SAFETY: backends() checked the ISA. Each checker bounds its own loads
        // and accepts arbitrary source bytes and lengths, including odd lengths.
        unsafe {
            match self.0 {
                Kind::Scalar => decode::hex_check_fallback_with_case(src, case),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                Kind::Sse41 => decode::hex_check_sse_with_case(src, case),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                Kind::Avx2 => decode::hex_check_avx2_with_case(src, case),
                #[cfg(target_arch = "aarch64")]
                Kind::Neon => decode::hex_check_neon_with_case(src, case),
            }
        }
    }

    pub fn decode(self, src: &[u8], dst: &mut [u8], case: CheckCase) -> bool {
        assert_eq!(dst.len().checked_mul(2), Some(src.len()));
        #[allow(unused_unsafe)] // The NEON dispatcher and scalar path are safe.
        // SAFETY: backends() checked the ISA and the assertion guarantees even
        // input and the exact 2:1 ratio. The checked kernels accept invalid text
        // and must reject it before writing; do not pre-check characters here.
        unsafe {
            match self.0 {
                Kind::Scalar => {
                    if !decode::hex_check_fallback_with_case(src, case) {
                        return false;
                    }
                    decode::hex_decode_fallback(src, dst);
                    true
                }
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                Kind::Sse41 => decode::hex_decode_sse41_checked(src, dst, case).is_ok(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                Kind::Avx2 => decode::hex_decode_avx2_checked(src, dst, case).is_ok(),
                // Use the actual short/bounded/general NEON selection so the
                // harness cannot drift from the production length thresholds.
                #[cfg(target_arch = "aarch64")]
                Kind::Neon => decode::decode_checked(src, dst, case).is_ok(),
            }
        }
    }
}
