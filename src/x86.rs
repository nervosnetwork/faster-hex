use crate::Vectorization;

// Later probes run only when the CPU and OS support them.
#[inline(always)]
pub(super) fn basic(
    max_leaf: u32,
    leaf1_ecx: impl FnOnce() -> u32,
    avx: impl FnOnce() -> Vectorization,
) -> Vectorization {
    if max_leaf < 1 {
        return Vectorization::None;
    }
    let features = leaf1_ecx();
    if features & (1 << 19) == 0 {
        return Vectorization::None;
    }
    const XSAVE_OSXSAVE_AVX: u32 = (1 << 26) | (1 << 27) | (1 << 28);
    if max_leaf < 7 || features & XSAVE_OSXSAVE_AVX != XSAVE_OSXSAVE_AVX {
        return Vectorization::SSE41;
    }
    avx()
}

#[inline(always)]
pub(super) fn extended(state: u64, leaf7_ebx: impl FnOnce() -> u32) -> Vectorization {
    if state & 0x06 != 0x06 {
        return Vectorization::SSE41;
    }
    let extended = leaf7_ebx();
    if extended & (1 << 5) == 0 {
        return Vectorization::SSE41;
    }
    // AVX-512 also requires opmask and both ZMM state components.
    const AVX512F_BW: u32 = (1 << 16) | (1 << 30);
    if state & 0xe0 == 0xe0 && extended & AVX512F_BW == AVX512F_BW {
        Vectorization::AVX512
    } else {
        Vectorization::AVX2
    }
}

#[cfg(test)]
mod tests {
    use super::{basic, extended, Vectorization, Vectorization::*};

    fn select_backend(
        max_leaf: u32,
        leaf1: impl FnOnce() -> u32,
        xcr0: impl FnOnce() -> u64,
        leaf7: impl FnOnce() -> u32,
    ) -> Vectorization {
        basic(max_leaf, leaf1, || extended(xcr0(), leaf7))
    }

    #[test]
    fn missing_cpu_or_os_support_forces_a_fallback() {
        let ecx = (1 << 19) | (1 << 26) | (1 << 27) | (1 << 28);
        let ebx = (1 << 5) | (1 << 16) | (1 << 30);
        let no_leaf = || panic!("queried an unavailable CPUID leaf");
        let no_xcr0 = || panic!("read XCR0 without OS support");

        assert_eq!(select_backend(0, no_leaf, no_xcr0, no_leaf), None);
        assert_eq!(
            select_backend(7, || ecx & !(1 << 19), no_xcr0, no_leaf),
            None
        );
        assert_eq!(select_backend(6, || ecx, no_xcr0, no_leaf), SSE41);
        for bit in [26, 27, 28] {
            assert_eq!(
                select_backend(7, || ecx & !(1 << bit), no_xcr0, no_leaf),
                SSE41
            );
        }
        for bit in [1, 2] {
            assert_eq!(
                select_backend(7, || ecx, || 0xe6 & !(1 << bit), no_leaf),
                SSE41
            );
        }
        let select = |state, features| select_backend(7, || ecx, || state, || features);
        assert_eq!(select(0xe6, ebx & !(1 << 5)), SSE41);
        assert_eq!(select(0x06, ebx), AVX2);
        for bit in [5, 6, 7] {
            assert_eq!(select(0xe6 & !(1 << bit), ebx), AVX2);
        }
        for bit in [16, 30] {
            assert_eq!(select(0xe6, ebx & !(1 << bit)), AVX2);
        }
        assert_eq!(select(0xe6, ebx), AVX512);
    }
}
