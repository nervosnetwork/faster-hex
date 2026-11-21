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
    let proc_info_ecx = leaf1_ecx();
    let have_sse4 = (proc_info_ecx >> 19) & 1 == 1;
    // Every accelerated x86 backend requires SSE4.1.
    if !have_sse4 {
        return Vectorization::None;
    }

    let have_xsave = (proc_info_ecx >> 26) & 1 == 1;
    let have_osxsave = (proc_info_ecx >> 27) & 1 == 1;
    let have_avx = (proc_info_ecx >> 28) & 1 == 1;
    if max_leaf >= 7 && have_xsave && have_osxsave && have_avx {
        return avx();
    }
    Vectorization::SSE41
}

#[inline(always)]
pub(super) fn extended(xcr0: u64, leaf7_ebx: impl FnOnce() -> u32) -> Vectorization {
    let os_avx_support = xcr0 & 6 == 6;
    if os_avx_support {
        let extended_features_ebx = leaf7_ebx();
        let have_avx2 = (extended_features_ebx >> 5) & 1 == 1;
        if have_avx2 {
            // AVX-512 needs opmask and both ZMM state components in addition
            // to SSE/AVX state. CPUID alone is insufficient for safe dispatch.
            let avx512 = (1 << 16) | (1 << 30); // AVX-512F and AVX-512BW.
            if xcr0 & 0xe6 == 0xe6 && extended_features_ebx & avx512 == avx512 {
                return Vectorization::AVX512;
            }
            return Vectorization::AVX2;
        }
    }
    Vectorization::SSE41
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
