"""Bounded encoder dispatch alternatives; experimental branch only."""

def encoder_variant(work, family):
    path = work / "src/encode.rs"
    text = path.read_text()
    start = text.index("            crate::Vectorization::AVX512 if src.len() >= 64")
    end = text.index("            crate::Vectorization::SSE41", start)
    if family:
        arm = """            kind @ (crate::Vectorization::AVX2 | crate::Vectorization::AVX512) => {
                // SAFETY: Dispatch checked AVX2 and the selected AVX-512 OS state.
                unsafe { hex_encode_avx(src, dst, upper_case, kind) }
            }
"""
    else:
        arm = """            crate::Vectorization::AVX2 | crate::Vectorization::AVX512 => {
                // SAFETY: Dispatch checked AVX2 and the OS register state.
                unsafe { hex_encode_avx2(src, dst, upper_case) }
            }
"""
    text = text[:start] + arm + text[end:]
    start = text.index('#[target_feature(enable = "avx512f,avx512bw")]')
    if family:
        helper = """// Keep the public encoder dispatch small enough to inline in caller loops.
#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn hex_encode_avx(
    src: &[u8],
    dst: &mut [MaybeUninit<u8>],
    upper: bool,
    kind: crate::Vectorization,
) {
    if kind == crate::Vectorization::AVX512 && src.len() >= 64 {
        hex_encode_avx512(src, dst, upper);
    } else {
        hex_encode_avx2(src, dst, upper);
    }
}

"""
        text = text[:start] + helper + text[start:]
    else:
        end = text.index('#[target_feature(enable = "avx2")]', start)
        text = text[:start] + text[end:]
        for name in ["src/tests.rs", "src/fuzzing.rs"]:
            other = work / name
            other.write_text(other.read_text().replace("encode::hex_encode_avx512", "encode::hex_encode_avx2"))
    path.write_text(text)
