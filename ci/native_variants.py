"""Source transformations for isolated native experiments, not public features."""


def short_decode(work):
    path = work / "src/decode.rs"
    text = path.read_text()
    begin = text.index('pub(crate) fn decode_checked(')
    end = text.index('    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]', begin)
    block = text[begin:end].replace('#[cfg(target_arch = "aarch64")]',
        '#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]')
    path.write_text(text[:begin] + block + text[end:])


def inline_case(work, sse=False, avx512=False):
    path = work / "src/decode.rs"
    text = path.read_text()
    functions = ["hex_decode_avx2_checked", "hex_check_avx2_with_case"]
    if sse:
        functions += ["hex_decode_sse41_checked", "hex_check_sse_with_case"]
    if avx512:
        functions += ["hex_decode_avx512_checked", "hex_check_avx512_with_case"]
    for name in functions:
        before = "pub(crate) unsafe fn " + name
        assert text.count(before) == 1
        text = text.replace(before, "#[inline]\n" + before)
    path.write_text(text)


def group_avx_decode(work):
    path = work / "src/decode.rs"
    text = path.read_text()
    for start_name, call in [('pub fn hex_check_with_case(', 'hex_check_avx_family(src, check_case, kind)'),
                             ('pub(crate) fn decode_checked(', 'hex_decode_avx_family(src, dst, check_case, kind)')]:
        start = text.index('            crate::Vectorization::AVX512 => {', text.index(start_name))
        end = text.index('            crate::Vectorization::SSE41', start)
        text = text[:start] + '''            kind @ (crate::Vectorization::AVX512 | crate::Vectorization::AVX2) => {
                // SAFETY: The selected AVX family and its OS state were checked.
                unsafe { ''' + call + ''' }
            }
''' + text[end:]
    text += '''
#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn hex_check_avx_family(src: &[u8], case: CheckCase, kind: crate::Vectorization) -> bool {
    if kind == crate::Vectorization::AVX512 { hex_check_avx512_with_case(src, case) }
    else { hex_check_avx2_with_case(src, case) }
}

#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn hex_decode_avx_family(src: &[u8], dst: &mut [u8], case: CheckCase, kind: crate::Vectorization) -> Result<(), ()> {
    if kind == crate::Vectorization::AVX512 { hex_decode_avx512_checked(src, dst, case) }
    else { hex_decode_avx2_checked(src, dst, case) }
}
'''
    path.write_text(text)


def paired_check(work):
    path = work / "src/decode.rs"
    text = path.read_text()
    begin = text.index("pub(crate) unsafe fn hex_check_avx2_with_case(")
    end = text.index("// Wrapping subtraction", begin)
    block = text[begin:end]
    before = "    let (blocks, tail) = src.as_chunks::<32>();"
    assert block.count(before) == 1
    block = block.replace(before, '''    let (batches, rest) = src.as_chunks::<64>();
    for batch in batches {
        let a = valid_avx2(_mm256_loadu_si256(batch.as_ptr().cast()), case);
        let b = valid_avx2(_mm256_loadu_si256(batch.as_ptr().add(32).cast()), case);
        if _mm256_movemask_epi8(_mm256_and_si256(a, b)) != -1 {
            return false;
        }
    }
    let (blocks, tail) = rest.as_chunks::<32>();''')
    path.write_text(text[:begin] + block + text[end:])


def outline_long_decode(work):
    path = work / "src/decode.rs"
    text = path.read_text()
    start = text.index('pub(crate) unsafe fn hex_decode_avx2_checked(')
    end = text.index('\n#[inline]', start)
    block = text[start:end]
    previous = '''        if !hex_check_avx2_with_case(src, case) {
            return Err(());
        }
        hex_decode_avx2(src, dst);'''
    assert block.count(previous) == 1
    block = block.replace(previous, '        return hex_decode_avx2_long_checked(src, dst, case);')
    helper = '''
// Keep complete-buffer validation out of the register-only Hash256 fast path.
#[inline(never)]
#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn hex_decode_avx2_long_checked(src: &[u8], dst: &mut [u8], case: CheckCase) -> Result<(), ()> {
    if !hex_check_avx2_with_case(src, case) {
        return Err(());
    }
    hex_decode_avx2(src, dst);
    Ok(())
}
'''
    path.write_text(text[:start] + block + helper + text[end:])


def short_x86(work):
    path = work / "src/encode.rs"
    text = path.read_text()
    begin = text.index('    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]\n    {')
    end = text.index('    #[cfg(target_arch = "aarch64")]', begin)
    block = text[begin:end]
    block = block.replace('        match crate::vectorization_support() {',
                          '        if src.len() < 8 {\n            hex_encode_pairs(src, dst, upper_case);\n        } else {\n        match crate::vectorization_support() {')
    block = block[:-6] + '        }\n    }\n'
    text = text[:begin] + block + text[end:]
    begin = text.index('pub(crate) unsafe fn hex_encode_sse41(')
    end = text.index('\n#[inline]', begin)
    block = text[begin:end].replace('if src.len() < 16', 'if src.len() < 8', 1)
    position = block.index('    let (blocks, tail)')
    block = block[:position] + '''    if src.len() < 16 {
        if let (Some(input), Some(output)) = (src.first_chunk::<8>(), dst.first_chunk_mut::<16>()) {
            encode_sse41_8(input, output, table);
        }
        if src.len() > 8 {
            if let (Some(input), Some(output)) = (src.last_chunk::<8>(), dst.last_chunk_mut::<16>()) {
                encode_sse41_8(input, output, table);
            }
        }
        return;
    }
''' + block[position:]
    helper = '''
#[inline]
#[target_feature(enable = "sse4.1")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn encode_sse41_8(src: &[u8; 8], dst: &mut [MaybeUninit<u8>; 16], table: __m128i) {
    let bytes = _mm_loadl_epi64(src.as_ptr().cast());
    let mask = _mm_set1_epi8(15);
    let high = _mm_shuffle_epi8(table, _mm_and_si128(_mm_srli_epi16::<4>(bytes), mask));
    let low = _mm_shuffle_epi8(table, _mm_and_si128(bytes, mask));
    _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm_unpacklo_epi8(high, low));
}
'''
    text = text[:begin] + block + helper + text[end:]
    path.write_text(text)
    path = work / "src/decode.rs"
    text = path.read_text()
    begin = text.index('pub(crate) fn decode_checked(')
    end = text.index('    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]', begin)
    block = text[begin:end].replace('#[cfg(target_arch = "aarch64")]',
        '#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]')
    text = text[:begin] + block + text[end:]
    begin = text.index('pub fn hex_check_with_case(')
    end = text.index('    {', begin) + len('    {')
    text = text[:end] + '''
        if src.len() < 16 {
            return hex_check_fallback_with_case(src, check_case);
        }
''' + text[end:]
    path.write_text(text)
