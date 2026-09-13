"""Source transformations for isolated short-input experiments, not public features."""


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
