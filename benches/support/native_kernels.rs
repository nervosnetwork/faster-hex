use core::arch::x86_64::*;
#[inline]
#[target_feature(enable = "sse4.1")]
unsafe fn valid128(x: __m128i) -> __m128i {
    let d = _mm_cmpgt_epi8(_mm_set1_epi8(-118), _mm_add_epi8(x, _mm_set1_epi8(80)));
    let a = _mm_cmpgt_epi8(
        _mm_set1_epi8(-122),
        _mm_add_epi8(_mm_or_si128(x, _mm_set1_epi8(32)), _mm_set1_epi8(31)),
    );
    _mm_or_si128(d, a)
}
#[inline]
#[target_feature(enable = "sse4.1")]
unsafe fn nibble128(x: __m128i) -> __m128i {
    _mm_add_epi8(
        _mm_and_si128(x, _mm_set1_epi8(15)),
        _mm_and_si128(_mm_cmpgt_epi8(x, _mm_set1_epi8(57)), _mm_set1_epi8(9)),
    )
}
#[inline]
#[target_feature(enable = "sse4.1")]
unsafe fn mapped128(x: __m128i) -> __m128i {
    let d = _mm_sub_epi8(
        _mm_subs_epu8(_mm_add_epi8(x, _mm_set1_epi8(-58)), _mm_set1_epi8(6)),
        _mm_set1_epi8(-16),
    );
    let a = _mm_adds_epu8(
        _mm_sub_epi8(_mm_or_si128(x, _mm_set1_epi8(32)), _mm_set1_epi8(97)),
        _mm_set1_epi8(10),
    );
    _mm_min_epu8(d, a)
}
#[no_mangle]
#[target_feature(enable = "sse4.1")]
pub unsafe extern "sysv64" fn decode_before_128(src: *const u8, dst: *mut u8) -> bool {
    let x0 = _mm_loadu_si128(src.add(0).cast());
    let x1 = _mm_loadu_si128(src.add(16).cast());
    let x2 = _mm_loadu_si128(src.add(32).cast());
    let x3 = _mm_loadu_si128(src.add(48).cast());
    let v0 = valid128(x0);
    let v1 = valid128(x1);
    let v2 = valid128(x2);
    let v3 = valid128(x3);
    if _mm_movemask_epi8(_mm_and_si128(_mm_and_si128(_mm_and_si128(v0, v1), v2), v3)) != 65535 {
        return false;
    }
    let n0 = nibble128(x0);
    let n1 = nibble128(x1);
    let n2 = nibble128(x2);
    let n3 = nibble128(x3);
    _mm_storeu_si128(
        dst.add(0).cast(),
        _mm_packus_epi16(
            _mm_maddubs_epi16(n0, _mm_set1_epi16(0x0110)),
            _mm_maddubs_epi16(n1, _mm_set1_epi16(0x0110)),
        ),
    );
    _mm_storeu_si128(
        dst.add(16).cast(),
        _mm_packus_epi16(
            _mm_maddubs_epi16(n2, _mm_set1_epi16(0x0110)),
            _mm_maddubs_epi16(n3, _mm_set1_epi16(0x0110)),
        ),
    );
    true
}
#[no_mangle]
#[target_feature(enable = "sse4.1")]
pub unsafe extern "sysv64" fn decode_fused_128(src: *const u8, dst: *mut u8) -> bool {
    let x0 = _mm_loadu_si128(src.add(0).cast());
    let x1 = _mm_loadu_si128(src.add(16).cast());
    let x2 = _mm_loadu_si128(src.add(32).cast());
    let x3 = _mm_loadu_si128(src.add(48).cast());
    let n0 = mapped128(x0);
    let n1 = mapped128(x1);
    let n2 = mapped128(x2);
    let n3 = mapped128(x3);
    if _mm_testz_si128(
        _mm_or_si128(_mm_or_si128(_mm_or_si128(n0, n1), n2), n3),
        _mm_set1_epi8(-16),
    ) == 0
    {
        return false;
    }
    _mm_storeu_si128(
        dst.add(0).cast(),
        _mm_packus_epi16(
            _mm_maddubs_epi16(n0, _mm_set1_epi16(0x0110)),
            _mm_maddubs_epi16(n1, _mm_set1_epi16(0x0110)),
        ),
    );
    _mm_storeu_si128(
        dst.add(16).cast(),
        _mm_packus_epi16(
            _mm_maddubs_epi16(n2, _mm_set1_epi16(0x0110)),
            _mm_maddubs_epi16(n3, _mm_set1_epi16(0x0110)),
        ),
    );
    true
}
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn valid256(x: __m256i) -> __m256i {
    let d = _mm256_cmpgt_epi8(
        _mm256_set1_epi8(-118),
        _mm256_add_epi8(x, _mm256_set1_epi8(80)),
    );
    let a = _mm256_cmpgt_epi8(
        _mm256_set1_epi8(-122),
        _mm256_add_epi8(
            _mm256_or_si256(x, _mm256_set1_epi8(32)),
            _mm256_set1_epi8(31),
        ),
    );
    _mm256_or_si256(d, a)
}
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn nibble256(x: __m256i) -> __m256i {
    _mm256_add_epi8(
        _mm256_and_si256(x, _mm256_set1_epi8(15)),
        _mm256_and_si256(
            _mm256_cmpgt_epi8(x, _mm256_set1_epi8(57)),
            _mm256_set1_epi8(9),
        ),
    )
}
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn mapped256(x: __m256i) -> __m256i {
    let d = _mm256_sub_epi8(
        _mm256_subs_epu8(
            _mm256_add_epi8(x, _mm256_set1_epi8(-58)),
            _mm256_set1_epi8(6),
        ),
        _mm256_set1_epi8(-16),
    );
    let a = _mm256_adds_epu8(
        _mm256_sub_epi8(
            _mm256_or_si256(x, _mm256_set1_epi8(32)),
            _mm256_set1_epi8(97),
        ),
        _mm256_set1_epi8(10),
    );
    _mm256_min_epu8(d, a)
}
#[no_mangle]
#[target_feature(enable = "avx2")]
pub unsafe extern "sysv64" fn decode_before_256(src: *const u8, dst: *mut u8) -> bool {
    let x0 = _mm256_loadu_si256(src.add(0).cast());
    let x1 = _mm256_loadu_si256(src.add(32).cast());
    let v0 = valid256(x0);
    let v1 = valid256(x1);
    if _mm256_movemask_epi8(_mm256_and_si256(v0, v1)) != -1 {
        return false;
    }
    let n0 = nibble256(x0);
    let n1 = nibble256(x1);
    _mm256_storeu_si256(
        dst.add(0).cast(),
        _mm256_permute4x64_epi64::<0xd8>(_mm256_packus_epi16(
            _mm256_maddubs_epi16(n0, _mm256_set1_epi16(0x0110)),
            _mm256_maddubs_epi16(n1, _mm256_set1_epi16(0x0110)),
        )),
    );
    true
}
#[no_mangle]
#[target_feature(enable = "avx2")]
pub unsafe extern "sysv64" fn decode_fused_256(src: *const u8, dst: *mut u8) -> bool {
    let x0 = _mm256_loadu_si256(src.add(0).cast());
    let x1 = _mm256_loadu_si256(src.add(32).cast());
    let n0 = mapped256(x0);
    let n1 = mapped256(x1);
    if _mm256_testz_si256(_mm256_or_si256(n0, n1), _mm256_set1_epi8(-16)) == 0 {
        return false;
    }
    _mm256_storeu_si256(
        dst.add(0).cast(),
        _mm256_permute4x64_epi64::<0xd8>(_mm256_packus_epi16(
            _mm256_maddubs_epi16(n0, _mm256_set1_epi16(0x0110)),
            _mm256_maddubs_epi16(n1, _mm256_set1_epi16(0x0110)),
        )),
    );
    true
}

#[no_mangle]
#[target_feature(enable = "avx2")]
pub unsafe extern "sysv64" fn encode_before_256(src: *const u8, dst: *mut u8) {
    let x = _mm256_loadu_si256(src.cast());
    let m = _mm256_set1_epi8(15);
    let ascii = |n| {
        _mm256_add_epi8(
            n,
            _mm256_blendv_epi8(
                _mm256_set1_epi8(48),
                _mm256_set1_epi8(87),
                _mm256_cmpgt_epi8(n, _mm256_set1_epi8(9)),
            ),
        )
    };
    let h = ascii(_mm256_and_si256(_mm256_srli_epi16::<4>(x), m));
    let l = ascii(_mm256_and_si256(x, m));
    let a = _mm256_unpacklo_epi8(h, l);
    let b = _mm256_unpackhi_epi8(h, l);
    _mm256_storeu_si256(dst.cast(), _mm256_permute2x128_si256::<0x20>(a, b));
    _mm256_storeu_si256(dst.add(32).cast(), _mm256_permute2x128_si256::<0x31>(a, b));
}
#[no_mangle]
#[target_feature(enable = "avx2")]
pub unsafe extern "sysv64" fn encode_table_256(src: *const u8, dst: *mut u8) {
    let x = _mm256_loadu_si256(src.cast());
    let m = _mm256_set1_epi8(15);
    let lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(b"0123456789abcdef".as_ptr().cast()));
    let h = _mm256_and_si256(_mm256_srli_epi16::<4>(x), m);
    let l = _mm256_and_si256(x, m);
    let a = _mm256_unpacklo_epi8(h, l);
    let b = _mm256_unpackhi_epi8(h, l);
    _mm256_storeu_si256(
        dst.cast(),
        _mm256_shuffle_epi8(lut, _mm256_permute2x128_si256::<0x20>(a, b)),
    );
    _mm256_storeu_si256(
        dst.add(32).cast(),
        _mm256_shuffle_epi8(lut, _mm256_permute2x128_si256::<0x31>(a, b)),
    );
}
#[no_mangle]
#[target_feature(enable = "avx2")]
pub unsafe extern "sysv64" fn encode_widen_256(src: *const u8, dst: *mut u8) {
    let lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(b"0123456789abcdef".as_ptr().cast()));
    for i in 0..2 {
        let x = _mm256_cvtepu8_epi16(_mm_loadu_si128(src.add(i * 16).cast()));
        let n = _mm256_and_si256(
            _mm256_or_si256(_mm256_srli_epi16::<4>(x), _mm256_slli_epi16::<8>(x)),
            _mm256_set1_epi8(15),
        );
        _mm256_storeu_si256(dst.add(i * 32).cast(), _mm256_shuffle_epi8(lut, n));
    }
}
#[no_mangle]
#[target_feature(enable = "avx512f,avx512bw")]
pub unsafe extern "sysv64" fn encode_widen_512(src: *const u8, dst: *mut u8) {
    let lut = _mm512_broadcast_i32x4(_mm_loadu_si128(b"0123456789abcdef".as_ptr().cast()));
    let x = _mm512_cvtepu8_epi16(_mm256_loadu_si256(src.cast()));
    let n = _mm512_and_si512(
        _mm512_or_si512(_mm512_srli_epi16::<4>(x), _mm512_slli_epi16::<8>(x)),
        _mm512_set1_epi8(15),
    );
    _mm512_storeu_si512(dst.cast(), _mm512_shuffle_epi8(lut, n));
}
#[no_mangle]
#[target_feature(enable = "avx512f,avx512bw,avx512vbmi")]
pub unsafe extern "sysv64" fn encode_vbmi_512(src: *const u8, dst: *mut u8) {
    let lut = _mm512_broadcast_i32x4(_mm_loadu_si128(b"0123456789abcdef".as_ptr().cast()));
    let x = _mm512_cvtepu32_epi64(_mm256_loadu_si256(src.cast()));
    let n = _mm512_and_si512(
        _mm512_multishift_epi64_epi8(_mm512_set1_epi64(0x181c1014080c0004), x),
        _mm512_set1_epi8(15),
    );
    _mm512_storeu_si512(dst.cast(), _mm512_shuffle_epi8(lut, n));
}
#[no_mangle]
#[target_feature(enable = "avx512f,avx512bw")]
pub unsafe extern "sysv64" fn decode_fused_512(src: *const u8, dst: *mut u8) -> bool {
    let x = _mm512_loadu_si512(src.cast());
    let d = _mm512_sub_epi8(
        _mm512_subs_epu8(
            _mm512_add_epi8(x, _mm512_set1_epi8(-58)),
            _mm512_set1_epi8(6),
        ),
        _mm512_set1_epi8(-16),
    );
    let a = _mm512_adds_epu8(
        _mm512_sub_epi8(
            _mm512_or_si512(x, _mm512_set1_epi8(32)),
            _mm512_set1_epi8(97),
        ),
        _mm512_set1_epi8(10),
    );
    let n = _mm512_min_epu8(d, a);
    if _mm512_test_epi8_mask(n, _mm512_set1_epi8(-16)) != 0 {
        return false;
    }
    let out = _mm512_cvtepi16_epi8(_mm512_maddubs_epi16(n, _mm512_set1_epi16(0x0110)));
    _mm256_storeu_si256(dst.cast(), out);
    true
}
