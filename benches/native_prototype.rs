//! Experimental fixed Hash256 kernels. These measurements exclude public API
//! dispatch and variable-length contracts; compare AVX2 and AVX-512 kernels here.
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

#[allow(dead_code)]
#[path = "support/native_kernels.rs"]
mod kernels;

fn encoding<F: Fn(&[u8; 32], &mut [u8; 64])>(c: &mut Criterion, name: &str, encode: F) {
    let inputs: Vec<[u8; 32]> = (0..256)
        .map(|seed| core::array::from_fn(|i| (i * 73 + seed) as u8))
        .collect();
    for src in &inputs {
        let mut dst = [0xa5; 64];
        encode(src, &mut dst);
        assert_eq!(dst.as_slice(), hex::encode(src).as_bytes());
    }
    for rotating in [false, true] {
        let name = format!(
            "prototype_encode/{name}/{}",
            if rotating { "rotating" } else { "hot" }
        );
        let mut dst = [0; 64];
        let mut cursor = 0;
        c.bench_function(&name, |b| {
            b.iter(|| {
                let src = black_box(&inputs[cursor]);
                if rotating {
                    cursor = (cursor + 1) & 255;
                }
                encode(src, black_box(&mut dst));
                black_box(&dst);
            })
        });
    }
}

fn decoding<F: Fn(&[u8; 64], &mut [u8; 32]) -> bool>(c: &mut Criterion, name: &str, decode: F) {
    let inputs: Vec<[u8; 64]> = (0..256)
        .map(|seed| {
            let bytes: [u8; 32] = core::array::from_fn(|i| (i * 73 + seed) as u8);
            let text = hex::encode(bytes);
            core::array::from_fn(|i| {
                if i % 2 == 0 {
                    text.as_bytes()[i].to_ascii_uppercase()
                } else {
                    text.as_bytes()[i]
                }
            })
        })
        .collect();
    for src in &inputs {
        let mut dst = [0xa5; 32];
        assert!(decode(src, &mut dst));
        assert_eq!(dst.as_slice(), hex::decode(src).unwrap());
    }
    for pos in 0..64 {
        for byte in 0..=255 {
            let mut src = [b'0'; 64];
            src[pos] = byte;
            let mut dst = [0xa5; 32];
            assert_eq!(decode(&src, &mut dst), byte.is_ascii_hexdigit());
            if !byte.is_ascii_hexdigit() {
                assert_eq!(dst, [0xa5; 32]);
            }
        }
    }
    for rotating in [false, true] {
        let name = format!(
            "prototype_decode/{name}/{}",
            if rotating { "rotating" } else { "hot" }
        );
        let mut dst = [0; 32];
        let mut cursor = 0;
        c.bench_function(&name, |b| {
            b.iter(|| {
                let src = black_box(&inputs[cursor]);
                if rotating {
                    cursor = (cursor + 1) & 255;
                }
                assert!(decode(src, black_box(&mut dst)));
                black_box(&dst);
            })
        });
    }
}

fn prototypes(c: &mut Criterion) {
    if !std::arch::is_x86_feature_detected!("avx2") {
        return;
    }
    // SAFETY: All buffers have the exact kernel sizes; the CPU checks above and
    // below establish each instruction requirement before any invocation.
    encoding(c, "avx2_table", |s, d| unsafe {
        kernels::encode_table_256(s.as_ptr(), d.as_mut_ptr())
    });
    encoding(c, "avx2_widen", |s, d| unsafe {
        kernels::encode_widen_256(s.as_ptr(), d.as_mut_ptr())
    });
    decoding(c, "avx2_fused", |s, d| unsafe {
        kernels::decode_fused_256(s.as_ptr(), d.as_mut_ptr())
    });
    if std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512bw")
    {
        encoding(c, "avx512_bw", |s, d| unsafe {
            kernels::encode_widen_512(s.as_ptr(), d.as_mut_ptr())
        });
        decoding(c, "avx512_bw", |s, d| unsafe {
            kernels::decode_fused_512(s.as_ptr(), d.as_mut_ptr())
        });
        if std::arch::is_x86_feature_detected!("avx512vbmi") {
            encoding(c, "avx512_vbmi", |s, d| unsafe {
                kernels::encode_vbmi_512(s.as_ptr(), d.as_mut_ptr())
            });
        }
    }
}

criterion_group!(benches, prototypes);
criterion_main!(benches);
