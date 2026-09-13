//! Controlled disjoint source/output layouts for repeated Hash256 conversion.
use criterion::{criterion_group, criterion_main, Criterion};
use hex_simd::{AsOut, AsciiCase};
use std::hint::black_box;

#[repr(align(64))]
struct Storage([u8; 512]);

fn layout(c: &mut Criterion) {
    let binary: Vec<u8> = (0..32).map(|i| (i * 73 + 11) as u8).collect();
    let lower = hex::encode(&binary).into_bytes();
    for encoding in [true, false] {
        let (source, expected) = if encoding {
            (&binary, &lower)
        } else {
            (&lower, &binary)
        };
        for (layout, start, end) in [
            ("aligned_separate", 0, 128),
            ("unaligned_separate", 16, 144),
            ("adjacent_shared_line", 16, 16 + source.len()),
        ] {
            let mut storage = Storage([0; 512]);
            let (left, right) = storage.0.split_at_mut(end);
            let input = &mut left[start..][..source.len()];
            input.copy_from_slice(source);
            let input = &*input;
            let output = &mut right[..expected.len()];
            let operation = if encoding { "encode" } else { "decode" };
            eprintln!(
                "LAYOUT {operation}/{layout}: input={:p}, output={:p}, lengths={}/{}",
                input.as_ptr(),
                output.as_ptr(),
                input.len(),
                output.len()
            );
            let mut group = c.benchmark_group(format!("layout/{operation}/{layout}"));
            macro_rules! case {
                ($name:literal, $convert:expr) => {{
                    let convert = $convert;
                    convert(input, output);
                    assert_eq!(output, expected.as_slice());
                    group.bench_function($name, |b| {
                        b.iter(|| {
                            convert(black_box(input), black_box(&mut *output));
                            black_box(&*output);
                        });
                    });
                    assert_eq!(output, expected.as_slice());
                }};
            }
            if encoding {
                case!("faster_hex", |src: &[u8], dst: &mut [u8]| {
                    faster_hex::hex_encode(src, dst).unwrap();
                });
                case!("const_hex", |src: &[u8], dst: &mut [u8]| {
                    const_hex::encode_to_str(src, dst).unwrap();
                });
                case!("hex_simd", |src: &[u8], dst: &mut [u8]| {
                    hex_simd::encode_as_str(src, dst.as_out(), AsciiCase::Lower);
                });
                case!("fashex", |src: &[u8], dst: &mut [u8]| {
                    fashex::encode::<false>(src, dst).unwrap();
                });
            } else {
                case!("faster_hex", |src: &[u8], dst: &mut [u8]| {
                    faster_hex::hex_decode(src, dst).unwrap();
                });
                case!("const_hex", |src: &[u8], dst: &mut [u8]| {
                    const_hex::decode_to_slice(src, dst).unwrap();
                });
                case!("hex_simd", |src: &[u8], dst: &mut [u8]| {
                    hex_simd::decode(src, dst.as_out()).unwrap();
                });
                case!("fashex", |src: &[u8], dst: &mut [u8]| {
                    fashex::decode(src, dst).unwrap();
                });
            }
            group.finish();
        }
    }
}

criterion_group!(benches, layout);
criterion_main!(benches);
