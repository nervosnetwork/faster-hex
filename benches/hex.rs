use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use faster_hex::{hex_append, hex_decode, hex_encode, hex_encode_upper, hex_string};
use hex_simd::{AsOut, AsciiCase};
use std::hint::black_box;

mod support;

// Keep source/destination alignment and relative page offsets fixed across builds.
// Offset benchmarks below exercise other layouts separately.
struct ConversionBuffers {
    bytes: Vec<u8>,
    input: core::ops::Range<usize>,
    output: usize,
}

impl ConversionBuffers {
    fn new(input: &[u8], output_len: usize) -> Self {
        let separation = input.len().div_ceil(4096) * 4096 + 64;
        let mut bytes = vec![0; separation + output_len + 63];
        let start = bytes.as_ptr().align_offset(64);
        let output = start + separation;
        bytes.truncate(output + output_len);
        bytes[start..start + input.len()].copy_from_slice(input);
        Self {
            bytes,
            input: start..start + input.len(),
            output,
        }
    }

    fn parts(&mut self) -> (&[u8], &mut [u8]) {
        let (input, output) = self.bytes.split_at_mut(self.output);
        (&input[self.input.clone()], output)
    }
}

fn conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for &len in support::LENGTHS {
        let mut buffers = ConversionBuffers::new(&support::bytes(len), len * 2);
        let (input, output) = buffers.parts();
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("faster_hex", len), input, |b, src| {
            b.iter(|| {
                black_box(hex_encode(black_box(src), black_box(&mut *output)).unwrap());
            });
        });
        group.bench_with_input(
            BenchmarkId::new("faster_hex_upper", len),
            input,
            |b, src| {
                b.iter(|| {
                    black_box(hex_encode_upper(black_box(src), black_box(&mut *output)).unwrap());
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("hex", len), input, |b, src| {
            b.iter(|| {
                hex::encode_to_slice(black_box(src), black_box(&mut *output)).unwrap();
                black_box(&output);
            });
        });
        group.bench_with_input(BenchmarkId::new("const_hex", len), input, |b, src| {
            b.iter(|| {
                black_box(
                    const_hex::encode_to_str(black_box(src), black_box(&mut *output)).unwrap(),
                );
            });
        });
        group.bench_with_input(BenchmarkId::new("hex_simd", len), input, |b, src| {
            b.iter(|| {
                black_box(hex_simd::encode_as_str(
                    black_box(src),
                    black_box(&mut *output).as_out(),
                    AsciiCase::Lower,
                ));
            });
        });
        group.bench_with_input(BenchmarkId::new("fashex", len), input, |b, src| {
            b.iter(|| {
                black_box(
                    fashex::encode::<false>(black_box(src), black_box(&mut *output)).unwrap(),
                );
            });
        });
        group.bench_with_input(BenchmarkId::new("better_hex", len), input, |b, src| {
            b.iter(|| {
                black_box(
                    better_hex::encode_to_slice(black_box(src), black_box(&mut *output)).unwrap(),
                );
            });
        });
        group.bench_with_input(BenchmarkId::new("data_encoding", len), input, |b, src| {
            b.iter(|| {
                data_encoding::HEXLOWER.encode_mut(black_box(src), black_box(&mut *output));
                black_box(&output);
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("decode");
    for &len in support::LENGTHS {
        let lower = hex::encode(support::bytes(len)).into_bytes();
        let mixed: Vec<u8> = lower
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if i % 2 == 0 {
                    b.to_ascii_uppercase()
                } else {
                    *b
                }
            })
            .collect();
        let mut lower_buffers = ConversionBuffers::new(&lower, len);
        let mut mixed_buffers = ConversionBuffers::new(&mixed, len);
        let (lower, lower_output) = lower_buffers.parts();
        let (mixed, output) = mixed_buffers.parts();
        // Throughput uses decoded bytes for direct comparison with encode.
        group.throughput(Throughput::Bytes(len as u64));
        for (name, input, output) in [
            ("faster_hex", lower, lower_output),
            ("faster_hex_mixed", mixed, &mut *output),
        ] {
            group.bench_with_input(BenchmarkId::new(name, len), input, |b, src| {
                b.iter(|| {
                    hex_decode(black_box(src), black_box(&mut *output)).unwrap();
                    black_box(&output);
                });
            });
        }
        group.bench_with_input(BenchmarkId::new("hex", len), mixed, |b, src| {
            b.iter(|| {
                hex::decode_to_slice(black_box(src), black_box(&mut *output)).unwrap();
                black_box(&output);
            });
        });
        group.bench_with_input(BenchmarkId::new("const_hex", len), mixed, |b, src| {
            b.iter(|| {
                const_hex::decode_to_slice(black_box(src), black_box(&mut *output)).unwrap();
                black_box(&output);
            });
        });
        group.bench_with_input(BenchmarkId::new("hex_simd", len), mixed, |b, src| {
            b.iter(|| {
                black_box(
                    hex_simd::decode(black_box(src), black_box(&mut *output).as_out()).unwrap(),
                );
            });
        });
        group.bench_with_input(BenchmarkId::new("fashex", len), mixed, |b, src| {
            b.iter(|| {
                fashex::decode(black_box(src), black_box(&mut *output)).unwrap();
                black_box(&output);
            });
        });
        group.bench_with_input(BenchmarkId::new("better_hex", len), mixed, |b, src| {
            b.iter(|| {
                better_hex::decode_to_slice(black_box(src), black_box(&mut *output)).unwrap();
                black_box(&output);
            });
        });
        group.bench_with_input(BenchmarkId::new("data_encoding", len), mixed, |b, src| {
            b.iter(|| {
                data_encoding::HEXLOWER_PERMISSIVE
                    .decode_mut(black_box(src), black_box(&mut *output))
                    .unwrap();
                black_box(&output);
            });
        });
    }
    group.finish();
}

fn allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("string");
    for len in [8, 32, 64, 4096, 65536] {
        let input = support::bytes(len);
        let mut output = String::with_capacity(len * 2);
        group.bench_with_input(
            BenchmarkId::new("faster_hex_alloc", len),
            &input,
            |b, src| {
                b.iter(|| black_box(hex_string(black_box(src))));
            },
        );
        group.bench_with_input(BenchmarkId::new("hex_alloc", len), &input, |b, src| {
            b.iter(|| black_box(hex::encode(black_box(src))));
        });
        group.bench_with_input(
            BenchmarkId::new("const_hex_alloc", len),
            &input,
            |b, src| {
                b.iter(|| black_box(const_hex::encode(black_box(src))));
            },
        );
        group.bench_with_input(BenchmarkId::new("hex_simd_alloc", len), &input, |b, src| {
            b.iter(|| black_box(hex_simd::encode_to_string(black_box(src), AsciiCase::Lower)));
        });
        group.bench_with_input(BenchmarkId::new("hex_simd_reuse", len), &input, |b, src| {
            b.iter(|| {
                output.clear();
                hex_simd::encode_append(black_box(src), black_box(&mut output), AsciiCase::Lower);
                black_box(&output);
            });
        });
        group.bench_with_input(
            BenchmarkId::new("faster_hex_reuse", len),
            &input,
            |b, src| {
                b.iter(|| {
                    output.clear();
                    black_box(hex_append(black_box(src), black_box(&mut output)));
                });
            },
        );
    }
    group.finish();
}

fn alignment(c: &mut Criterion) {
    let mut group = c.benchmark_group("alignment");
    for len in [31, 32, 33, 4096] {
        let binary = support::bytes(len + 32);
        let encoded = hex::encode(&binary).into_bytes();
        for offset in [0, 1, 7, 15, 31] {
            let mut output = vec![0; len * 2 + 32];
            group.bench_function(format!("encode/{len}/{offset}"), |b| {
                b.iter(|| {
                    black_box(
                        hex_encode(
                            black_box(&binary[offset..offset + len]),
                            black_box(&mut output[(offset * 7) % 32..][..len * 2]),
                        )
                        .unwrap(),
                    );
                });
            });
            group.bench_function(format!("decode/{len}/{offset}"), |b| {
                b.iter(|| {
                    let dst = &mut output[(offset * 7) % 32..][..len];
                    hex_decode(
                        black_box(&encoded[offset..offset + len * 2]),
                        black_box(&mut *dst),
                    )
                    .unwrap();
                    black_box(dst);
                });
            });
        }
    }
    group.finish();
}

fn rotating_case(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    input: &[u8],
    expected: &[u8],
    payload_len: usize,
    mut convert: impl FnMut(&[u8], &mut [u8]),
) {
    let input_len = input.len() / 4096;
    let output_len = expected.len() / 4096;
    let mut output = vec![0; output_len];
    for (src, expected) in input
        .chunks_exact(input_len)
        .zip(expected.chunks_exact(output_len))
    {
        convert(src, &mut output);
        assert_eq!(output, expected);
    }
    group.throughput(Throughput::Bytes(payload_len as u64));
    group.bench_function(BenchmarkId::new(name, payload_len), |b| {
        let mut cursor = 0;
        b.iter(|| {
            let src = &input[cursor * input_len..][..input_len];
            cursor = (cursor + 1) & 4095;
            convert(black_box(src), black_box(&mut output));
            black_box(&output);
        });
    });
}

fn rotating(c: &mut Criterion) {
    for encode in [true, false] {
        let mut group = c.benchmark_group(if encode {
            "rotating_encode"
        } else {
            "rotating_decode"
        });
        for len in [1, 4, 8, 15, 16, 31, 32, 33, 64] {
            let binary = support::bytes(len * 4096);
            let lower = hex::encode(&binary).into_bytes();
            let mixed: Vec<_> = lower
                .iter()
                .enumerate()
                .map(|(i, byte)| {
                    if i % 2 == 0 {
                        byte.to_ascii_uppercase()
                    } else {
                        *byte
                    }
                })
                .collect();
            let (input, expected) = if encode {
                (&binary, &lower)
            } else {
                (&mixed, &binary)
            };
            // Expand each concrete closure here so the timer has no function-pointer dispatch.
            macro_rules! case {
                ($name:literal, $convert:expr) => {
                    rotating_case(&mut group, $name, input, expected, len, $convert);
                };
            }
            if encode {
                case!("faster_hex", |src, dst| {
                    hex_encode(src, dst).unwrap();
                });
                case!("const_hex", |src, dst| {
                    const_hex::encode_to_str(src, dst).unwrap();
                });
                case!("hex_simd", |src, dst| {
                    let _ = hex_simd::encode_as_str(src, dst.as_out(), AsciiCase::Lower);
                });
                case!("fashex", |src, dst| {
                    fashex::encode::<false>(src, dst).unwrap();
                });
                case!("better_hex", |src, dst| {
                    better_hex::encode_to_slice(src, dst).unwrap();
                });
            } else {
                case!("faster_hex", |src, dst| {
                    hex_decode(src, dst).unwrap();
                });
                case!("const_hex", |src, dst| {
                    const_hex::decode_to_slice(src, dst).unwrap();
                });
                case!("hex_simd", |src, dst| {
                    hex_simd::decode(src, dst.as_out()).unwrap();
                });
                case!("fashex", |src, dst| {
                    fashex::decode(src, dst).unwrap();
                });
                case!("better_hex", |src, dst| {
                    better_hex::decode_to_slice(src, dst).unwrap();
                });
            }
        }
        group.finish();
    }
}

fn text(c: &mut Criterion) {
    let input = support::TEXT;
    let expected = hex::encode(input);
    let mut encoded = vec![0; expected.len()];
    let mut decoded = vec![0; input.len()];
    let mut group = c.benchmark_group("text");
    group.throughput(Throughput::Bytes(input.len() as u64));
    group.bench_function("encode", |b| {
        b.iter(|| {
            black_box(hex_encode(black_box(input), black_box(&mut encoded)).unwrap());
        });
        assert_eq!(encoded, expected.as_bytes());
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            black_box(hex_decode(black_box(expected.as_bytes()), black_box(&mut decoded)).unwrap());
        });
        assert_eq!(decoded, input);
    });
    group.finish();
}

criterion_group!(benches, conversion, allocation, alignment, rotating, text);
criterion_main!(benches);
