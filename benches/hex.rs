use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use faster_hex::{
    hex_append, hex_decode, hex_decode_array, hex_decode_vec, hex_encode, hex_encode_upper,
    hex_string,
};
use hex_simd::{AsOut, AsciiCase};
use std::hint::black_box;

mod support;

fn conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for &len in support::LENGTHS {
        let input = support::bytes(len);
        let expected = hex::encode(&input);
        let mut output = vec![0; len * 2];
        group.throughput(Throughput::Bytes(len as u64));
        // Expand concrete calls: function-pointer overhead distorts short hashes.
        macro_rules! case {
            ($name:literal, $encode:expr, $expected:expr) => {
                group.bench_function(BenchmarkId::new($name, len), |b| {
                    b.iter(|| {
                        $encode(
                            black_box(input.as_slice()),
                            black_box(output.as_mut_slice()),
                        );
                        black_box(&output);
                    });
                    assert_eq!(output, $expected.as_bytes());
                });
            };
        }
        case!(
            "faster_hex",
            |src, dst| {
                hex_encode(src, dst).unwrap();
            },
            expected
        );
        case!(
            "faster_hex_upper",
            |src, dst| {
                hex_encode_upper(src, dst).unwrap();
            },
            expected.to_ascii_uppercase()
        );
        case!(
            "hex",
            |src, dst| {
                hex::encode_to_slice(src, dst).unwrap();
            },
            expected
        );
        case!(
            "const_hex",
            |src, dst| {
                const_hex::encode_to_str(src, dst).unwrap();
            },
            expected
        );
        case!(
            "hex_simd",
            |src, dst: &mut [u8]| {
                let _ = hex_simd::encode_as_str(src, dst.as_out(), AsciiCase::Lower);
            },
            expected
        );
        case!(
            "fashex",
            |src, dst| {
                fashex::encode::<false>(src, dst).unwrap();
            },
            expected
        );
        case!(
            "better_hex",
            |src, dst| {
                better_hex::encode_to_slice(src, dst).unwrap();
            },
            expected
        );
        case!(
            "data_encoding",
            |src, dst| {
                data_encoding::HEXLOWER.encode_mut(src, dst);
            },
            expected
        );
    }
    group.finish();

    let mut group = c.benchmark_group("decode");
    for &len in support::LENGTHS {
        let expected = support::bytes(len);
        let lower = hex::encode(&expected).into_bytes();
        let mut mixed = lower.clone();
        for byte in mixed.iter_mut().step_by(2) {
            byte.make_ascii_uppercase();
        }
        let mut output = vec![0; len];
        // Throughput counts decoded bytes, as in the encoding benchmark.
        group.throughput(Throughput::Bytes(len as u64));
        macro_rules! case {
            ($name:literal, $input:expr, $decode:expr) => {
                group.bench_function(BenchmarkId::new($name, len), |b| {
                    b.iter(|| {
                        $decode(
                            black_box($input.as_slice()),
                            black_box(output.as_mut_slice()),
                        );
                        black_box(&output);
                    });
                    assert_eq!(output, expected);
                });
            };
        }
        case!("faster_hex", lower, |src, dst| {
            hex_decode(src, dst).unwrap();
        });
        case!("faster_hex_mixed", mixed, |src, dst| {
            hex_decode(src, dst).unwrap();
        });
        case!("hex", mixed, |src, dst| {
            hex::decode_to_slice(src, dst).unwrap();
        });
        case!("const_hex", mixed, |src, dst| {
            const_hex::decode_to_slice(src, dst).unwrap();
        });
        case!("hex_simd", mixed, |src, dst: &mut [u8]| {
            hex_simd::decode(src, dst.as_out()).unwrap();
        });
        case!("fashex", mixed, |src, dst| {
            fashex::decode(src, dst).unwrap();
        });
        case!("better_hex", mixed, |src, dst| {
            better_hex::decode_to_slice(src, dst).unwrap();
        });
        case!("data_encoding", mixed, |src, dst| {
            data_encoding::HEXLOWER_PERMISSIVE
                .decode_mut(src, dst)
                .unwrap();
        });
    }
    group.finish();
}

fn array_size<const N: usize>(c: &mut Criterion) {
    let expected = support::bytes(N);
    let mut input = hex::encode(&expected).into_bytes();
    for byte in input.iter_mut().step_by(2) {
        byte.make_ascii_uppercase();
    }
    let mut group = c.benchmark_group("decode_array");
    group.throughput(Throughput::Bytes(N as u64));
    // Every case returns an owned array, including the slice-API controls.
    // Criterion consumes the returned array; keep calls concrete inside the timer.
    macro_rules! case {
        ($name:literal, $decode:expr) => {
            assert_eq!(($decode)(&input).as_slice(), expected.as_slice());
            group.bench_function(BenchmarkId::new($name, N), |b| {
                b.iter(|| ($decode)(black_box(input.as_slice())));
            });
        };
    }
    case!("faster_hex", |src: &[u8]| hex_decode_array::<N>(src)
        .unwrap());
    case!("faster_hex_slice", |src: &[u8]| {
        let mut output = [0; N];
        hex_decode(src, &mut output).unwrap();
        output
    });
    case!("const_hex", |src: &[u8]| {
        const_hex::decode_to_array::<_, N>(src).unwrap()
    });
    case!("fashex_slice", |src: &[u8]| {
        let mut output = [0; N];
        fashex::decode(src, &mut output).unwrap();
        output
    });
    group.finish();
}

fn decode_array(c: &mut Criterion) {
    array_size::<4>(c);
    array_size::<8>(c);
    array_size::<32>(c);
    array_size::<65>(c);
    array_size::<256>(c);
    array_size::<4096>(c);
}

fn decode_vec(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_vec");
    for len in [32, 65, 256, 4096, 65536] {
        let expected = support::bytes(len);
        let mut input = hex::encode(&expected).into_bytes();
        for byte in input.iter_mut().step_by(2) {
            byte.make_ascii_uppercase();
        }
        group.throughput(Throughput::Bytes(len as u64));
        // Include allocation, validation, decoding and destruction on every side.
        macro_rules! case {
            ($name:literal, $decode:expr) => {
                assert_eq!(($decode)(&input), expected);
                group.bench_function(BenchmarkId::new($name, len), |b| {
                    b.iter(|| ($decode)(black_box(input.as_slice())));
                });
            };
        }
        case!("faster_hex", |src: &[u8]| hex_decode_vec(src).unwrap());
        case!("const_hex", |src: &[u8]| const_hex::decode(src).unwrap());
        case!("fashex_slice", |src: &[u8]| {
            let mut output = vec![0; src.len() / 2];
            fashex::decode(src, output.as_mut_slice()).unwrap();
            output
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
        for len in [1, 8, 10, 32, 64] {
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

criterion_group!(
    benches,
    conversion,
    decode_array,
    decode_vec,
    allocation,
    rotating
);
criterion_main!(benches);
