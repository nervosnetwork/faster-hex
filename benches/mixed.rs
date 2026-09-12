//! One iteration processes a complete, deterministically shuffled batch. Reported
//! latency is per batch; byte throughput counts the decoded payload. Input creation,
//! output allocation and correctness checks are outside the timer.
use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, Throughput};
use std::hint::black_box;

mod support;

fn conversion(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    input: &[Vec<u8>],
    expected: &[Vec<u8>],
    mut convert: impl FnMut(&[u8], &mut [u8]),
) {
    let mut output: Vec<Vec<u8>> = expected
        .iter()
        .map(|bytes| vec![0xa5; bytes.len()])
        .collect();
    for ((input, output), expected) in input.iter().zip(&mut output).zip(expected) {
        convert(input, output);
        assert_eq!(output, expected);
        output.fill(0xa5);
    }
    group.bench_function(name, |b| {
        b.iter(|| {
            for (input, output) in input.iter().zip(&mut output) {
                convert(black_box(input), black_box(&mut *output));
                black_box(output.as_slice());
            }
        });
        assert_eq!(output, expected);
    });
}

fn mixed(c: &mut Criterion) {
    for (name, lengths) in [
        ("small", &[1, 8, 16, 32, 32, 32, 64, 64][..]),
        (
            "bulk",
            &[0, 1, 8, 16, 32, 32, 64, support::TEXT.len(), 256, 4096][..],
        ),
    ] {
        let mut lengths = lengths.repeat(16);
        let mut seed = 0x243f_6a88u32;
        for index in (1..lengths.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            lengths.swap(index, seed as usize % (index + 1));
        }
        let binary: Vec<_> = lengths
            .iter()
            .enumerate()
            .map(|(index, &len)| {
                if len == support::TEXT.len() {
                    support::TEXT.to_vec()
                } else {
                    support::bytes(len)
                        .into_iter()
                        .map(|byte| byte.wrapping_add(index as u8))
                        .collect()
                }
            })
            .collect();
        let lower: Vec<_> = binary
            .iter()
            .map(|bytes| hex::encode(bytes).into_bytes())
            .collect();
        let mixed: Vec<_> = lower
            .iter()
            .map(|bytes| {
                bytes
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| {
                        if index % 3 == 0 {
                            byte.to_ascii_uppercase()
                        } else {
                            *byte
                        }
                    })
                    .collect()
            })
            .collect();
        let mut group = c.benchmark_group(format!("mixed/{name}"));
        group.throughput(Throughput::Bytes(lengths.iter().sum::<usize>() as u64));
        conversion(
            &mut group,
            "encode/faster_hex",
            &binary,
            &lower,
            |src, dst| {
                faster_hex::hex_encode(src, dst).unwrap();
            },
        );
        conversion(
            &mut group,
            "encode/const_hex",
            &binary,
            &lower,
            |src, dst| {
                const_hex::encode_to_str(src, dst).unwrap();
            },
        );
        conversion(&mut group, "encode/hex", &binary, &lower, |src, dst| {
            hex::encode_to_slice(src, dst).unwrap();
        });
        conversion(
            &mut group,
            "decode/faster_hex",
            &mixed,
            &binary,
            |src, dst| {
                faster_hex::hex_decode(src, dst).unwrap();
            },
        );
        conversion(
            &mut group,
            "decode/const_hex",
            &mixed,
            &binary,
            |src, dst| {
                const_hex::decode_to_slice(src, dst).unwrap();
            },
        );
        conversion(&mut group, "decode/hex", &mixed, &binary, |src, dst| {
            hex::decode_to_slice(src, dst).unwrap();
        });
        group.finish();
    }
}

criterion_group!(benches, mixed);
criterion_main!(benches);
