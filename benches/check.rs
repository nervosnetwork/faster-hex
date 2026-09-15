use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use faster_hex::{hex_check, hex_check_with_case, hex_decode, CheckCase};
use std::hint::black_box;

mod support;

fn comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_compare");
    for &len in support::LENGTHS {
        let input: Vec<_> = hex::encode(support::bytes(len))
            .bytes()
            .enumerate()
            .map(|(i, byte)| {
                if i % 2 == 0 {
                    byte.to_ascii_uppercase()
                } else {
                    byte
                }
            })
            .collect();
        group.throughput(Throughput::Bytes(len as u64));
        // Keep each library's concrete checker inlined into its own timer.
        macro_rules! case {
            ($name:literal, $check:expr) => {
                assert!($check(&input));
                group.bench_function(BenchmarkId::new($name, len), |b| {
                    b.iter(|| black_box($check(black_box(&input))));
                });
            };
        }
        case!("faster_hex", |src: &[u8]| hex_check(src));
        case!("const_hex", |src: &[u8]| const_hex::check(src).is_ok());
        case!("hex_simd", |src: &[u8]| hex_simd::check(src).is_ok());
        case!("better_hex", |src: &[u8]| better_hex::check(src));
    }
    group.finish();
}

fn check(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_valid");
    for &len in support::LENGTHS {
        let src = hex::encode(support::bytes(len));
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("either", len), &src, |b, src| {
            b.iter(|| black_box(hex_check(black_box(src.as_bytes()))));
        });
        group.bench_with_input(BenchmarkId::new("lower", len), &src, |b, src| {
            b.iter(|| {
                black_box(hex_check_with_case(
                    black_box(src.as_bytes()),
                    CheckCase::Lower,
                ))
            });
        });
        let upper = src.to_ascii_uppercase();
        group.bench_with_input(BenchmarkId::new("upper", len), &upper, |b, src| {
            b.iter(|| {
                black_box(hex_check_with_case(
                    black_box(src.as_bytes()),
                    CheckCase::Upper,
                ))
            });
        });
    }
    group.finish();

    // Failed inputs report latency, not misleading whole-input throughput.
    let mut group = c.benchmark_group("invalid");
    for len in [1, 32, 4096] {
        let valid = hex::encode(support::bytes(len)).into_bytes();
        let mut output = vec![0xa5; len];
        for (name, position) in [("first", 0), ("middle", len), ("last", len * 2 - 1)] {
            let mut src = valid.clone();
            src[position] = b'g';
            group.bench_function(format!("check/{name}/{len}"), |b| {
                b.iter(|| black_box(hex_check(black_box(&src))));
            });
            group.bench_function(format!("decode/{name}/{len}"), |b| {
                b.iter(|| {
                    black_box(hex_decode(black_box(&src), black_box(&mut output)).unwrap_err());
                    black_box(&output);
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, check, comparison);
criterion_main!(benches);
