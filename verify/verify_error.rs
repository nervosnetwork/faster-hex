use criterion::{criterion_group, criterion_main, Criterion};
use faster_hex::{hex_validate, Error};
use std::hint::black_box;

fn errors(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_error");
    for len in [32, 65, 4096] {
        for (position, index) in [("first", 0), ("middle", len), ("last", len * 2 - 1)] {
            let mut bytes = b"aF".repeat(len);
            bytes[index] = 0x80;
            assert!(matches!(
                hex_validate(&bytes),
                Err(Error::InvalidChar { index: actual, byte: 0x80, .. }) if actual == index
            ));
            group.bench_function(format!("{position}/{len}"), |b| {
                b.iter(|| black_box(hex_validate(black_box(&bytes))))
            });
        }
    }
    group.finish();
}

fn append_errors(c: &mut Criterion) {
    let mut group = c.benchmark_group("append_error");
    for len in [32, 65, 4096] {
        for (name, index) in [("first", 0), ("middle", len), ("last", len * 2 - 1)] {
            let mut input = b"aF".repeat(len);
            input[index] = 0x80;
            let mut dst = Vec::with_capacity(len + 3);
            dst.extend_from_slice(b"old");
            group.bench_function(format!("{name}/{len}"), |b| {
                b.iter(|| black_box(faster_hex::hex_decode_append(black_box(&input), black_box(&mut dst)).unwrap_err()))
            });
            assert_eq!(dst, b"old");
        }
    }
    group.finish();
}

criterion_group!(benches, errors, append_errors);
criterion_main!(benches);
