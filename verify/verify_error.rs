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
criterion_group!(benches, errors);
criterion_main!(benches);
