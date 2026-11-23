use criterion::{criterion_group, criterion_main, Criterion};
use faster_hex::{hex_decode_vec, Error};
use std::hint::black_box;

fn owned_errors(c: &mut Criterion) {
    let mut group = c.benchmark_group("owned_error");
    let len = 4096;
    for (name, index) in [("first", 0), ("second_block", 64), ("middle", len), ("last", 2 * len - 1)] {
        let mut input = b"aF".repeat(len);
        input[index] = 0x80;
        assert!(matches!(hex_decode_vec(&input),
            Err(Error::InvalidChar { index: actual, byte: 0x80, .. }) if actual == index));
        group.bench_function(format!("{name}/{len}"), |b| {
            b.iter(|| black_box(hex_decode_vec(black_box(&input)).unwrap_err()))
        });
    }
    group.finish();
}
criterion_group!(benches, owned_errors);
criterion_main!(benches);
