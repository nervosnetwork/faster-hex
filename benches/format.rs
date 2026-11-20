//! Format complete inputs and abbreviated views into reusable storage.
use criterion::{criterion_group, criterion_main, Criterion};
use faster_hex::Hex;
use std::{fmt::Write, hint::black_box};

#[path = "support/format.rs"]
mod format;
mod support;

fn leading_digits(c: &mut Criterion) {
    let hash = support::bytes(32);
    let mut output = String::with_capacity(64);
    c.bench_function("format/leading_digits/7", |b| {
        b.iter(|| {
            output.clear();
            write!(
                output,
                "{}",
                Hex::new(black_box(&hash)).leading_digits(black_box(7))
            )
            .unwrap();
            black_box(output.as_str());
        });
        assert_eq!(output, hex::encode(&hash)[..7]);
    });
}

criterion_group!(benches, format::formatting, leading_digits);
criterion_main!(benches);
