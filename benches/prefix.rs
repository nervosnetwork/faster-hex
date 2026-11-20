//! The two gix-hash call sites have different destination contracts.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::{fmt, fmt::Write, hint::black_box};

#[path = "support/prefix.rs"]
mod prefix;

struct Abbreviation<'a>(&'a [u8], usize);

impl fmt::Display for Abbreviation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // gix's formatter owns a full-size scratch buffer, even for a short ID.
        let mut buffer = [0; 64];
        let text = faster_hex::hex_encode(self.0, &mut buffer).unwrap();
        f.write_str(&text[..self.1.min(text.len())])
    }
}

fn git_prefix(c: &mut Criterion) {
    let mut group = c.benchmark_group("git_prefix");
    for (size, digits) in [(20, 7), (20, 8), (20, 40), (32, 7), (32, 64)] {
        let src: Vec<_> = (0..size).map(|i| (i * 31 + 3) as u8).collect();
        let full = hex::encode(&src);
        let expected = &full[..digits];
        let label = format!("{size}b_{digits}digits");
        let mut buf = [0xff; 64];
        let dst = &mut buf[..digits];
        assert_eq!(prefix::to_buf(&src, digits, dst), expected);
        group.bench_function(BenchmarkId::new("buffer", &label), |b| {
            b.iter(|| {
                black_box(prefix::to_buf(
                    black_box(&src),
                    black_box(digits),
                    black_box(dst),
                ));
            });
        });
        let mut output = String::with_capacity(64);
        group.bench_function(BenchmarkId::new("display", &label), |b| {
            b.iter(|| {
                output.clear();
                write!(
                    output,
                    "{}",
                    Abbreviation(black_box(&src), black_box(digits))
                )
                .unwrap();
                black_box(output.as_str());
            });
            assert_eq!(output, expected);
        });
    }
}

criterion_group!(benches, git_prefix);
criterion_main!(benches);
