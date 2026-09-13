//! Compare identical formatted output using preallocated destination storage.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use faster_hex::{hex_string, Hex};
use std::fmt::Write;
use std::hint::black_box;

mod support;

fn formatting(c: &mut Criterion) {
    let mut group = c.benchmark_group("format");
    for len in [
        0,
        1,
        4,
        7,
        8,
        10,
        15,
        16,
        32,
        64,
        support::TEXT.len(),
        128,
        129,
        255,
        256,
        257,
        4096,
    ] {
        let input = if len == support::TEXT.len() {
            support::TEXT.to_vec()
        } else {
            support::bytes(len)
        };
        let expected = hex::encode(&input);
        let mut output = String::with_capacity(len * 2 + 32);
        assert_eq!(format!("{}", Hex::new(&input)), expected);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_function(BenchmarkId::new("borrowed", len), |b| {
            b.iter(|| {
                output.clear();
                write!(output, "{}", Hex::new(black_box(&input))).unwrap();
                black_box(output.as_bytes());
            });
            assert_eq!(output, expected);
        });
        group.bench_function(BenchmarkId::new("allocated_string", len), |b| {
            b.iter(|| {
                output.clear();
                write!(output, "{}", hex_string(black_box(&input))).unwrap();
                black_box(output.as_bytes());
            });
            assert_eq!(output, expected);
        });
        group.bench_function(BenchmarkId::new("per_byte", len), |b| {
            b.iter(|| {
                output.clear();
                for byte in black_box(&input) {
                    write!(output, "{byte:02x}").unwrap();
                }
                black_box(output.as_bytes());
            });
            assert_eq!(output, expected);
        });
        let padded = format!("+0x00000000{}", expected.to_ascii_uppercase());
        let width = padded.len();
        group.bench_function(BenchmarkId::new("padded_upper", len), |b| {
            b.iter(|| {
                output.clear();
                write!(output, "{:+#0width$X}", Hex::new(black_box(&input))).unwrap();
                black_box(output.as_bytes());
            });
            assert_eq!(output, padded);
        });
    }
    group.finish();
}

criterion_group!(benches, formatting);
criterion_main!(benches);
