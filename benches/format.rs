//! Compare identical formatted output using preallocated destination storage.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use faster_hex::{hex_string, Hex};
use std::fmt::Write;
use std::hint::black_box;

mod support;

fn formatting(c: &mut Criterion) {
    let mut group = c.benchmark_group("format");
    for &len in support::LENGTHS {
        if len > 4096 {
            continue;
        }
        let input = support::bytes(len);
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
        let prefixed = format!("0x{expected}");
        group.bench_function(BenchmarkId::new("alternate", len), |b| {
            b.iter(|| {
                output.clear();
                write!(output, "{:#x}", Hex::new(black_box(&input))).unwrap();
                black_box(output.as_bytes());
            });
            assert_eq!(output, prefixed);
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

fn leading_digits(c: &mut Criterion) {
    let hash = support::bytes(32);
    let full = hex::encode(&hash);
    let mut group = c.benchmark_group("prefix");
    for digits in [7, 8, 12] {
        let mut dst = vec![0; digits];
        group.bench_function(BenchmarkId::new("buffer", digits), |b| {
            b.iter(|| {
                let view = Hex::new(black_box(&hash)).leading_digits(black_box(digits));
                black_box(view.encode_to(black_box(dst.as_mut_slice())).unwrap());
            });
            assert_eq!(dst, &full.as_bytes()[..digits]);
        });
        let mut text = String::with_capacity(digits);
        group.bench_function(BenchmarkId::new("display", digits), |b| {
            b.iter(|| {
                text.clear();
                let view = Hex::new(black_box(&hash)).leading_digits(black_box(digits));
                write!(text, "{view}").unwrap();
                black_box(text.as_str());
            });
            assert_eq!(text, full[..digits]);
        });
    }
    group.finish();
}

criterion_group!(benches, formatting, leading_digits);
criterion_main!(benches);
