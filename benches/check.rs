use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use faster_hex::{hex_check, hex_check_with_case, hex_decode, CheckCase};
use std::hint::black_box;

mod support;

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
    for len in [1, 8, 16, 31, 32, 33, 64, 4096, 65536] {
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
            for (case_name, byte, case) in [
                ("lower", b'A', CheckCase::Lower),
                ("upper", b'a', CheckCase::Upper),
            ] {
                let mut source = vec![b'0'; len * 2];
                source[position] = byte;
                assert!(!hex_check_with_case(&source, case));
                group.bench_function(format!("case/{case_name}/{name}/{len}"), |b| {
                    b.iter(|| black_box(hex_check_with_case(black_box(&source), case)));
                });
            }
        }
        group.bench_function(format!("decode/odd/{len}"), |b| {
            b.iter(|| {
                black_box(
                    hex_decode(black_box(&valid[..valid.len() - 1]), black_box(&mut output))
                        .unwrap_err(),
                );
                black_box(&output);
            });
        });
        group.bench_function(format!("decode/short_dst/{len}"), |b| {
            b.iter(|| {
                black_box(
                    hex_decode(black_box(&valid), black_box(&mut output[..len - 1])).unwrap_err(),
                );
                black_box(&output);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, check);
criterion_main!(benches);
