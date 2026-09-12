//! Owned output includes its construction and destruction in the timed operation.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use faster_hex::{hex_decode, hex_decode_array, hex_decode_vec};
use std::hint::black_box;

mod support;

fn arrays<const N: usize>(c: &mut Criterion) {
    let input = support::bytes(N);
    let text = hex::encode(&input);
    assert_eq!(
        hex_decode_array::<N>(text.as_bytes()).unwrap().as_slice(),
        input
    );
    let mut group = c.benchmark_group("decode_array");
    group.throughput(Throughput::Bytes(N as u64));
    group.bench_function(BenchmarkId::new("faster_hex", N), |b| {
        b.iter(|| black_box(hex_decode_array::<N>(black_box(text.as_bytes())).unwrap()));
    });
    group.bench_function(BenchmarkId::new("manual_slice", N), |b| {
        b.iter(|| {
            let mut output = [0; N];
            hex_decode(black_box(text.as_bytes()), black_box(&mut output)).unwrap();
            black_box(output)
        });
    });
    group.bench_function(BenchmarkId::new("const_hex", N), |b| {
        b.iter(|| {
            let mut output = [0; N];
            const_hex::decode_to_slice(black_box(text.as_bytes()), black_box(&mut output)).unwrap();
            black_box(output)
        });
    });
    group.finish();
}

fn owned(c: &mut Criterion) {
    arrays::<0>(c);
    arrays::<16>(c);
    arrays::<32>(c);
    arrays::<64>(c);
    arrays::<128>(c);
    let mut group = c.benchmark_group("decode_vec");
    for len in [0, 1, 16, 32, 64, 256, 4096, 65536] {
        let input = support::bytes(len);
        let text = hex::encode(&input);
        assert_eq!(hex_decode_vec(text.as_bytes()).unwrap(), input);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_function(BenchmarkId::new("faster_hex", len), |b| {
            b.iter(|| black_box(hex_decode_vec(black_box(text.as_bytes())).unwrap()));
        });
        group.bench_function(BenchmarkId::new("manual_slice", len), |b| {
            b.iter(|| {
                let mut output = vec![0; len];
                hex_decode(black_box(text.as_bytes()), black_box(&mut output)).unwrap();
                black_box(output)
            });
        });
        group.bench_function(BenchmarkId::new("hex", len), |b| {
            b.iter(|| black_box(hex::decode(black_box(&text)).unwrap()));
        });
    }
    group.finish();

    // Report failures as latency, not throughput over bytes never decoded.
    let mut group = c.benchmark_group("owned_errors");
    for (name, source) in [
        ("odd", vec![b'g'; 63]),
        ("short", vec![b'0'; 62]),
        ("long", vec![b'0'; 66]),
        ("invalid_first", [&b"g0"[..], &[b'0'; 62]].concat()),
        ("invalid_last", [&[b'0'; 62][..], b"0g"].concat()),
    ] {
        assert!(hex_decode_array::<32>(&source).is_err());
        group.bench_function(format!("array/{name}"), |b| {
            b.iter(|| black_box(hex_decode_array::<32>(black_box(&source)).unwrap_err()));
        });
        if name != "short" && name != "long" {
            assert!(hex_decode_vec(&source).is_err());
            group.bench_function(format!("vec/{name}"), |b| {
                b.iter(|| black_box(hex_decode_vec(black_box(&source)).unwrap_err()));
            });
        }
    }
    group.finish();
}

criterion_group!(benches, owned);
criterion_main!(benches);
