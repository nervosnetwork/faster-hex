use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use faster_hex::{
    hex_decode, hex_decode_fallback, hex_decode_unchecked, hex_decode_unchecked_fallback,
    hex_encode_fallback, hex_string,
};
use rustc_hex::{FromHex, ToHex};
use std::time::Duration;

const BYTE_SIZES: [usize; 5] = [2, 16, 32, 128, 4096];

fn rand_slice(size: usize) -> Vec<u8> {
    use rand::Rng;
    let mut input: Vec<u8> = vec![0; size];
    rand::thread_rng().fill(input.as_mut_slice());
    input
}

fn rand_hex_encoded(size: usize) -> String {
    use rand::seq::SliceRandom;
    String::from_utf8(
        std::iter::repeat(())
            .map(|_| *b"0123456789abcdef".choose(&mut rand::thread_rng()).unwrap())
            .take(size)
            .collect(),
    )
    .unwrap()
}

fn bench(c: &mut Criterion) {
    let mut encode_group = c.benchmark_group("encode");
    for size in &BYTE_SIZES[..] {
        encode_group.throughput(Throughput::Bytes(*size as u64));
        encode_group.bench_with_input(BenchmarkId::new("rustc", size), size, |b, &size| {
            let input = rand_slice(size);
            b.iter(|| {
                let ret = input.to_hex();
                black_box(ret);
            })
        });
        encode_group.bench_with_input(BenchmarkId::new("hex", size), size, |b, &size| {
            let input = rand_slice(size);
            b.iter(|| {
                let ret = hex::encode(&input);
                black_box(ret);
            })
        });
        encode_group.bench_with_input(BenchmarkId::new("faster_hex", size), size, |b, &size| {
            let input = rand_slice(size);
            b.iter(|| {
                let ret = hex_string(&input);
                black_box(ret);
            })
        });
        encode_group.bench_with_input(
            BenchmarkId::new("faster_hex_fallback", size),
            size,
            |b, &size| {
                let input = rand_slice(size);
                let mut buffer = vec![0; input.len() * 2];
                b.iter(|| {
                    let ret = hex_encode_fallback(&input, buffer.as_mut_slice());
                    black_box(ret);
                })
            },
        );
    }
    encode_group.finish();

    let mut decode_group = c.benchmark_group("decode");
    for size in &BYTE_SIZES[..] {
        decode_group.throughput(Throughput::Bytes(*size as u64));
        decode_group.bench_with_input(BenchmarkId::new("rustc", size), size, |b, &size| {
            let hex_input = rand_hex_encoded(size);
            b.iter(|| {
                let ret: Vec<u8> = hex_input.from_hex().unwrap();
                black_box(ret);
            })
        });
        decode_group.bench_with_input(BenchmarkId::new("hex", size), size, |b, &size| {
            let hex_input = rand_hex_encoded(size);
            b.iter(|| {
                let ret: Vec<u8> = hex::decode(&hex_input).unwrap();
                black_box(ret);
            })
        });
        decode_group.bench_with_input(BenchmarkId::new("faster_hex", size), size, |b, &size| {
            let hex_input = rand_hex_encoded(size);
            let mut dst = vec![0; size / 2];
            b.iter(|| {
                let ret = hex_decode(hex_input.as_bytes(), &mut dst).unwrap();
                black_box(ret);
            })
        });
        decode_group.bench_with_input(
            BenchmarkId::new("faster_hex_unchecked", size),
            size,
            |b, &size| {
                let hex_input = rand_hex_encoded(size);
                let mut dst = vec![0; size / 2];
                b.iter(|| {
                    let ret = hex_decode_unchecked(hex_input.as_bytes(), &mut dst);
                    black_box(ret);
                })
            },
        );
        decode_group.bench_with_input(
            BenchmarkId::new("faster_hex_fallback", size),
            size,
            |b, &size| {
                let hex_input = rand_hex_encoded(size);
                let mut dst = vec![0; size / 2];
                b.iter(|| {
                    let ret = hex_decode_fallback(hex_input.as_bytes(), &mut dst).unwrap();
                    black_box(ret);
                })
            },
        );
        decode_group.bench_with_input(
            BenchmarkId::new("faster_hex_unchecked_fallback", size),
            size,
            |b, &size| {
                let hex_input = rand_hex_encoded(size);
                let mut dst = vec![0; size / 2];
                b.iter(|| {
                    let ret = hex_decode_unchecked_fallback(hex_input.as_bytes(), &mut dst);
                    black_box(ret);
                })
            },
        );
    }
    decode_group.finish();
}

fn quicker() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = quicker();
    targets = bench
}
criterion_main!(benches);
