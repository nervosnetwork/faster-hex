use criterion::{black_box, criterion_group, criterion_main, Criterion};
use faster_hex::{hex_decode, hex_decode_fallback, hex_string};
use rustc_hex::{FromHex, ToHex};

fn bench(c: &mut Criterion) {
    let s = "Day before yesterday I saw a rabbit, and yesterday a deer, and today, you.";

    c.bench_function("bench_rustc_hex", move |b| {
        b.iter(|| {
            let ret = s.as_bytes().to_hex();
            black_box(ret);
        })
    });

    c.bench_function("bench_hex_hex", move |b| {
        b.iter(|| {
            let ret = hex::encode(s);
            black_box(ret);
        })
    });

    c.bench_function("bench_simd_hex", move |b| {
        b.iter(|| {
            let ret = hex_string(s.as_bytes()).unwrap();
            black_box(ret);
        })
    });

    c.bench_function("bench_rustc_unhex", move |b| {
        let hex = s.as_bytes().to_hex();
        b.iter(|| {
            let ret: Vec<u8> = hex.from_hex().unwrap();
            black_box(ret);
        })
    });

    c.bench_function("bench_simd_unhex", move |b| {
        let hex = hex_string(s.as_bytes()).unwrap();
        let len = s.as_bytes().len();
        b.iter(|| {
            let mut dst = Vec::with_capacity(len);
            dst.resize(len, 0);
            let ret = hex_decode(hex.as_bytes(), &mut dst);
            black_box(ret);
        })
    });

    c.bench_function("bench_simd_unhex_fallback", move |b| {
        let hex = hex_string(s.as_bytes()).unwrap();
        let len = s.as_bytes().len();
        b.iter(|| {
            let mut dst = Vec::with_capacity(len);
            dst.resize(len, 0);
            let ret = hex_decode_fallback(hex.as_bytes(), &mut dst);
            black_box(ret);
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
