use criterion::{black_box, criterion_group, criterion_main, Criterion};
use faster_hex::{
    hex_decode, hex_decode_fallback, hex_decode_unchecked, hex_encode_fallback, hex_string,
};
use rustc_hex::{FromHex, ToHex};

fn bench(c: &mut Criterion) {
    let s = "Day before yesterday I saw a rabbit, and yesterday a deer, and today, you.";

    c.bench_function("bench_rustc_hex_encode", move |b| {
        b.iter(|| {
            let ret = s.as_bytes().to_hex();
            black_box(ret);
        })
    });

    c.bench_function("bench_hex_encode", move |b| {
        b.iter(|| {
            let ret = hex::encode(s);
            black_box(ret);
        })
    });

    c.bench_function("bench_faster_hex_encode", move |b| {
        b.iter(|| {
            let ret = hex_string(s.as_bytes()).unwrap();
            black_box(ret);
        })
    });

    c.bench_function("bench_faster_hex_encode_fallback", move |b| {
        b.iter(|| {
            let bytes = s.as_bytes();
            let mut buffer = vec![0; bytes.len() * 2];
            let ret = hex_encode_fallback(bytes, &mut buffer);
            black_box(ret);
        })
    });

    c.bench_function("bench_rustc_hex_decode", move |b| {
        let hex = s.as_bytes().to_hex();
        b.iter(|| {
            let ret: Vec<u8> = hex.from_hex().unwrap();
            black_box(ret);
        })
    });

    c.bench_function("bench_hex_decode", move |b| {
        let hex = s.as_bytes().to_hex();
        b.iter(|| {
            let ret: Vec<u8> = hex::decode(&hex).unwrap();
            black_box(ret);
        })
    });

    c.bench_function("bench_faster_hex_decode", move |b| {
        let hex = hex_string(s.as_bytes()).unwrap();
        let len = s.as_bytes().len();
        b.iter(|| {
            let mut dst = Vec::with_capacity(len);
            dst.resize(len, 0);
            let ret = hex_decode(hex.as_bytes(), &mut dst);
            black_box(ret);
        })
    });

    c.bench_function("bench_faster_hex_decode_unchecked", move |b| {
        let hex = hex_string(s.as_bytes()).unwrap();
        let len = s.as_bytes().len();
        b.iter(|| {
            let mut dst = Vec::with_capacity(len);
            dst.resize(len, 0);
            let ret = hex_decode_unchecked(hex.as_bytes(), &mut dst);
            black_box(ret);
        })
    });

    c.bench_function("bench_faster_hex_decode_fallback", move |b| {
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
