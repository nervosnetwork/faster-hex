use criterion::{black_box, criterion_group, criterion_main, Criterion};
use faster_hex::hex_string;
use rustc_hex::ToHex;

fn bench(c: &mut Criterion) {
    let s = "Day before yesterday I saw a rabbit, and yesterday a deer, and today, you.";

    c.bench_function("bench_rustc_hex", move |b| {
        b.iter(|| {
            let ret = s.as_bytes().to_hex();
            black_box(ret);
        })
    });

    c.bench_function("bench_hex", move |b| {
        b.iter(|| {
            let ret = hex::encode(s);
            black_box(ret);
        })
    });

    c.bench_function("bench_simd", move |b| {
        b.iter(|| {
            let ret = hex_string(s.as_bytes()).unwrap();
            black_box(ret);
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
