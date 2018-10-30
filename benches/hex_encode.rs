#[macro_use]
extern crate criterion;
extern crate faster_hex;
extern crate hex;
extern crate rustc_hex;

use criterion::Criterion;
use faster_hex::hex_string;
use rustc_hex::ToHex;

fn bench(c: &mut Criterion) {
    let s = "Day before yesterday I saw a rabbit, and yesterday a deer, and today, you.";

    c.bench_function("bench_rustc_hex", move |b| {
        b.iter(|| {
            s.as_bytes().to_hex();
        })
    });

    c.bench_function("bench_hex", move |b| {
        b.iter(|| {
            hex::encode(s);
        })
    });

    c.bench_function("bench_simd", move |b| {
        b.iter(|| {
            hex_string(s.as_bytes()).unwrap();
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
