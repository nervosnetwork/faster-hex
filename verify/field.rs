use criterion::{criterion_group, criterion_main, Criterion};
use serde::{de::value::{BorrowedStrDeserializer, Error, StrDeserializer}, Deserialize};
use std::hint::black_box;

#[derive(Deserialize)]
struct Optional(#[serde(with = "faster_hex::option_withpfx_ignorecase::array")] Option<[u8; 32]>);

fn fields(c: &mut Criterion) {
    let text = format!("0x{}", "aB".repeat(32));
    let json = format!("{text:?}");
    let mut g = c.benchmark_group("field");
    g.bench_function("borrowed_array/32", |b| b.iter(|| faster_hex::array::deserialize::<_, 32>(
        BorrowedStrDeserializer::<Error>::new(black_box(text.as_str()))).unwrap()));
    g.bench_function("transient_array/32", |b| b.iter(|| faster_hex::array::deserialize::<_, 32>(
        StrDeserializer::<Error>::new(black_box(text.as_str()))).unwrap()));
    g.bench_function("bounded_vec/32", |b| b.iter(|| faster_hex::deserialize_bounded::<32, _, Vec<u8>>(
        StrDeserializer::<Error>::new(black_box(text.as_str()))).unwrap()));
    g.bench_function("optional_array/32", |b| b.iter(|| serde_json::from_str::<Optional>(black_box(&json)).unwrap().0.unwrap()));
    macro_rules! array {
        ($n:literal) => {{
            let value = format!("0x{}", "aB".repeat($n));
            g.bench_function(concat!("borrowed_array/", stringify!($n)), |b| b.iter(|| {
                faster_hex::array::deserialize::<_, $n>(
                    BorrowedStrDeserializer::<Error>::new(black_box(value.as_str()))).unwrap()
            }));
        }};
    }
    array!(4);
    array!(20);
    array!(65);
    array!(256);
    array!(4096);
    g.bench_function("wrong_length_array/4096", |b| b.iter(|| {
        black_box(faster_hex::hex_decode_array::<4096>(black_box(b"00"))).unwrap_err()
    }));
    g.bench_function("wrong_length_field/4096", |b| b.iter(|| {
        black_box(faster_hex::array::deserialize::<_,4096>(BorrowedStrDeserializer::<Error>::new(black_box("0x00")))).unwrap_err()
    }));
    g.finish();
}

criterion_group!(benches, fields);
criterion_main!(benches);
