use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde::{Deserialize, Serialize};
use std::hint::black_box;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Payload {
    #[serde(with = "faster_hex")]
    bytes: Vec<u8>,
}

fn serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("serde_json");
    for len in [0, 10, 32, 64, 65, 256, 4096] {
        let input = Payload {
            bytes: (0..len).map(|i| (i * 37 + 11) as u8).collect(),
        };
        let json = format!(r#"{{"bytes":"0x{}"}}"#, hex::encode(&input.bytes));
        assert_eq!(serde_json::to_string(&input).unwrap(), json);
        assert_eq!(serde_json::from_str::<Payload>(&json).unwrap(), input);
        let escaped = json.replace('a', "\\u0061");
        assert_eq!(serde_json::from_str::<Payload>(&escaped).unwrap(), input);
        group.bench_with_input(BenchmarkId::new("serialize", len), &input, |b, input| {
            b.iter(|| black_box(serde_json::to_string(black_box(input)).unwrap()));
        });
        let mut output = Vec::with_capacity(json.len());
        group.bench_function(BenchmarkId::new("serialize_reuse", len), |b| {
            b.iter(|| {
                output.clear();
                serde_json::to_writer(&mut output, black_box(&input)).unwrap();
                black_box(output.as_slice());
            });
            assert_eq!(output, json.as_bytes());
        });
        for (name, source) in [("deserialize", &json), ("deserialize_escaped", &escaped)] {
            group.bench_with_input(BenchmarkId::new(name, len), source, |b, source| {
                b.iter(|| black_box(serde_json::from_str::<Payload>(black_box(source)).unwrap()));
            });
        }
    }
    group.finish();
}

fn postcard(c: &mut Criterion) {
    let mut group = c.benchmark_group("serde_postcard");
    for len in [0, 32, 64, 65, 256, 4096] {
        let input = Payload {
            bytes: (0..len).map(|i| (i * 37 + 11) as u8).collect(),
        };
        let mut output = vec![0; len * 2 + 32];
        let encoded = postcard::to_slice(&input, &mut output).unwrap();
        assert_eq!(postcard::from_bytes::<Payload>(encoded).unwrap(), input);
        group.bench_function(BenchmarkId::new("serialize_reuse", len), |b| {
            b.iter(|| {
                black_box(postcard::to_slice(black_box(&input), black_box(&mut output)).unwrap());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, serde, postcard);
criterion_main!(benches);
