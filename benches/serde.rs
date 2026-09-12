use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde::{Deserialize, Serialize};
use std::hint::black_box;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Payload {
    #[serde(with = "faster_hex")]
    bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct OptionalPayload {
    #[serde(with = "faster_hex::option_withpfx_ignorecase")]
    bytes: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct BoundedPayload {
    #[serde(deserialize_with = "faster_hex::deserialize_bounded::<64, _, _>")]
    bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ArrayPayload<const N: usize> {
    #[serde(with = "faster_hex::array")]
    bytes: [u8; N],
}

fn serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("serde_json");
    for len in [0, 8, 32, 63, 64, 65, 256, 4096] {
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
        group.bench_function(BenchmarkId::new("deserialize_reader", len), |b| {
            b.iter(|| {
                black_box(
                    serde_json::from_reader::<_, Payload>(black_box(json.as_bytes())).unwrap(),
                )
            });
        });
        if len <= 64 {
            assert_eq!(
                serde_json::from_str::<BoundedPayload>(&json).unwrap().bytes,
                input.bytes
            );
            group.bench_function(BenchmarkId::new("deserialize_bounded", len), |b| {
                b.iter(|| {
                    black_box(serde_json::from_str::<BoundedPayload>(black_box(&json)).unwrap())
                });
            });
        }
        group.bench_with_input(
            BenchmarkId::new("deserialize_option", len),
            &json,
            |b, source| {
                b.iter(|| {
                    black_box(serde_json::from_str::<OptionalPayload>(black_box(source)).unwrap())
                });
            },
        );
    }
    group.bench_function("deserialize_none", |b| {
        b.iter(|| {
            black_box(
                serde_json::from_str::<OptionalPayload>(black_box(r#"{"bytes":null}"#)).unwrap(),
            )
        });
    });
    group.finish();
}

fn arrays<const N: usize>(c: &mut Criterion) {
    let input = ArrayPayload {
        bytes: core::array::from_fn(|index| (index * 73) as u8),
    };
    let json = format!(r#"{{"bytes":"0x{}"}}"#, hex::encode(input.bytes));
    let escaped = json.replace('0', "\\u0030");
    assert_eq!(serde_json::to_string(&input).unwrap(), json);
    assert_eq!(
        serde_json::from_str::<ArrayPayload<N>>(&json).unwrap(),
        input
    );
    assert_eq!(
        serde_json::from_str::<ArrayPayload<N>>(&escaped).unwrap(),
        input
    );
    let mut group = c.benchmark_group("serde_array");
    group.bench_function(BenchmarkId::new("serialize", N), |b| {
        b.iter(|| black_box(serde_json::to_string(black_box(&input)).unwrap()));
    });
    for (name, text) in [("deserialize", &json), ("deserialize_escaped", &escaped)] {
        group.bench_function(BenchmarkId::new(name, N), |b| {
            b.iter(|| black_box(serde_json::from_str::<ArrayPayload<N>>(black_box(text)).unwrap()));
        });
    }
    group.finish();
}

fn policies(c: &mut Criterion) {
    arrays::<0>(c);
    arrays::<16>(c);
    arrays::<32>(c);
    arrays::<64>(c);
    arrays::<65>(c);
    let mut group = c.benchmark_group("serde_errors");
    for len in [65, 4096] {
        let json = format!(r#"{{"bytes":"0x{}"}}"#, "00".repeat(len));
        assert!(serde_json::from_str::<BoundedPayload>(&json).is_err());
        group.bench_function(BenchmarkId::new("over_limit", len), |b| {
            b.iter(|| {
                black_box(serde_json::from_str::<BoundedPayload>(black_box(&json)).unwrap_err())
            });
        });
    }
    for (name, text) in [
        ("prefix", "0Xgg".to_string()),
        ("odd", "0xg".to_string()),
        ("invalid_first", format!("0xg{}", "0".repeat(127))),
        ("invalid_last", format!("0x{}g", "0".repeat(127))),
    ] {
        let json = format!(r#"{{"bytes":"{text}"}}"#);
        assert!(serde_json::from_str::<BoundedPayload>(&json).is_err());
        group.bench_function(name, |b| {
            b.iter(|| {
                black_box(serde_json::from_str::<BoundedPayload>(black_box(&json)).unwrap_err())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, serde, policies);
criterion_main!(benches);
