#![no_main]
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Payload {
    #[serde(with = "faster_hex")]
    bytes: Vec<u8>,
    #[serde(with = "faster_hex::option_nopfx_lowercase")]
    optional: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ArrayPayload {
    #[serde(with = "faster_hex::array")]
    bytes: [u8; 32],
    #[serde(with = "faster_hex::option_nopfx_uppercase::array")]
    optional: Option<[u8; 32]>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct BoundedPayload {
    #[serde(
        serialize_with = "faster_hex::serialize",
        deserialize_with = "faster_hex::deserialize_bounded::<64, _, _>"
    )]
    bytes: Vec<u8>,
    #[serde(
        serialize_with = "faster_hex::option_nopfx_lowercase::serialize",
        deserialize_with = "faster_hex::option_nopfx_lowercase::deserialize_bounded::<64, _, _>"
    )]
    optional: Option<Vec<u8>>,
}

fn roundtrip<T: Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug>(
    input: T,
) -> String {
    let json = serde_json::to_string(&input).unwrap();
    assert_eq!(serde_json::from_str::<T>(&json).unwrap(), input);
    // Escapes exercise owned deserializer strings as well as borrowed strings.
    let escaped = json.replace('a', "\\u0061");
    assert_eq!(serde_json::from_str::<T>(&escaped).unwrap(), input);
    json
}

fuzz_target!(|data: &[u8]| {
    // Always reach valid serialization, including None and an empty Some.
    let input = Payload {
        bytes: data.to_vec(),
        optional: data
            .first()
            .filter(|b| **b & 1 == 0)
            .map(|_| data[1..].to_vec()),
    };
    let json = roundtrip(input);
    let bounded = serde_json::from_str::<BoundedPayload>(&json);
    if data.len() <= 64 {
        let bounded = bounded.unwrap();
        assert_eq!(bounded.bytes, data);
        roundtrip(bounded);
    } else {
        assert!(bounded.is_err());
    }
    let bytes = core::array::from_fn(|i| data.get(i).copied().unwrap_or(0));
    roundtrip(ArrayPayload {
        bytes,
        optional: data.first().filter(|b| **b & 1 == 0).map(|_| bytes),
    });

    // Arbitrary JSON, invalid hex, prefixes, odd lengths and unexpected types.
    if let Ok(parsed) = serde_json::from_slice::<Payload>(data) {
        roundtrip(parsed);
    }
    if let Ok(parsed) = serde_json::from_slice::<ArrayPayload>(data) {
        roundtrip(parsed);
    }
    if let Ok(parsed) = serde_json::from_slice::<BoundedPayload>(data) {
        assert!(parsed.bytes.len() <= 64);
        assert!(parsed
            .optional
            .as_ref()
            .is_none_or(|bytes| bytes.len() <= 64));
        roundtrip(parsed);
    }
});
