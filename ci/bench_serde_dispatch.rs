// Both modes serialize the same Payload with the same downstream JSON writer.
// The first untimed round-trip initializes the selector for this process.
use serde::{Deserializer, Serializer};
use std::sync::LazyLock;

static HEAD: LazyLock<bool> =
    LazyLock::new(
        || match std::env::var("FASTER_HEX_BENCH_REVISION").as_deref() {
            Ok("base") => false,
            Ok("head") => true,
            _ => panic!("expected base or head"),
        },
    );

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if *HEAD {
        codec_head::serialize(bytes, serializer)
    } else {
        codec_base::serialize(bytes, serializer)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    if *HEAD {
        codec_head::deserialize(deserializer)
    } else {
        codec_base::deserialize(deserializer)
    }
}
