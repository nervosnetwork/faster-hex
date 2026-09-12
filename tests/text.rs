use faster_hex::{hex_decode, hex_decode_array, hex_encode, hex_encode_upper, Hex};

const TEXT: &[u8] = b"Day before yesterday I saw a rabbit,";
const ENCODED: &str = "446179206265666f7265207965737465726461792049207361772061207261626269742c";

#[test]
fn text_roundtrip() {
    let mut encoded = [0xff; TEXT.len() * 2 + 7];
    assert_eq!(hex_encode(TEXT, &mut encoded).unwrap(), ENCODED);
    assert_eq!(&encoded[TEXT.len() * 2..], &[0xff; 7]);
    assert_eq!(
        &*hex_encode_upper(TEXT, &mut encoded).unwrap(),
        ENCODED.to_ascii_uppercase()
    );
    assert_eq!(&encoded[TEXT.len() * 2..], &[0xff; 7]);

    let mut decoded = [0xa5; TEXT.len() + 7];
    assert_eq!(hex_decode(ENCODED.as_bytes(), &mut decoded).unwrap(), TEXT);
    assert_eq!(&decoded[TEXT.len()..], &[0xa5; 7]);
    assert_eq!(
        &hex_decode_array::<{ TEXT.len() }>(ENCODED.as_bytes()).unwrap(),
        TEXT
    );
    assert_eq!(format!("{}", Hex::new(TEXT)), ENCODED);
    #[cfg(feature = "alloc")]
    assert_eq!(
        faster_hex::hex_decode_vec(ENCODED.as_bytes()).unwrap(),
        TEXT
    );
}

#[cfg(feature = "serde")]
#[test]
fn text_roundtrip_with_serialization() {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Message(#[serde(with = "faster_hex::array")] [u8; TEXT.len()]);

    let mut bytes = [0; TEXT.len()];
    bytes.copy_from_slice(TEXT);
    let value = Message(bytes);
    let json = format!("\"0x{ENCODED}\"");
    assert_eq!(serde_json::to_string(&value).unwrap(), json);
    assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), value);
    let escaped = json.replace('4', "\\u0034");
    assert_eq!(serde_json::from_str::<Message>(&escaped).unwrap(), value);
    let mut storage = [0; 256];
    let binary = postcard::to_slice(&value, &mut storage).unwrap();
    assert_eq!(postcard::from_bytes::<Message>(binary).unwrap(), value);
}
