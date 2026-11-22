use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, Visitor};
use std::{fmt, hint::black_box, time::Instant};

type Decode<T> = fn(&str, bool) -> T;

struct Field<T>(Decode<T>);
impl<'de, T> Visitor<'de> for Field<T> {
    type Value = T;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a hex string")
    }
    fn visit_borrowed_str<E: de::Error>(self, text: &'de str) -> Result<T, E> {
        Ok((self.0)(text, true))
    }
    fn visit_str<E: de::Error>(self, text: &str) -> Result<T, E> {
        Ok((self.0)(text, false))
    }
}
impl<'de, T> DeserializeSeed<'de> for Field<T> {
    type Value = T;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<T, D::Error> {
        d.deserialize_string(self)
    }
}
struct Payload<T>(Field<T>);
impl<'de, T> Visitor<'de> for Payload<T> {
    type Value = T;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a one-field object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<T, M::Error> {
        if m.next_key::<IgnoredAny>()?.is_none() {
            return Err(de::Error::missing_field("bytes"));
        }
        let value = m.next_value_seed(self.0)?;
        if m.next_key::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom("unexpected second key"));
        }
        Ok(value)
    }
}
#[inline(never)]
fn shared_decode<T>(input: &[u8], stream: bool, decode: Decode<T>) -> T {
    let visitor = Payload(Field(black_box(decode)));
    if stream {
        let mut de = serde_json::Deserializer::from_reader(input);
        let value = de.deserialize_struct("Field", &["bytes"], visitor).unwrap();
        de.end().unwrap();
        value
    } else {
        let mut de = serde_json::Deserializer::from_slice(input);
        let value = de.deserialize_struct("Field", &["bytes"], visitor).unwrap();
        de.end().unwrap();
        value
    }
}
macro_rules! codec {
    ($func:ident,$ty:ty,$adapter:path) => {
        #[inline(never)]
        fn $func(text: &str, borrowed: bool) -> $ty {
            use de::value::{BorrowedStrDeserializer, Error, StrDeserializer};
            if borrowed {
                $adapter(BorrowedStrDeserializer::<Error>::new(text)).unwrap()
            } else {
                $adapter(StrDeserializer::<Error>::new(text)).unwrap()
            }
        }
    };
}
codec!(l_vec, Vec<u8>, left::deserialize);
codec!(r_vec, Vec<u8>, right::deserialize);
codec!(l_fixed, [u8; 4096], left::array::deserialize);
codec!(r_fixed, [u8; 4096], right::array::deserialize);
fn run<T: AsRef<[u8]>>(readers: [Decode<T>; 2], kind: &str, n: usize, cycles: usize) {
    let bytes: Vec<u8> = (0..4096).map(|i| (37 * i + 11) as u8).collect();
    let digits = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if i % 3 == 0 {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect::<String>();
    let text = format!("0x{digits}");
    let prefix = if kind == "escaped" { r"\u0030x" } else { "0x" };
    let json = format!(r#"{{"bytes":"{prefix}{digits}"}}"#);
    let stream = kind == "reader";
    let borrowed = kind == "plain";
    for decode in readers {
        assert_eq!(
            shared_decode(json.as_bytes(), stream, decode).as_ref(),
            bytes
        );
        assert_eq!(decode(&text, borrowed).as_ref(), bytes);
    }
    let mut seed = 0xf735fa1b37b47_u64;
    for k in 0..=cycles {
        let mut order = [0, 1, 2, 3, 4, 5];
        for i in (1..order.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            order.swap(i, seed as usize % (i + 1));
        }
        let mut row = [0.; 6];
        for &i in order.iter().chain(order.iter().rev()) {
            let decode = black_box(readers[usize::from(i % 3 == 1)]);
            let start = Instant::now();
            let count = if i < 3 { n } else { n * 4 };
            if i < 3 {
                for _ in 0..count {
                    black_box(shared_decode(black_box(json.as_bytes()), stream, decode));
                }
            } else {
                for _ in 0..count {
                    black_box(decode(black_box(text.as_str()), borrowed));
                }
            }
            row[i] += start.elapsed().as_nanos() as f64 / (2 * count) as f64;
        }
        if k != 0 {
            println!("{}", row.map(|v| format!("{v:.6}")).join(" "));
        }
    }
}
fn main() {
    let a: Vec<_> = std::env::args().collect();
    let n = a[3].parse().unwrap();
    let k = a[4].parse().unwrap();
    match a[1].as_str() {
        "vec" => run([l_vec, r_vec], &a[2], n, k),
        "array" => run([l_fixed, r_fixed], &a[2], n, k),
        _ => unreachable!(),
    }
}
