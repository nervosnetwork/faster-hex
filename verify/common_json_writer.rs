use serde::Deserialize;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[derive(serde::Serialize)]
struct Output<'a> {
    #[serde(serialize_with = "left::serialize")]
    bytes: &'a [u8],
}

#[inline(never)]
#[no_mangle]
fn common_json_writer(bytes: &[u8], output: &mut Vec<u8>) {
    output.clear();
    serde_json::to_writer(&mut *output, &Output { bytes }).unwrap();
    black_box(output.as_slice());
}

macro_rules! field {
    ($module:ident,$ty:ty,$l:literal,$r:literal) => {
        mod $module {
            use super::*;
            #[derive(Deserialize)]
            struct L {
                #[serde(with=$l)]
                bytes: $ty,
            }
            #[derive(Deserialize)]
            struct R {
                #[serde(with=$r)]
                bytes: $ty,
            }
            #[inline(never)]
            pub fn l_slice(json: &[u8]) -> $ty {
                serde_json::from_slice::<L>(json).unwrap().bytes
            }
            #[inline(never)]
            pub fn r_slice(json: &[u8]) -> $ty {
                serde_json::from_slice::<R>(json).unwrap().bytes
            }
            #[inline(never)]
            pub fn l_reader(json: &[u8]) -> $ty {
                serde_json::from_reader::<_, L>(json).unwrap().bytes
            }
            #[inline(never)]
            pub fn r_reader(json: &[u8]) -> $ty {
                serde_json::from_reader::<_, R>(json).unwrap().bytes
            }
        }
    };
}

field!(vecfield, Vec<u8>, "left", "right");
field!(arrayfield, [u8; 4096], "left::array", "right::array");

#[inline(never)]
fn measure<T: AsRef<[u8]>>(
    read: fn(&[u8]) -> T,
    input: &[u8],
    fixed: &[u8],
    output: &mut Vec<u8>,
    mode: usize,
    count: usize,
) -> f64 {
    let read = black_box(read);
    if mode == 3 {
        let start = Instant::now();
        for _ in 0..count {
            black_box(read(black_box(input)));
        }
        return start.elapsed().as_nanos() as f64 / count as f64;
    }
    if mode == 0 {
        // The original parse and write, using one writer for all readers.
        let start = Instant::now();
        for _ in 0..count {
            let value = read(black_box(input));
            common_json_writer(black_box(value.as_ref()), output);
        }
        return start.elapsed().as_nanos() as f64 / count as f64;
    }
    let mut elapsed = Duration::ZERO;
    for _ in 0..count {
        // Always parse and keep the returned value live through the write.
        let value = read(black_box(input));
        let parsed = black_box(value.as_ref());
        let bytes = if mode == 1 { parsed } else { fixed };
        // Only the write, from freshly decoded bytes or the same prebuilt allocation.
        let now = Instant::now();
        common_json_writer(black_box(bytes), output);
        elapsed += now.elapsed();
        black_box(&value);
    }
    elapsed.as_nanos() as f64 / count as f64
}

fn run<T: AsRef<[u8]>>(
    left: fn(&[u8]) -> T,
    right: fn(&[u8]) -> T,
    input: &[u8],
    expected: &[u8],
    count: usize,
    cycles: usize,
) {
    let mut output = Vec::with_capacity(input.len());
    let reference = serde_json::to_vec(&Output { bytes: expected }).unwrap();
    let pos = (expected.as_ptr(), output.as_ptr());
    for read in [left, right] {
        let got = read(input);
        assert_eq!(got.as_ref(), expected);
        common_json_writer(got.as_ref(), &mut output);
        assert_eq!(output, reference);
    }
    let mut rnd = as_seed(input);
    for turn in 0..=cycles {
        let mut seq = core::array::from_fn::<_, 12, _>(|i| i);
        for i in (1..seq.len()).rev() {
            rnd ^= rnd << 13;
            rnd ^= rnd >> 7;
            rnd ^= rnd << 17;
            seq.swap(i, rnd as usize % (i + 1));
        }
        let mut row = [0.0; 12];
        for &i in seq.iter().chain(seq.iter().rev()) {
            let read = if i % 3 == 1 { right } else { left };
            row[i] += measure(read, input, expected, &mut output, i / 3, count) * 0.5;
        }
        assert_eq!(pos, (expected.as_ptr(), output.as_ptr()));
        assert_eq!(output, reference);
        if turn > 0 {
            println!("{}", row.map(|t| format!("{t:.6}")).join(" "));
        }
    }
}
fn as_seed(input: &[u8]) -> u64 {
    0x7643_efed_67a4_d937 ^ input.len() as u64
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let dest = &args[1];
    let mode = &args[2];
    let count = args[3].parse().unwrap();
    let cycles = args[4].parse().unwrap();
    let bytes: Vec<_> = (0..4096).map(|i| (37 * i + 11) as u8).collect();
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
    let prefix = if mode == "escaped" { r"\u0030x" } else { "0x" };
    let json = format!(r#"{{"bytes":"{prefix}{digits}"}}"#);
    macro_rules! check {
        ($m:ident) => {{
            let (a, b): (fn(&[u8]) -> _, fn(&[u8]) -> _) = if mode == "reader" {
                ($m::l_reader, $m::r_reader)
            } else {
                ($m::l_slice, $m::r_slice)
            };
            run(a, b, json.as_bytes(), &bytes, count, cycles);
        }};
    }
    match dest.as_str() {
        "vec" => check!(vecfield),
        "array" => check!(arrayfield),
        _ => unreachable!(),
    }
}
