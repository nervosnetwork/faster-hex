use std::{hint::black_box, time::Instant};

#[derive(serde::Deserialize, serde::Serialize)]
struct Old {
    #[serde(with = "baseline")]
    bytes: Vec<u8>,
}
#[derive(serde::Deserialize, serde::Serialize)]
struct New {
    #[serde(with = "candidate")]
    bytes: Vec<u8>,
}

macro_rules! stages {
    ($read:ident, $write:ident, $full:ident, $value:ident) => {
        #[inline(never)]
        fn $read(text: &str) -> Vec<u8> {
            serde_json::from_str::<$value>(text).unwrap().bytes
        }

        #[inline(never)]
        fn $write(bytes: Vec<u8>, dst: &mut Vec<u8>) {
            dst.clear();
            serde_json::to_writer(dst, &$value { bytes }).unwrap();
        }

        fn $full(text: &str, dst: &mut Vec<u8>) {
            let value: $value = serde_json::from_str(text).unwrap();
            dst.clear();
            serde_json::to_writer(dst, &value).unwrap();
        }
    };
}
stages!(old_read, old_write, old_full, Old);
stages!(new_read, new_write, new_full, New);

fn time<F: FnMut()>(count: usize, mut operation: F) -> f64 {
    let start = Instant::now();
    for _ in 0..count {
        operation();
    }
    start.elapsed().as_nanos() as f64 / count as f64
}

fn sample(mode: usize, input: &str, count: usize, dst: &mut Vec<u8>, old: &Old, new: &New) -> f64 {
    match mode {
        0 | 6 => time(count, || {
            old_full(black_box(input), dst);
            black_box(dst.as_slice());
        }),
        1 | 7 => time(count, || {
            new_full(black_box(input), dst);
            black_box(dst.as_slice());
        }),
        2 => time(count, || {
            old_write(old_read(black_box(input)), dst);
            black_box(dst.as_slice());
        }),
        3 => time(count, || {
            old_write(new_read(black_box(input)), dst);
            black_box(dst.as_slice());
        }),
        4 => time(count, || {
            new_write(old_read(black_box(input)), dst);
            black_box(dst.as_slice());
        }),
        5 => time(count, || {
            new_write(new_read(black_box(input)), dst);
            black_box(dst.as_slice());
        }),
        8 => time(count, || {
            black_box(old_read(black_box(input)));
        }),
        9 => time(count, || {
            black_box(new_read(black_box(input)));
        }),
        10 => time(count, || {
            dst.clear();
            serde_json::to_writer(&mut *dst, black_box(old)).unwrap();
            black_box(dst.as_slice());
        }),
        11 => time(count, || {
            dst.clear();
            serde_json::to_writer(&mut *dst, black_box(new)).unwrap();
            black_box(dst.as_slice());
        }),
        _ => unreachable!(),
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let len: usize = args[0].parse().unwrap();
    let count: usize = args[1].parse().unwrap();
    let cycles: usize = args[2].parse().unwrap();
    let bytes: Vec<_> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
    let digits: String = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if i % 3 == 0 {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect();
    let prefix = if args[3] == "escaped" {
        r"\u0030x"
    } else {
        "0x"
    };
    let input = format!(r#"{{"bytes":"{prefix}{digits}"}}"#);
    let old = Old {
        bytes: bytes.clone(),
    };
    let new = New {
        bytes: bytes.clone(),
    };
    let expected = serde_json::to_vec(&old).unwrap();
    assert_eq!(serde_json::to_vec(&new).unwrap(), expected);
    assert_eq!(old_read(&input), bytes);
    assert_eq!(new_read(&input), bytes);
    let mut dst = vec![0; len * 2 + 32];
    for mode in 0..12 {
        sample(mode, &input, (count / 8).max(1), &mut dst, &old, &new);
        if mode != 8 && mode != 9 {
            assert_eq!(dst, expected);
        }
    }
    let mut state = 0x89ad_7543_dc98_b6f1_u64;
    for _ in 0..cycles {
        let mut order = core::array::from_fn::<_, 12, _>(|i| i);
        for i in (1..order.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            order.swap(i, state as usize % (i + 1));
        }
        let mut row = [0.0; 12];
        for &mode in order.iter().chain(order.iter().rev()) {
            row[mode] += sample(mode, &input, count, &mut dst, &old, &new) / 2.0;
        }
        println!("{}", row.map(|v| format!("{v:.6}")).join(" "));
    }
}
