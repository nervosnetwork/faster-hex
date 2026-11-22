use std::{hint::black_box, time::Instant};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let n: usize = args[1].parse().unwrap();
    let count: usize = args[2].parse().unwrap();
    let mode = args[3].as_str();
    let src: Vec<_> = (0..n).map(|i| (37 * i + 11) as u8).collect();
    let prefix = mode.starts_with("tag-");
    let upper = mode.ends_with("upper");
    let digits: String = src
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect();
    let want = format!("\"{}{}\"", if prefix { "0x" } else { "" }, digits);
    let mut dst = Vec::with_capacity(want.len());
    let mut run = |rounds| {
        let start = Instant::now();
        for _ in 0..rounds {
            dst.clear();
            let mut ser = serde_json::Serializer::new(&mut dst);
            let bytes = black_box(&src);
            match (prefix, upper) {
                (true, true) => faster_hex::withpfx_uppercase::serialize(bytes, &mut ser),
                (true, false) => faster_hex::withpfx_lowercase::serialize(bytes, &mut ser),
                (false, true) => faster_hex::nopfx_uppercase::serialize(bytes, &mut ser),
                (false, false) => faster_hex::nopfx_lowercase::serialize(bytes, &mut ser),
            }
            .unwrap();
            black_box(dst.as_slice());
        }
        start.elapsed().as_nanos() as f64 / rounds as f64
    };
    black_box(run((count / 6).max(16)));
    println!("{:.6}", run(count));
    assert_eq!(dst, want.as_bytes());
}
