use serde::Serialize;
use std::{hint::black_box, time::Instant};

#[derive(Serialize)]
struct Old {
    #[serde(with = "codec_a")]
    bytes: Vec<u8>,
}
#[derive(Serialize)]
struct New {
    #[serde(with = "codec_b")]
    bytes: Vec<u8>,
}
#[inline(never)]
fn timed<P: Serialize>(payload: &P, output: &mut Vec<u8>, offset: usize, count: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..count {
        output.truncate(offset);
        serde_json::to_writer(&mut *output, black_box(payload)).unwrap();
        black_box(output.as_slice());
    }
    start.elapsed().as_nanos() as f64 / count as f64
}
fn measure(
    new: bool,
    data: Vec<u8>,
    output: &mut Vec<u8>,
    offset: usize,
    count: usize,
) -> (Vec<u8>, f64) {
    let ptr = data.as_ptr();
    let (data, t) = if new {
        let p = New { bytes: data };
        let t = timed(&p, output, offset, count);
        (p.bytes, t)
    } else {
        let p = Old { bytes: data };
        let t = timed(&p, output, offset, count);
        (p.bytes, t)
    };
    assert_eq!(ptr, data.as_ptr());
    (data, t)
}
fn main() {
    let old = timed::<Old> as *const ();
    let new = timed::<New> as *const ();
    eprintln!("same timed function address: {}", old == new);
    println!("len,source_offset,output_offset,round,base,head,base_control,head_control");
    for n in [10, 32, 65, 256, 4096] {
        let mut data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
        let mut output = Vec::with_capacity(2 * n + 256);
        let align = (64 - output.as_ptr() as usize % 64) % 64;
        let count = (160_000_usize * 32 / n).clamp(1800, 140_000);
        for offset in [0, 1, 7, 15, 16, 31, 48, 63] {
            let start = align + offset;
            output.resize(start, 0);
            (data, _) = measure(false, data, &mut output, start, 1);
            let gold = output[start..].to_vec();
            (data, _) = measure(true, data, &mut output, start, 1);
            assert_eq!(&output[start..], &gold);
            for round in 0..19 {
                let reverse = round % 2 == 1;
                let mut v = [0.0; 4];
                for (i, b) in [false, true, true, false].into_iter().enumerate() {
                    (data, v[i]) = measure(b ^ reverse, data, &mut output, start, count)
                }
                let [a, b, bb, aa] = if reverse { [v[1], v[0], v[3], v[2]] } else { v };
                if round > 0 {
                    println!(
                        "{n},{},{offset},{round},{a:.6},{b:.6},{aa:.6},{bb:.6}",
                        data.as_ptr() as usize % 64
                    )
                }
            }
        }
    }
}
