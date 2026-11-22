use std::{hint::black_box, time::Instant};

#[inline(never)]
fn sample<const VIEW: u8>(text: &[u8], dst: &mut Vec<u8>, rounds: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..rounds {
        let r = faster_hex::hex_decode_append(black_box(text), black_box(&mut *dst));
        match VIEW {
            0 => assert!(black_box(r).is_ok()),
            1 => {
                black_box(r.unwrap());
            }
            2 => assert!(r.is_ok()),
            _ => unreachable!(),
        }
        black_box(&*dst);
        dst.truncate(3);
    }
    start.elapsed().as_nanos() as f64 / rounds as f64
}

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let text = b"0F".repeat(n);
    let mut dst = Vec::with_capacity(n + 3);
    dst.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        faster_hex::hex_decode_append(&text, &mut dst).unwrap(),
        vec![15; n]
    );
    dst.truncate(3);
    let run = |dst: &mut Vec<u8>, count| match mode.as_str() {
        "opaque" => sample::<0>(&text, dst, count),
        "suffix" => sample::<1>(&text, dst, count),
        "status" => sample::<2>(&text, dst, count),
        _ => panic!("unknown result consumption"),
    };
    black_box(run(&mut dst, (rounds / 6).max(32)));
    println!("{:.6}", run(&mut dst, rounds));
    assert_eq!(dst, [1, 2, 3]);
}
