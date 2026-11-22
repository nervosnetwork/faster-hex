use faster_hex::Hex;
use std::{hint::black_box, time::Instant};
fn sample(src: &[u8], requested: usize, dst: &mut [u8], rounds: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..rounds {
        let text = Hex::new(black_box(src))
            .leading_digits(black_box(requested))
            .encode_to(black_box(&mut *dst))
            .unwrap();
        black_box(text);
    }
    start.elapsed().as_nanos() as f64 / rounds as f64
}
fn main() {
    let mut args = std::env::args().skip(1);
    let digits: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let input: Vec<u8> = (0..digits.div_ceil(2) + 5)
        .map(|i| (37 * i + 11) as u8)
        .collect();
    let want = input.iter().map(|v| format!("{v:02x}")).collect::<String>();
    let spare = match mode.as_str() {
        "exact" => 0,
        "spare" => 19,
        _ => unreachable!(),
    };
    let mut output = vec![0xcd; digits + spare];
    let written = Hex::new(&input)
        .leading_digits(digits)
        .encode_to(&mut output)
        .unwrap();
    assert_eq!(written, &want[..digits]);
    assert!(output[digits..].iter().all(|&x| x == 0xcd));
    black_box(sample(&input, digits, &mut output, (rounds / 6).max(32)));
    println!("{:.6}", sample(&input, digits, &mut output, rounds));
    assert_eq!(&output[..digits], &want.as_bytes()[..digits]);
    assert!(output[digits..].iter().all(|&x| x == 0xcd));
}
