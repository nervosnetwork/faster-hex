use std::{hint::black_box, time::Instant};
use faster_hex::Hex;

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    let hash: [u8; 32] = std::array::from_fn(|i| (37 * i + 11) as u8);
    let expected = hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let mut buf = [0u8; 64];
    assert_eq!(Hex::new(&hash).leading_digits(n).encode_to(&mut buf[..n]).unwrap(), &expected[..n]);
    let mut sample = |rounds| {
        let now = Instant::now();
        for _ in 0..rounds {
            let text = Hex::new(black_box(&hash)).leading_digits(black_box(n))
                .encode_to(black_box(&mut buf[..n])).unwrap();
            black_box(text);
        }
        now.elapsed().as_nanos() as f64 / rounds as f64
    };
    black_box(sample((rounds / 6).max(32)));
    println!("{:.6}", sample(rounds));
}
