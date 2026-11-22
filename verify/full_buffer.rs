use std::{hint::black_box, time::Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    let src: Vec<_> = (0..n).map(|i| (37*i+11) as u8).collect();
    let mut buf = vec![0; 2*n];
    let expected = src.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(faster_hex::hex_encode(&src, &mut buf).unwrap(), expected.as_str());
    let mut sample = |count| {
        let start = Instant::now();
        for _ in 0..count {
            let result = faster_hex::hex_encode(black_box(&src), black_box(&mut buf)).unwrap();
            black_box(result);
        }
        start.elapsed().as_nanos() as f64 / count as f64
    };
    black_box(sample((rounds / 6).max(32)));
    println!("{:.6}", sample(rounds));
}
