use gix_hash::{ObjectId, Prefix};
use std::{hint::black_box, time::Instant};

fn run(
    prefixes: &[Prefix],
    expected: &str,
    count: usize,
    render: impl for<'a> Fn(&Prefix, &'a mut [u8]) -> &'a mut str,
) -> f64 {
    let mut out = [0xcd; 64];
    for prefix in prefixes {
        out.fill(0xcd);
        let len = prefix.hex_len();
        assert_eq!(render(prefix, &mut out), &expected[..len]);
        assert!(out[len..].iter().all(|&byte| byte == 0xcd));
    }

    let start = Instant::now();
    if let [prefix] = prefixes {
        for _ in 0..count {
            black_box(render(black_box(prefix), black_box(&mut out)));
        }
    } else {
        assert_eq!(prefixes.len(), 8);
        for i in 0..count {
            black_box(render(black_box(&prefixes[i & 7]), black_box(&mut out)));
        }
    }
    start.elapsed().as_nanos() as f64 / count as f64
}

fn main() {
    let mut args = std::env::args().skip(1);
    let digits: usize = args.next().unwrap().parse().unwrap();
    let count: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let (kind, method) = mode.split_once('-').unwrap();
    let size = match kind { "sha1" => 20, "sha256" => 32, _ => unreachable!() };
    let bytes: Vec<u8> = (0..size).map(|i| (37*i+11) as u8).collect();
    let oid = ObjectId::from_bytes_or_panic(&bytes);
    let lengths = if digits == 0 { vec![4,7,8,12,2*size-1,2*size,9,16] } else {vec![digits]};
    let prefixes: Vec<_> = lengths.iter().map(|&len| Prefix::new(oid.as_ref(),len).unwrap()).collect();
    let expected: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut result = 0.0;
    for n in [(count/6).max(16), count] {
        assert_eq!(method, "adopt");
        result = run(&prefixes, &expected, n, Prefix::hex_to_buf);
        black_box(result);
    }
    println!("{result:.6}");
}
