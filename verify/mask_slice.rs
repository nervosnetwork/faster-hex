use faster_hex::{hex_decode_with_case, CheckCase, Error};
use std::{hint::black_box, time::Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let iterations: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let (policy, position) = mode.split_once('-').unwrap();
    let (case, good, bad) = match policy {
        "lower" => (CheckCase::Lower, b'a', b'A'),
        "upper" => (CheckCase::Upper, b'A', b'a'),
        "mixed" => (CheckCase::None, b'A', b'!'),
        _ => unreachable!(),
    };
    let mut input = vec![good; n * 2];
    let mut output = vec![0xa5; n + 8];
    let bad_at = match position {
        "first" => Some(0),
        "last" => Some(2*n-1),
        "both" => { input[2*n-1]=0xff; Some(n-1) },
        "valid" => None,
        _ => unreachable!(),
    };
    if let Some(at)=bad_at { input[at]=bad; }
    let got = hex_decode_with_case(&input,&mut output[1..],case);
    if let Some(at)=bad_at {
        assert!(matches!(got, Err(Error::InvalidChar{index,byte,..}) if index==at && byte==bad));
        assert!(output.iter().all(|&b| b==0xa5));
    } else {
        assert_eq!(got.unwrap(),vec![0xaa;n]);
        assert!(output[1+n..].iter().all(|&b|b==0xa5) && output[0]==0xa5);
    }
    let mut sample = |k:usize| {
        let start=Instant::now();
        for _ in 0..k {
            let result=hex_decode_with_case(black_box(&input),black_box(&mut output[1..]),black_box(case));
            assert_eq!(black_box(result).is_err(),bad_at.is_some());
        }
        start.elapsed().as_nanos() as f64 / k as f64
    };
    black_box(sample((iterations/6).max(32)));
    println!("{:.6}",sample(iterations));
}
