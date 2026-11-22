use std::{hint::black_box, time::Instant};

fn material(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes.iter().flat_map(|&b| [DIGITS[(b >> 4) as usize], DIGITS[(b & 15) as usize]]).collect()
}
fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let rounds: usize = args.next().unwrap().parse().unwrap();
    for len in 0..=130 {
        let expected: Vec<u8> = (0..len).map(|i| (37*i+11) as u8).collect();
        let mut text = material(&expected);
        let mut dst = vec![0x5a;len+7];
        assert_eq!(faster_hex::hex_decode(&text,&mut dst).unwrap(), &expected);
        assert!(dst[len..].iter().all(|&v|v==0x5a));
        if len > 0 {
            for i in [0, len, 2*len-1] {
                let previous = std::mem::replace(&mut text[i], 0xff);
                dst.fill(0x5a);
                assert!(matches!(faster_hex::hex_decode(&text,&mut dst),
                         Err(faster_hex::Error::InvalidChar{index,byte:0xff,..}) if index == i));
                assert!(dst.iter().all(|&v| v==0x5a));
                text[i]=previous;
            }
        }
    }
    let total = 32*1024*1024;
    let bytes:Vec<u8>=(0..total).map(|i|(i*37+11) as u8).collect();
    let input = material(&bytes);
    let mut dst = vec![0;total];
    assert_eq!(total%n,0);
    let mut elapsed=0;
    for step in 0..=rounds {
        let start=Instant::now();
        for (src, out) in input.chunks_exact(2*n).zip(dst.chunks_exact_mut(n)) {
            faster_hex::hex_decode(black_box(src),black_box(out)).unwrap();
        }
        black_box(&dst);
        let span = start.elapsed().as_nanos();
        if step>0 {elapsed+=span}
    }
    assert_eq!(dst,bytes);
    println!("{:.6}",elapsed as f64 / (total/n*rounds) as f64);
}
