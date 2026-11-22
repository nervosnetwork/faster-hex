use bytes::Bytes;
use ckb_jsonrpc_types::{JsonBytes, release_bytes};
use std::{hint::black_box, time::Instant};

type Read = fn(&[u8]) -> Bytes;
type Write = fn(Bytes, &mut Vec<u8>);

#[inline(never)]
fn read_old(src: &[u8]) -> Bytes {
    serde_json::from_slice::<release_bytes::JsonBytes>(src).unwrap().into_bytes()
}
#[inline(never)]
fn read_new(src: &[u8]) -> Bytes {
    serde_json::from_slice::<JsonBytes>(src).unwrap().into_bytes()
}
#[inline(never)]
fn write_old(bytes: Bytes, dst: &mut Vec<u8>) {
    serde_json::to_writer(dst, &release_bytes::JsonBytes::from_bytes(bytes)).unwrap()
}
#[inline(never)]
fn write_new(bytes: Bytes, dst: &mut Vec<u8>) {
    serde_json::to_writer(dst, &JsonBytes::from_bytes(bytes)).unwrap()
}

#[inline(never)]
fn sample(read: Read, write: Write, src: &[u8], dst: &mut Vec<u8>, n: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..n {
        let bytes = read(black_box(src));
        dst.clear();
        write(bytes, dst);
        black_box(dst.as_slice());
    }
    start.elapsed().as_nanos() as f64 / n as f64
}
fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let loops: usize = args.next().unwrap().parse().unwrap();
    let paths = args.next().unwrap();
    let (read, write): (Read, Write) = match paths.as_str() {
        "oo" => (read_old, write_old),
        "on" => (read_old, write_new),
        "no" => (read_new, write_old),
        "nn" => (read_new, write_new),
        _ => unreachable!(),
    };
    let bytes: Vec<u8> = (0..n).map(|i| (37*i+11) as u8).collect();
    let text: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let expected = format!("\"0x{text}\"");
    let input = if mode == "escaped" { expected.replacen("0x", "\\u0030x", 1) } else { expected.clone() };
    let mut dst = Vec::with_capacity(expected.len());
    let parsed = read(input.as_bytes());
    assert_eq!(parsed.as_ref(), &bytes);
    write(parsed, &mut dst);
    assert_eq!(dst, expected.as_bytes());
    black_box(sample(read, write, input.as_bytes(), &mut dst, loops/8+1));
    println!("{:.6}",sample(read, write, input.as_bytes(), &mut dst, loops));
}
