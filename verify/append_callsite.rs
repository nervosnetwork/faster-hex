use std::{hint::black_box, time::Instant};

type Append = for<'s, 'd> fn(&'s [u8], &'d mut Vec<u8>) -> Result<&'d mut [u8], faster_hex::Error>;

#[inline(never)]
fn caller_boundary<'d>(
    src: &[u8],
    dst: &'d mut Vec<u8>,
) -> Result<&'d mut [u8], faster_hex::Error> {
    faster_hex::hex_decode_append(src, dst)
}

#[inline(never)]
fn sample<F>(text: &[u8], dst: &mut Vec<u8>, rounds: usize, fail: bool, append: F) -> f64
where
    F: for<'s, 'd> Fn(&'s [u8], &'d mut Vec<u8>) -> Result<&'d mut [u8], faster_hex::Error>,
{
    let start = Instant::now();
    for _ in 0..rounds {
        let result = append(black_box(text), black_box(&mut *dst));
        assert_eq!(black_box(result).is_err(), fail);
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
    let (kind, outcome) = mode.split_once('-').unwrap();
    let fail = outcome == "rollback";
    let mut text = b"0F".repeat(n);
    if fail {
        *text.last_mut().unwrap() = b'!';
    }
    let mut dst = Vec::with_capacity(3 + n);
    dst.extend_from_slice(&[1, 2, 3]);
    let ptr: Append = match kind {
        "direct" | "api" => faster_hex::hex_decode_append,
        "wrapper" => caller_boundary,
        _ => panic!("unknown call style"),
    };
    let got = ptr(&text, &mut dst);
    if fail {
        assert!(
            matches!(got, Err(faster_hex::Error::InvalidChar { index, byte: b'!', .. }) if index == 2*n-1)
        );
        assert_eq!(dst, [1, 2, 3]);
    } else {
        assert_eq!(got.unwrap(), vec![15; n]);
    }
    dst.truncate(3);
    let run = |dst: &mut Vec<u8>, count| match kind {
        "direct" => sample(&text, dst, count, fail, faster_hex::hex_decode_append),
        _ => sample(&text, dst, count, fail, black_box(ptr)),
    };
    black_box(run(&mut dst, (rounds / 6).max(32)));
    println!("{:.6}", run(&mut dst, rounds));
    assert_eq!(dst, [1, 2, 3]);
}
