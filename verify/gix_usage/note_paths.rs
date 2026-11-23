use bstr::BStr;
use gix_hash::{oid, ObjectId};
use std::{hint::black_box, time::Instant};
fn note_path<'a>(id: &oid, fanout: usize, out: &'a mut [u8]) -> &'a BStr {
    let mut pos = 0;
    for offset in 0..fanout {
        let component = id.to_prefix(offset..offset + 1);
        pos += component.hex_to_buf(&mut out[pos..]).len();
        out[pos] = b'/';
        pos += 1;
    }
    let remainder = id.to_prefix(fanout..id.as_bytes().len());
    pos += remainder.hex_to_buf(&mut out[pos..]).len();
    BStr::new(&out[..pos])
}
fn main() {
    let mut args = std::env::args().skip(1);
    let fanout: usize = args.next().unwrap().parse().unwrap();
    let iterations: usize = args.next().unwrap().parse().unwrap();
    let width = match args.next().unwrap().as_str() { "sha1" => 20, "sha256" => 32, _ => unreachable!() };
    let raw: Vec<_> = (0..width).map(|i| (37 * i + 11) as u8).collect();
    let id = ObjectId::from_bytes_or_panic(&raw);
    let mut expected = String::new();
    for (i,byte) in raw.iter().enumerate() {
        use std::fmt::Write;
        write!(&mut expected, "{byte:02x}").unwrap();
        if i < fanout { expected.push('/'); }
    }
    let mut output = [0xcd; 96];
    assert_eq!(note_path(id.as_ref(),fanout,&mut output), BStr::new(expected.as_bytes()));
    assert!(output[expected.len()..].iter().all(|&b| b == 0xcd));
    let mut elapsed = 0.0;
    for count in [(iterations/6).max(16), iterations] {
        let start = Instant::now();
        for _ in 0..count {
            black_box(note_path(black_box(id.as_ref()),black_box(fanout),black_box(&mut output)));
        }
        elapsed=start.elapsed().as_nanos() as f64 / count as f64;
    }
    println!("{elapsed:.6}");
}
