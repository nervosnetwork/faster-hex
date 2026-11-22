use faster_hex::Hex;
use std::{fmt::Write, hint::black_box, time::Instant};

fn measure(bytes: &[u8], expected: &str, count: usize, write: impl Fn(&mut String, &[u8])) -> f64 {
    let mut output = String::with_capacity(expected.len());
    write(&mut output, bytes);
    assert_eq!(output, expected);
    let started = Instant::now();
    for _ in 0..count {
        output.clear();
        write(&mut output, black_box(bytes));
        black_box(output.as_str());
    }
    started.elapsed().as_nanos() as f64 / count as f64
}

fn main() {
    let mut args = std::env::args().skip(1);
    let size: usize = args.next().unwrap().parse().unwrap();
    let count: usize = args.next().unwrap().parse().unwrap();
    let mode = args.next().unwrap();
    let bytes: Vec<_> = (0..size).map(|i| (i * 37 + 11) as u8).collect();
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let width = hex.len() + 11;
    let run = |count| match mode.as_str() {
        "display" => measure(&bytes, &hex, count, |out, b| write!(out, "{}", Hex::new(b)).unwrap()),
        "alternate" => measure(&bytes, &format!("0x{hex}"), count, |out, b| write!(out, "{:#x}", Hex::new(b)).unwrap()),
        "padded" => measure(&bytes, &format!("+0x00000000{}", hex.to_ascii_uppercase()), count, |out, b| write!(out, "{:+#0width$X}", Hex::new(b)).unwrap()),
        _ => unreachable!()
    };
    black_box(run((count / 6).max(10)));
    println!("{:.6}", run(count));
}
