use faster_hex::Hex;
use std::{
    fmt::{self, Write},
    hint::black_box,
    time::Instant,
};

struct Sink {
    bytes: Vec<u8>,
    written: usize,
    writes: usize,
}

impl Write for Sink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.written + s.len();
        self.bytes
            .get_mut(self.written..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.written = end;
        self.writes += 1;
        Ok(())
    }
}

enum Style {
    Display,
    Upper,
    Alternate,
    Both,
    SmallWidth,
    Zero,
    Unicode,
}

fn write_hex(out: &mut Sink, b: &[u8], mode: &Style, width: usize) {
    let value = Hex::new(b);
    match mode {
        Style::Display => write!(out, "{value}"),
        Style::Upper => write!(out, "{value:X}"),
        Style::Alternate => write!(out, "{value:#x}"),
        Style::Both => write!(out, "{value:+#X}"),
        Style::SmallWidth => write!(out, "{value:1x}"),
        Style::Zero => write!(out, "{value:+#0width$X}"),
        Style::Unicode => write!(out, "{value:🪐^+#width$.1x}"),
    }
    .unwrap();
}

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().unwrap().parse().unwrap();
    let count: usize = args.next().unwrap().parse().unwrap();
    let name = args.next().unwrap();
    let lower: String = (0..n)
        .map(|i| format!("{:02x}", (i * 37 + 11) as u8))
        .collect();
    let upper = lower.to_uppercase();
    let width = lower.len() + 11;
    let (mode, expected) = match name.as_str() {
        "display" => (Style::Display, lower),
        "upper" => (Style::Upper, upper),
        "alternate" => (Style::Alternate, format!("0x{lower}")),
        "both" => (Style::Both, format!("+0x{upper}")),
        "small-width" => (Style::SmallWidth, format!("{lower:>1}")),
        "zero" => (Style::Zero, format!("+0x00000000{upper}")),
        "unicode" => (Style::Unicode, format!("🪐🪐🪐🪐+0x{lower}🪐🪐🪐🪐")),
        _ => unreachable!(),
    };
    let input: Vec<_> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
    let mut out = Sink {
        bytes: vec![0xcd; expected.len() + 1],
        written: 0,
        writes: 0,
    };
    write_hex(&mut out, &input, &mode, width);
    assert_eq!(&out.bytes[..out.written], expected.as_bytes());
    assert_eq!(out.bytes[out.written], 0xcd);
    let calls = out.writes;
    let mut sample = |rounds| {
        let t = Instant::now();
        for _ in 0..rounds {
            out.written = 0;
            out.writes = 0;
            write_hex(&mut out, black_box(&input), &mode, width);
            black_box(&out.bytes[..out.written]);
            black_box(out.writes);
        }
        t.elapsed().as_nanos() as f64 / rounds as f64
    };
    black_box(sample((count / 6).max(16)));
    println!("{:.6}", sample(count));
    assert_eq!(&out.bytes[..out.written], expected.as_bytes());
    assert_eq!(out.writes, calls);
    assert_eq!(out.bytes[out.written], 0xcd);
}
