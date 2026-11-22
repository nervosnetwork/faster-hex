use std::{
    fmt::{self, Write},
    hint::black_box,
    time::Instant,
};
struct Reject {
    calls: usize,
}
impl Write for Reject {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.calls += 1;
        black_box(text.as_bytes());
        Err(fmt::Error)
    }
}
fn main() {
    let a: Vec<_> = std::env::args().collect();
    let n: usize = a[1].parse().unwrap();
    let count: usize = a[2].parse().unwrap();
    let src: Vec<_> = (0..n).map(|n| (37 * n + 11) as u8).collect();
    let mut sample = |iters| {
        let mut reject = Reject { calls: 0 };
        let start = Instant::now();
        for _ in 0..iters {
            let v = faster_hex::Hex::new(black_box(&src));
            let result = if a[3] == "both" {
                write!(reject, "{v:+#X}")
            } else {
                write!(reject, "{v:#x}")
            };
            assert!(black_box(result).is_err());
        }
        let ns = start.elapsed().as_nanos() as f64 / iters as f64;
        assert_eq!(reject.calls, iters);
        ns
    };
    black_box(sample((count / 6).max(16)));
    println!("{:.6}", sample(count));
}
