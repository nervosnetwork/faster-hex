//! Count only the current test thread's allocations inside explicit measurement scopes.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

fn record_allocation() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(value) = count.get() {
            count.set(Some(value.saturating_add(1)));
        }
    });
}

struct CountingAllocator;

// SAFETY: All memory management is delegated unchanged to System. The counter
// uses a const-initialized thread-local Cell and does not allocate or retain pointers.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: The caller guarantees this allocation and new size are valid.
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller guarantees the pointer was allocated with this layout.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATIONS.with(|count| count.set(None));
        }
    }
    ALLOCATIONS.with(|count| {
        assert!(count.get().is_none());
        count.set(Some(0));
    });
    let reset = Reset;
    let output = operation();
    let count = ALLOCATIONS.with(|count| count.get().unwrap());
    drop(reset);
    (output, count)
}
use std::fmt::{self, Write};

struct Sink {
    text: String,
    calls: usize,
}
impl Write for Sink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.text.push_str(s);
        self.calls += 1;
        Ok(())
    }
}
fn main() {
    for n in [0, 20, 32, 65, 66, 67, 128, 129, 4096] {
        let src: Vec<_> = (0..n).map(|i| (37 * i + 11) as u8).collect();
        for tagged in [false, true] {
            for upper in [false, true] {
                let hex: String = src
                    .iter()
                    .map(|b| {
                        if upper {
                            format!("{b:02X}")
                        } else {
                            format!("{b:02x}")
                        }
                    })
                    .collect();
                let expected = format!("\"{}{}\"", if tagged { "0x" } else { "" }, hex);
                let mut dst = Vec::with_capacity(expected.len());
                let (result, allocations) = measure(|| {
                    let mut ser = serde_json::Serializer::new(&mut dst);
                    match (tagged, upper) {
                        (true, true) => faster_hex::withpfx_uppercase::serialize(&src, &mut ser),
                        (true, false) => faster_hex::withpfx_lowercase::serialize(&src, &mut ser),
                        (false, true) => faster_hex::nopfx_uppercase::serialize(&src, &mut ser),
                        (false, false) => faster_hex::nopfx_lowercase::serialize(&src, &mut ser),
                    }
                });
                result.unwrap();
                assert_eq!(dst, expected.as_bytes());
                assert_eq!(
                    allocations,
                    usize::from(2 * n + 2 * usize::from(tagged) > 132)
                );
                println!("serde {n} {tagged} {upper} {allocations}");
            }
        }
        let view = faster_hex::Hex::new(&src);
        for flags in ["plain", "alt", "plus", "both", "width"] {
            let mut sink = Sink {
                text: String::with_capacity(2 * n + 32),
                calls: 0,
            };
            let (result, allocations) = measure(|| match flags {
                "plain" => write!(sink, "{view}"),
                "alt" => write!(sink, "{view:#x}"),
                "plus" => write!(sink, "{view:+}"),
                "both" => write!(sink, "{view:+#X}"),
                _ => write!(sink, "{view:+#010X}"),
            });
            result.unwrap();
            assert_eq!(allocations, 0);
            println!("format {n} {flags} {} {allocations}", sink.calls);
        }
    }
}
