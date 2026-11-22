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

struct Present<D>(D);
impl<'de,D:serde::Deserializer<'de>> serde::Deserializer<'de> for Present<D> {
    type Error=D::Error;
    fn deserialize_any<V:serde::de::Visitor<'de>>(self,v:V)->Result<V::Value,D::Error> {v.visit_some(self.0)}
    fn deserialize_option<V:serde::de::Visitor<'de>>(self,v:V)->Result<V::Value,D::Error> {v.visit_some(self.0)}
    serde::forward_to_deserialize_any!{
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf unit
        unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any
    }
}
fn main() {
    use serde::de::value::{BorrowedStrDeserializer, Error, StrDeserializer};

    let input = format!("0x{}", "ab".repeat(32));
    let (borrowed, array_borrowed) = measure(|| {
        faster_hex::array::deserialize::<_, 32>(BorrowedStrDeserializer::<Error>::new(&input)).unwrap()
    });
    let (transient, array_transient) = measure(|| {
        faster_hex::array::deserialize::<_, 32>(StrDeserializer::<Error>::new(&input)).unwrap()
    });
    assert_eq!(borrowed, [0xab; 32]);
    assert_eq!(transient, borrowed);
    let (borrowed, vec_borrowed) = measure(|| {
        faster_hex::deserialize_bounded::<32, _, Vec<u8>>(BorrowedStrDeserializer::<Error>::new(&input)).unwrap()
    });
    let (transient, vec_transient) = measure(|| {
        faster_hex::deserialize_bounded::<32, _, Vec<u8>>(StrDeserializer::<Error>::new(&input)).unwrap()
    });
    assert_eq!(borrowed, [0xab; 32]);
    assert_eq!(transient, borrowed);
    println!("array borrowed={array_borrowed} transient={array_transient}");
    println!("bounded Vec borrowed={vec_borrowed} transient={vec_transient}");
    use faster_hex::option_withpfx_ignorecase as opt;
    let (a,n)=measure(||opt::array::deserialize::<_,32>(Present(StrDeserializer::<Error>::new(&input))).unwrap());
    let (b,m)=measure(||opt::array::deserialize::<_,32>(Present(BorrowedStrDeserializer::<Error>::new(&input))).unwrap());
    assert_eq!(a,Some([0xab;32]));assert_eq!(a,b);
    let (v,k)=measure(||opt::deserialize_bounded::<32,_,Vec<u8>>(Present(StrDeserializer::<Error>::new(&input))).unwrap());
    let (u,j)=measure(||opt::deserialize_bounded::<32,_,Vec<u8>>(Present(BorrowedStrDeserializer::<Error>::new(&input))).unwrap());
    assert_eq!(v,Some(vec![0xab;32]));assert_eq!(v,u);
    println!("optional array borrowed={m} transient={n}; optional bounded vec borrowed={j} transient={k}");
    let plain = format!("{input:?}");
    let escaped = plain.replace('a', r"\u0061");
    for (kind, source) in [("literal", plain), ("escaped", escaped)] {
        let (array, n) = measure(|| faster_hex::array::deserialize::<_,32>(&mut serde_json::Deserializer::from_str(&source)).unwrap());
        let (bytes, v) = measure(|| faster_hex::deserialize_bounded::<32,_,Vec<u8>>(&mut serde_json::Deserializer::from_str(&source)).unwrap());
        assert_eq!(array, [0xab;32]); assert_eq!(&bytes[..], array);
        println!("serde_json {kind} array={n} bounded_vec={v}");
    }
}
