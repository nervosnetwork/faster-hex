//! Count only the current test thread's allocations inside explicit measurement scopes.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fmt::{self, Write};

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

struct Buffer {
    bytes: [u8; 2048],
    len: usize,
}

impl Write for Buffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len + text.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[test]
fn documented_allocation_free_operations_remain_allocation_free() {
    use faster_hex::{hex_check, hex_decode, hex_decode_array, hex_encode, hex_validate, Hex};

    // Also prove the observer is active; successful zero counts alone are weak evidence.
    let (allocation, count) = measure(|| std::hint::black_box(vec![0u8; 1024]));
    assert!(count > 0);
    drop(allocation);

    let bytes = [0xab; 513];
    let expected = hex::encode(bytes);
    let mut encoded = [0; 1026];
    let (text, count) = measure(|| hex_encode(&bytes, &mut encoded));
    assert_eq!(&*text.unwrap(), expected);
    assert_eq!(count, 0);
    let (prefix, count) = measure(|| {
        Hex::new(&bytes)
            .leading_digits(7)
            .encode_to(&mut encoded[..7])
    });
    assert_eq!(prefix.unwrap(), &expected[..7]);
    assert_eq!(count, 0);
    let mut decoded = [0; 513];
    let (data, count) = measure(|| hex_decode(expected.as_bytes(), &mut decoded));
    assert_eq!(data.unwrap(), bytes);
    assert_eq!(count, 0);
    let (array, count) = measure(|| hex_decode_array::<513>(expected.as_bytes()));
    assert_eq!(array.unwrap(), bytes);
    assert_eq!(count, 0);
    let (valid, count) = measure(|| hex_check(expected.as_bytes()));
    assert!(valid);
    assert_eq!(count, 0);
    let (valid, count) = measure(|| hex_validate(expected.as_bytes()));
    assert_eq!(valid, Ok(()));
    assert_eq!(count, 0);

    let mut writer = Buffer {
        bytes: [0; 2048],
        len: 0,
    };
    let (result, count) = measure(|| write!(writer, "{}", Hex::new(&bytes).leading_digits(7)));
    result.unwrap();
    assert_eq!(&writer.bytes[..writer.len], &expected.as_bytes()[..7]);
    assert_eq!(count, 0);
    writer.len = 0;
    let (result, count) = measure(|| write!(writer, "{:+#01040X}", Hex::new(&bytes)));
    result.unwrap();
    assert_eq!(
        &writer.bytes[..writer.len],
        format!("+0x{}{}", "0".repeat(11), expected.to_uppercase()).as_bytes()
    );
    assert_eq!(count, 0);

    for len in [0, 1, 10, 32] {
        writer.len = 0;
        let (result, count) = measure(|| write!(writer, "{}", Hex::new(&bytes[..len])));
        result.unwrap();
        assert_eq!(&writer.bytes[..writer.len], &expected.as_bytes()[..len * 2]);
        assert_eq!(count, 0);
    }

    let (error, count) = measure(|| hex_decode(b"g0", &mut decoded));
    assert!(error.is_err());
    assert_eq!(count, 0);

    #[cfg(feature = "alloc")]
    {
        let mut text = String::with_capacity(2048);
        text.push_str("前缀:");
        let (suffix, count) = measure(|| faster_hex::hex_append(&bytes, &mut text).len());
        assert_eq!(suffix, expected.len());
        assert_eq!(text, format!("前缀:{expected}"));
        assert_eq!(count, 0);
        let mut dst = Vec::with_capacity(bytes.len());
        let (appended, count) =
            measure(|| faster_hex::hex_decode_append(expected.as_bytes(), &mut dst));
        assert_eq!(appended.unwrap(), bytes);
        assert_eq!(count, 0);
        let mut empty = Vec::new();
        let (error, count) = measure(|| faster_hex::hex_decode_append(b"g", &mut empty));
        assert_eq!(error, Err(faster_hex::Error::OddLength));
        assert_eq!(count, 0);
        assert_eq!(empty.capacity(), 0);
        let (error, count) = measure(|| faster_hex::hex_decode_vec(b"g"));
        assert_eq!(error, Err(faster_hex::Error::OddLength));
        assert_eq!(count, 0);
    }
    #[cfg(feature = "heapless-09")]
    {
        let (text, count) = measure(|| faster_hex::heapless_09::hex_string::<1026>(&bytes));
        assert_eq!(text.unwrap().as_str(), expected);
        assert_eq!(count, 0);
    }
}

#[cfg(feature = "serde")]
#[test]
fn a_rejected_borrowed_option_does_not_allocate_its_decoded_bytes() {
    use serde::de::{
        value::BorrowedStrDeserializer, value::Error, Deserializer, Error as _, Visitor,
    };

    struct Framed<'a> {
        text: &'a str,
        closed: bool,
    }

    impl<'de> Deserializer<'de> for Framed<'de> {
        type Error = Error;

        fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            let value = visitor.visit_some(BorrowedStrDeserializer::<Error>::new(self.text))?;
            if self.closed {
                Ok(value)
            } else {
                Err(Error::custom("unclosed option"))
            }
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
            byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map struct
            enum identifier ignored_any
        }
    }

    let text = format!("0x{}", "ab".repeat(32));
    let frame = Framed {
        text: &text,
        closed: std::hint::black_box(false),
    };
    let (expected, error_allocations) = measure(|| Error::custom("unclosed option"));
    let (error, allocations) = measure(|| {
        faster_hex::option_withpfx_ignorecase::deserialize::<_, Vec<u8>>(frame).unwrap_err()
    });
    assert_eq!(error.to_string(), expected.to_string());
    assert_eq!(allocations, error_allocations);
}

#[cfg(feature = "serde")]
#[test]
fn fixed_size_serde_avoids_temporary_allocations() {
    #[derive(serde::Serialize)]
    struct Payload<'a>(#[serde(with = "faster_hex")] &'a [u8]);

    let bytes = [0xab; 65];
    for len in [0, 10, 20, 32, 64, 65] {
        let input = Payload(&bytes[..len]);
        let text = format!("0x{}", hex::encode(&bytes[..len]));
        let expected = serde_json::to_vec(&text).unwrap();
        let mut output = Vec::with_capacity(expected.len());
        let (result, count) = measure(|| serde_json::to_writer(&mut output, &input));
        result.unwrap();
        assert_eq!(output, expected);
        assert_eq!(count, 0);

        let mut actual = [0; 256];
        let mut expected = [0; 256];
        let expected = postcard::to_slice(&text, &mut expected).unwrap();
        let (result, count) = measure(|| postcard::to_slice(&input, &mut actual));
        assert_eq!(result.unwrap(), expected);
        assert_eq!(count, 0);
    }
}
