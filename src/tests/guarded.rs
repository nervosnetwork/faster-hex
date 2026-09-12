use crate::{hex_check_with_case, hex_decode_with_case, hex_encode, hex_encode_upper, CheckCase};

/// One writable page between inaccessible pages. Both ends are exercised so a
/// SIMD load or store outside either slice faults instead of touching spare capacity.
struct Guarded {
    allocation: *mut libc::c_void,
    page: usize,
}

impl Guarded {
    fn new() -> Self {
        // SAFETY: sysconf takes no pointer and querying the page size has no side effects.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page > 0);
        let page = page as usize;
        // SAFETY: Anonymous mapping, no existing mapping is replaced, fd/offset are unused.
        let allocation = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page * 3,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(allocation, libc::MAP_FAILED);
        let buffer = Self { allocation, page };
        // SAFETY: This page belongs to the new three-page allocation and is page-aligned.
        let result = unsafe {
            libc::mprotect(
                allocation.cast::<u8>().add(page).cast(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        assert_eq!(result, 0);
        buffer
    }

    fn pointer(&self, len: usize, end: bool) -> *mut u8 {
        assert!(len <= self.page);
        let offset = self.page + if end { self.page - len } else { 0 };
        // SAFETY: The offset stays in this allocation, including a one-past-page empty slice.
        unsafe { self.allocation.cast::<u8>().add(offset) }
    }

    fn slice(&self, len: usize, end: bool) -> &[u8] {
        // SAFETY: pointer() bounds the slice to initialized, readable mapped memory;
        // its lifetime is tied to self and the immutable borrow excludes writes.
        unsafe { std::slice::from_raw_parts(self.pointer(len, end), len) }
    }

    fn slice_mut(&mut self, len: usize, end: bool) -> &mut [u8] {
        // SAFETY: The exclusive borrow excludes aliases and pointer() bounds the writable slice.
        unsafe { std::slice::from_raw_parts_mut(self.pointer(len, end), len) }
    }
}

impl Drop for Guarded {
    fn drop(&mut self) {
        // SAFETY: This object owns the complete live mapping; no borrowed slices remain.
        unsafe { libc::munmap(self.allocation, self.page * 3) };
    }
}

unsafe fn public_encode(src: &[u8], dst: &mut [u8], upper: bool) {
    if upper {
        hex_encode_upper(src, dst).unwrap();
    } else {
        hex_encode(src, dst).unwrap();
    }
}

unsafe fn public_check(src: &[u8], case: CheckCase) -> bool {
    hex_check_with_case(src, case)
}

unsafe fn public_decode(src: &[u8], dst: &mut [u8], case: CheckCase) -> Result<(), ()> {
    hex_decode_with_case(src, dst, case)
        .map(|_| ())
        .map_err(|_| ())
}

#[test]
fn conversions_and_checks_stop_at_guard_pages() {
    type Encode = unsafe fn(&[u8], &mut [u8], bool);
    type Check = unsafe fn(&[u8], CheckCase) -> bool;
    type Decode = unsafe fn(&[u8], &mut [u8], CheckCase) -> Result<(), ()>;
    let backends = std::iter::once((
        "public",
        public_encode as Encode,
        public_check as Check,
        public_decode as Decode,
    ));
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let backends = backends.chain(super::x86::backends());
    let mut source = Guarded::new();
    let mut encoded = Guarded::new();
    let mut decoded = Guarded::new();
    for (name, encode, check, decode) in backends {
        for len in 0..=257 {
            let data: Vec<u8> = (0..len).map(|i| (i * 73 + i / 7) as u8).collect();
            for end in [false, true] {
                source.slice_mut(len, end).copy_from_slice(&data);
                for upper in [false, true] {
                    let case = if upper {
                        CheckCase::Upper
                    } else {
                        CheckCase::Lower
                    };
                    let expected = if upper {
                        hex::encode_upper(&data)
                    } else {
                        hex::encode(&data)
                    };
                    // SAFETY: Each backend is supported; both slices have the exact required size.
                    unsafe {
                        encode(
                            source.slice(len, end),
                            encoded.slice_mut(len * 2, end),
                            upper,
                        )
                    };
                    assert_eq!(encoded.slice(len * 2, end), expected.as_bytes(), "{name}");
                    // Also exercise odd-length character checking immediately against a guard page.
                    for size in [len * 2, (len * 2).saturating_sub(1)] {
                        encoded.slice_mut(size, end).fill(b'0');
                        // SAFETY: The checker supports this CPU and bounds its reads.
                        assert!(unsafe { check(encoded.slice(size, end), case) }, "{}", name);
                    }
                    encoded
                        .slice_mut(len * 2, end)
                        .copy_from_slice(expected.as_bytes());
                    // SAFETY: CPU support and the exact 2:1 ratio are established above.
                    unsafe {
                        decode(
                            encoded.slice(len * 2, end),
                            decoded.slice_mut(len, end),
                            case,
                        )
                    }
                    .unwrap();
                    assert_eq!(decoded.slice(len, end), &data, "{name}");
                    if len != 0 {
                        encoded.slice_mut(len * 2, end)[len * 2 - 1] = b'!';
                        decoded.slice_mut(len, end).fill(0xa5);
                        // SAFETY: Invalid characters are permitted; supported checked kernels reject them.
                        let result = unsafe {
                            decode(
                                encoded.slice(len * 2, end),
                                decoded.slice_mut(len, end),
                                case,
                            )
                        };
                        assert_eq!(result, Err(()));
                        assert!(
                            decoded.slice(len, end).iter().all(|&b| b == 0xa5),
                            "{}",
                            name
                        );
                    }
                }
            }
        }
    }
}
