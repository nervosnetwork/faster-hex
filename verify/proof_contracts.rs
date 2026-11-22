use crate::{hex_decode_with_case, CheckCase, Error};

#[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
#[kani::proof]
fn dynamic_backend_requires_cpu_and_os_support() {
    use crate::Vectorization::{AVX2, AVX512, None, SSE41};
    let max_leaf: u32 = kani::any();
    let flags1: u32 = kani::any();
    let flags7: u32 = kani::any();
    let xcr0: u64 = kani::any();
    let has_sse = max_leaf >= 1 && flags1 & (1 << 19) != 0;
    let may_read_xcr0 = has_sse && max_leaf >= 7 && flags1 & 0x1c00_0000 == 0x1c00_0000;
    let ymm_enabled = may_read_xcr0 && xcr0 & 0x06 == 0x06;
    let avx2 = ymm_enabled && flags7 & (1 << 5) != 0;
    let avx512 = avx2 && xcr0 & 0xe0 == 0xe0 && flags7 & 0x4001_0000 == 0x4001_0000;

    let selected = crate::x86::basic(max_leaf, || {
        assert!(max_leaf >= 1);
        flags1
    }, || {
        assert!(may_read_xcr0);
        crate::x86::extended(xcr0, || {
            assert!(ymm_enabled);
            flags7
        })
    });
    assert_eq!(selected == None, !has_sse);
    assert_eq!(selected == SSE41, has_sse && !avx2);
    assert_eq!(selected == AVX2, avx2 && !avx512);
    assert_eq!(selected == AVX512, avx512);
    kani::cover!(selected == None, "scalar reachable");
    kani::cover!(selected == SSE41, "SSE4.1 reachable");
    kani::cover!(selected == AVX2, "AVX2 reachable");
    kani::cover!(selected == AVX512, "AVX512 reachable");
}

fn digit(byte: u8, case: CheckCase) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' if case != CheckCase::Lower => Some(byte - b'A' + 10),
        b'a'..=b'f' if case != CheckCase::Upper => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[kani::proof]
#[kani::unwind(10)]
fn slice_decode_preserves_the_destination_contract() {
    let input: [u8; 8] = kani::any();
    let before: [u8; 5] = kani::any();
    let n: usize = kani::any();
    let capacity: usize = kani::any();
    kani::assume(n <= input.len() && capacity <= before.len());
    let case = match kani::any::<u8>() {
        0 => CheckCase::Lower,
        1 => CheckCase::Upper,
        _ => CheckCase::None,
    };

    let mut expected = before;
    let expected_result = if n % 2 != 0 {
        Err(Error::OddLength)
    } else if n / 2 > capacity {
        Err(Error::OutputTooSmall { required: n / 2 })
    } else {
        let mut status = Ok(n / 2);
        for (i, &byte) in input[..n].iter().enumerate() {
            match digit(byte, case) {
                Some(d) if i % 2 == 0 => expected[i / 2] = d << 4,
                Some(d) => expected[i / 2] |= d,
                None => {
                    status = Err(Error::InvalidChar { index: i, byte });
                    break;
                }
            }
        }
        status
    };

    let mut actual = before;
    let start = actual.as_ptr();
    let result = hex_decode_with_case(&input[..n], &mut actual[..capacity], case)
        .map(|written| {
            assert_eq!(written.as_ptr(), start);
            written.len()
        });
    assert_eq!(result, expected_result);
    assert_eq!(actual, if result.is_ok() { expected } else { before });
    kani::cover!(result.is_ok() && n != 0 && capacity > n / 2, "successful nonempty prefix");
    kani::cover!(matches!(result, Err(Error::OddLength)), "odd input");
    kani::cover!(matches!(result, Err(Error::OutputTooSmall { .. })), "short destination");
    kani::cover!(matches!(result, Err(Error::InvalidChar { index: 7, .. })), "last byte invalid");
}
