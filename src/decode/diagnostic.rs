//! Locate the first invalid byte after a backend rejects its input.

use super::{
    hex_check_with_case, hex_decode_fallback, CheckCase, Error, NIL, UNHEX, UNHEX_LOWER,
    UNHEX_UPPER,
};

// Backends report validity; diagnostics belong to the public boundary. The
// successful SIMD path does not track byte positions or construct an error.
#[cold]
pub(super) fn decode_diagnosed(src: &[u8], dst: &mut [u8], case: CheckCase) -> Result<(), Error> {
    diagnose_invalid(src, case)?;
    // Recover if a backend rejected valid input; the caller needs initialized bytes.
    hex_decode_fallback(src, dst);
    Ok(())
}

#[inline(always)]
pub(super) fn diagnose_invalid(src: &[u8], case: CheckCase) -> Result<(), Error> {
    let table = match case {
        CheckCase::None => &UNHEX,
        CheckCase::Lower => &UNHEX_LOWER,
        CheckCase::Upper => &UNHEX_UPPER,
    };
    // Report a malformed first pair before scanning any SIMD blocks.
    for (index, &byte) in src.iter().take(2).enumerate() {
        if table[usize::from(byte)] == NIL {
            return Err(Error::InvalidChar { index, byte });
        }
    }
    // Skip valid blocks so locating a late error retains SIMD throughput.
    let skipped = if src.len() > 64 {
        src.chunks_exact(64)
            .take_while(|chunk| hex_check_with_case(chunk, case))
            .count()
            * 64
    } else {
        0
    };
    // Four independent lookups skip valid digits before the exact byte scan.
    // A rejected digit sets all bits. Valid entries use only the low nibble.
    let groups = src[skipped..].as_chunks::<4>().0;
    let valid_groups = groups
        .iter()
        .take_while(|group| {
            group
                .iter()
                .fold(0, |bits, &byte| bits | table[usize::from(byte)])
                != NIL
        })
        .count();
    let start = skipped + 4 * valid_groups;
    for (offset, &byte) in src[start..].iter().enumerate() {
        let index = start + offset;
        if table[usize::from(byte)] == NIL {
            return Err(Error::InvalidChar { index, byte });
        }
    }
    Ok(())
}
