use crate::encode::{encode_prefix, encode_prefix_odd, encode_prefix_uninit};
use core::fmt::{self, Alignment, Write as _};
use core::mem::MaybeUninit;

use super::Hex;

/// A borrowed view of the leading hexadecimal digits selected by [`Hex::leading_digits`].
/// Supports the same formatting flags as [`Hex`]. Use [`Self::encode_to`]
/// to write its lowercase digits into a byte slice.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct LeadingDigits<'a> {
    hex: Hex<'a>,
    omit_low_nibble: bool,
}

impl<'a> Hex<'a> {
    /// Selects at most `count` leading hexadecimal digits for formatting or encoding.
    ///
    /// Each byte contributes two digits. Any count is valid, including zero.
    /// An odd count ends with the high nibble of the last selected byte. A count
    /// beyond the end shows the whole input. Only the selected bytes are encoded.
    /// Formatting width and padding apply to the visible digits. A sign or `0x`
    /// prefix does not count toward `count`.
    ///
    /// ```
    /// use faster_hex::Hex;
    /// let id = Hex::new(&[0xde, 0xad, 0xbe, 0xef, 0x12, 0x34]);
    /// assert_eq!(id.leading_digits(5).to_string(), "deadb");
    /// assert_eq!(format!("{:#X}", id.leading_digits(10)), "0xDEADBEEF12");
    /// assert_eq!(id.leading_digits(20).to_string(), "deadbeef1234");
    /// ```
    #[inline]
    pub const fn leading_digits(self, count: usize) -> LeadingDigits<'a> {
        let (bytes, omit_low_nibble) = match self.bytes.split_at_checked(count.div_ceil(2)) {
            Some((prefix, _)) => (prefix, !count.is_multiple_of(2)),
            None => (self.bytes, false),
        };
        LeadingDigits {
            hex: Self::new(bytes),
            omit_low_nibble,
        }
    }
}

impl LeadingDigits<'_> {
    /// Encodes the selected lowercase digits into caller-provided storage.
    /// Returns the written prefix, borrowing only `dst`. No space is needed
    /// for the unused low nibble of an odd-length prefix.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::OutputTooSmall`] if the selected digits do not fit,
    /// leaving the destination unchanged. Spare capacity is left untouched on success.
    ///
    /// ```
    /// use faster_hex::Hex;
    /// let mut dst = [0; 7];
    /// let text = Hex::new(&[0xde, 0xad, 0xbe, 0xef]).leading_digits(7).encode_to(&mut dst)?;
    /// assert_eq!(text, "deadbee");
    /// # Ok::<(), faster_hex::Error>(())
    /// ```
    #[inline]
    pub fn encode_to(self, dst: &mut [u8]) -> Result<&mut str, crate::Error> {
        if self.omit_low_nibble {
            encode_prefix_odd(self.hex.bytes, dst)
        } else {
            encode_prefix(self.hex.bytes, dst)
        }
    }

    #[inline]
    fn format<const UPPER: bool>(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(width) = f.width() {
            return self.format_padded::<UPPER>(f, width);
        }
        if f.sign_plus() {
            f.write_str("+")?;
        }
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.write_digits::<UPPER>(f)
    }

    // Generic on case so callers that only format `Hex` do not pull this into rlib CGUs.
    #[inline(never)]
    fn format_padded<const UPPER: bool>(
        &self,
        f: &mut fmt::Formatter<'_>,
        width: usize,
    ) -> fmt::Result {
        let prefix = if f.alternate() { "0x" } else { "" };
        let sign = if f.sign_plus() { "+" } else { "" };
        let digits = self.hex.bytes.len().saturating_mul(2) - usize::from(self.omit_low_nibble);
        let len = digits
            .saturating_add(prefix.len())
            .saturating_add(sign.len());
        let padding = width.saturating_sub(len);
        let zero_pad = f.sign_aware_zero_pad();
        let (left, right) = if zero_pad {
            (0, 0)
        } else {
            match f.align().unwrap_or(Alignment::Right) {
                Alignment::Left => (0, padding),
                Alignment::Right => (padding, 0),
                Alignment::Center => (padding / 2, padding - padding / 2),
            }
        };
        let fill = f.fill();
        write_fill(f, fill, left)?;
        if !sign.is_empty() {
            f.write_str(sign)?;
        }
        if !prefix.is_empty() {
            f.write_str(prefix)?;
        }
        if zero_pad {
            write_fill(f, '0', padding)?;
        }
        self.write_digits::<UPPER>(f)?;
        write_fill(f, fill, right)
    }

    #[inline]
    fn write_digits<const UPPER: bool>(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.hex.bytes;
        if bytes.is_empty() {
            return Ok(());
        }
        if bytes.len() <= 128 {
            let mut buffer = [MaybeUninit::uninit(); 256];
            let pair_digits = bytes.len() * 2;
            encode_prefix_uninit::<UPPER>(bytes, &mut buffer[..pair_digits]);
            let visible = pair_digits - usize::from(self.omit_low_nibble);
            // SAFETY: `encode_prefix_uninit` initialized `..pair_digits` with ASCII hex
            // digits, and `visible <= pair_digits`.
            let text = unsafe {
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                    buffer.as_ptr().cast(),
                    visible,
                ))
            };
            return f.write_str(text);
        }
        self.write_long::<UPPER>(f)
    }

    #[inline(never)]
    fn write_long<const UPPER: bool>(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = [MaybeUninit::uninit(); 1024];
        let mut remaining = self.hex.bytes;
        while !remaining.is_empty() {
            let (chunk, tail) = remaining.split_at(remaining.len().min(buffer.len() / 2));
            remaining = tail;
            let pair_digits = chunk.len() * 2;
            encode_prefix_uninit::<UPPER>(chunk, &mut buffer[..pair_digits]);
            let trim = self.omit_low_nibble && remaining.is_empty();
            let visible = pair_digits - usize::from(trim);
            // SAFETY: `encode_prefix_uninit` initialized `..pair_digits` with ASCII hex
            // digits, and `visible <= pair_digits`.
            let text = unsafe {
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                    buffer.as_ptr().cast(),
                    visible,
                ))
            };
            f.write_str(text)?;
        }
        Ok(())
    }
}

impl fmt::Display for LeadingDigits<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format::<false>(f)
    }
}

impl fmt::LowerHex for LeadingDigits<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format::<false>(f)
    }
}

impl fmt::UpperHex for LeadingDigits<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format::<true>(f)
    }
}

#[inline]
fn write_fill(f: &mut fmt::Formatter<'_>, fill: char, mut count: usize) -> fmt::Result {
    let block = match fill {
        ' ' => "                                ",
        '0' => "00000000000000000000000000000000",
        _ => {
            for _ in 0..count {
                f.write_char(fill)?;
            }
            return Ok(());
        }
    };
    while count >= block.len() {
        f.write_str(block)?;
        count -= block.len();
    }
    if count != 0 {
        f.write_str(&block[..count])?;
    }
    Ok(())
}
