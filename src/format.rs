use crate::encode::encode;
use core::fmt::{self, Alignment, Write};
use core::mem::MaybeUninit;

/// A borrowed hexadecimal view of a byte slice, available without allocation.
///
/// [`Display`](fmt::Display) and [`LowerHex`](fmt::LowerHex) use lowercase digits;
/// [`UpperHex`](fmt::UpperHex) uses uppercase. Every byte produces two digits in
/// source order, including leading zeroes. The slice is borrowed, not copied.
/// This is a byte-sequence view: it does not interpret the input as an integer
/// or reverse bytes according to the machine's endianness.
///
/// # Formatting
///
/// All three formatting traits use the following integer-style flags:
///
/// - `#` adds `0x`, also for uppercase output and an empty slice.
/// - `+` adds a leading plus sign. Width includes the sign and prefix.
/// - Width, fill and alignment apply to the complete value; default alignment is right.
///   Width counts Unicode characters, so a non-ASCII fill character counts as one.
/// - `0` pads after the sign/prefix, overriding fill and alignment.
/// - Precision and `-` are ignored. Precision never truncates a byte sequence.
///
/// # Allocation and writer errors
///
/// Available without `alloc` or `std`. Formatting uses bounded stack storage and
/// allocates no intermediate string; the destination writer may still allocate.
/// For example, `format!` allocates its resulting string, while `write!` can write
/// into existing storage.
///
/// An error from the writer is returned immediately and no further writes are
/// attempted. Text already accepted by the writer remains written, including a
/// partial write from the failing call. The number and size of writes are
/// unspecified. To make output atomic, format into a separate buffer first.
///
/// # Examples
///
/// ```
/// use faster_hex::Hex;
/// let bytes = [0, 0xab, 0xcd];
/// let hex = Hex::new(&bytes);
/// assert_eq!(format!("{hex}"), "00abcd");
/// assert_eq!(format!("{hex:#010X}"), "0x0000ABCD");
/// assert_eq!(format!("{hex:.2}"), "00abcd");
/// ```
///
/// Append to a text destination without creating an intermediate hex string:
///
/// ```
/// use core::fmt::Write;
/// use faster_hex::Hex;
///
/// let mut output = String::with_capacity(64);
/// write!(output, "hash={:#X}", Hex::new(&[0, 0xab, 0xcd]))?;
/// assert_eq!(output, "hash=0x00ABCD");
/// # Ok::<(), core::fmt::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct Hex<'a> {
    bytes: &'a [u8],
}

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
    /// Borrows bytes for hexadecimal formatting without copying or allocating.
    ///
    /// The view cannot outlive `bytes`. It accepts an empty slice and is usable
    /// in constant expressions. Creating a view does not perform any encoding.
    ///
    /// # Examples
    ///
    /// ```
    /// use faster_hex::Hex;
    ///
    /// const ID: Hex<'static> = Hex::new(&[0, 0xab]);
    /// assert_eq!(format!("{ID}"), "00ab");
    /// assert_eq!(format!("{ID:#X}"), "0x00AB");
    /// ```
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

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

impl Hex<'_> {
    fn format<const OMIT_LOW: bool>(&self, f: &mut fmt::Formatter<'_>, upper: bool) -> fmt::Result {
        if let Some(width) = f.width() {
            return self.format_padded::<OMIT_LOW>(f, upper, width);
        }
        if f.sign_plus() {
            f.write_str("+")?;
        }
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.write_hex::<OMIT_LOW>(f, upper)
    }

    // Padding needs more live state; keep it out of the usual hash/logging path.
    #[inline(never)]
    fn format_padded<const OMIT_LOW: bool>(
        &self,
        f: &mut fmt::Formatter<'_>,
        upper: bool,
        width: usize,
    ) -> fmt::Result {
        // Saturation is sufficient for width comparison: if the complete output
        // exceeds usize::MAX characters, no representable width adds padding.
        let prefix = if f.alternate() { "0x" } else { "" };
        let sign = if f.sign_plus() { "+" } else { "" };
        let digits = self.bytes.len().saturating_mul(2) - usize::from(OMIT_LOW);
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

        self.write_hex::<OMIT_LOW>(f, upper)?;
        write_fill(f, fill, right)
    }

    #[inline]
    fn write_hex<const OMIT_LOW: bool>(
        &self,
        f: &mut fmt::Formatter<'_>,
        upper: bool,
    ) -> fmt::Result {
        if self.bytes.is_empty() {
            return Ok(());
        }
        if self.bytes.len() <= 128 {
            // Hashes and short identifiers need one encode and one writer call.
            let mut buffer = [MaybeUninit::uninit(); 256];
            let text = encode(self.bytes, &mut buffer, upper)
                .expect("short input fits the fixed encoding buffer");
            return f.write_str(if OMIT_LOW {
                &text[..text.len() - 1]
            } else {
                text
            });
        }
        self.write_long::<OMIT_LOW>(f, upper)
    }

    // Keep the larger scratch space and streaming loop out of short hash calls.
    #[inline(never)]
    fn write_long<const OMIT_LOW: bool>(
        &self,
        f: &mut fmt::Formatter<'_>,
        upper: bool,
    ) -> fmt::Result {
        let mut buffer = [MaybeUninit::uninit(); 1024];
        let mut chunks = self.bytes.chunks(buffer.len() / 2);
        while let Some(chunk) = chunks.next() {
            // Each chunk is at most half this fixed, nonempty buffer. Its
            // encoded length cannot overflow or exceed capacity. Keep the
            // checked encoder's initialization boundary intact.
            let text = encode(chunk, &mut buffer, upper)
                .expect("each chunk fits the fixed encoding buffer");
            let trim = OMIT_LOW && chunks.len() == 0;
            f.write_str(&text[..text.len() - usize::from(trim)])?;
        }
        Ok(())
    }
}

fn write_fill(f: &mut fmt::Formatter<'_>, fill: char, mut count: usize) -> fmt::Result {
    // Common integer padding needs one write per block, not per character.
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

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format::<false>(f, false)
    }
}

impl fmt::LowerHex for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format::<false>(f, false)
    }
}

impl fmt::UpperHex for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format::<false>(f, true)
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
            crate::encode::encode_odd(self.hex.bytes, dst)
        } else {
            crate::encode::encode_bytes::<true>(self.hex.bytes, dst, false)
        }
    }

    fn format(&self, f: &mut fmt::Formatter<'_>, upper: bool) -> fmt::Result {
        if self.omit_low_nibble {
            self.hex.format::<true>(f, upper)
        } else {
            self.hex.format::<false>(f, upper)
        }
    }
}

impl fmt::Display for LeadingDigits<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(f, false)
    }
}

impl fmt::LowerHex for LeadingDigits<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(f, false)
    }
}

impl fmt::UpperHex for LeadingDigits<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(f, true)
    }
}
