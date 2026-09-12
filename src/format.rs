use crate::encode::hex_encode_custom;
use core::fmt::{self, Alignment, Write};

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

    fn format(&self, f: &mut fmt::Formatter<'_>, upper: bool) -> fmt::Result {
        let prefix = if f.alternate() { "0x" } else { "" };
        let sign = if f.sign_plus() { "+" } else { "" };
        // Saturation is sufficient for width comparison: if the complete output
        // exceeds usize::MAX characters, no representable width adds padding.
        let len = self
            .bytes
            .len()
            .saturating_mul(2)
            .saturating_add(prefix.len())
            .saturating_add(sign.len());
        let padding = f.width().unwrap_or(0).saturating_sub(len);
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
        f.write_str(sign)?;
        f.write_str(prefix)?;
        if zero_pad {
            write_fill(f, '0', padding)?;
        }

        let mut buffer = [0; 512];
        for chunk in self.bytes.chunks(buffer.len() / 2) {
            // Each chunk is at most half this fixed, nonempty buffer. Its
            // encoded length cannot overflow or exceed capacity. Keep the
            // checked encoder's initialization boundary intact.
            let text = hex_encode_custom(chunk, &mut buffer, upper)
                .expect("each chunk fits the fixed encoding buffer");
            f.write_str(text)?;
        }
        write_fill(f, fill, right)
    }
}

fn write_fill(f: &mut fmt::Formatter<'_>, fill: char, count: usize) -> fmt::Result {
    for _ in 0..count {
        f.write_char(fill)?;
    }
    Ok(())
}

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(f, false)
    }
}

impl fmt::LowerHex for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(f, false)
    }
}

impl fmt::UpperHex for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(f, true)
    }
}
