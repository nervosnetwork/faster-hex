# faster-hex

[![Crates.io](https://img.shields.io/crates/v/faster-hex.svg)](https://crates.io/crates/faster-hex)
[![docs.rs](https://img.shields.io/docsrs/faster-hex?label=docs.rs)](https://docs.rs/faster-hex)

Fast, checked hex encoding and decoding with SIMD on x86 and AArch64, a
portable scalar fallback, and `no_std` support. Requires Rust 1.95 or later.

## Usage

```toml
[dependencies]
faster-hex = "2.1"
```

```rust
use faster_hex::{hex_decode, hex_encode};

fn main() -> Result<(), faster_hex::Error> {
    let mut encoded = [0; 10];
    let text = hex_encode(b"hello", &mut encoded)?;
    assert_eq!(text, "68656c6c6f");

    let mut decoded = [0; 5];
    assert_eq!(hex_decode(text.as_bytes(), &mut decoded)?, b"hello");
    Ok(())
}
```

Both calls return the written slice and preserve the buffer on error.
`hex_decode` accepts mixed-case ASCII hex and reports the first invalid digit's
byte offset. Use `hex_validate` to check hex pairs without an output buffer, or
`hex_decode_append` (with `alloc`) to extend an existing `Vec<u8>`.

## Hash prefixes

Use `let view = Hex::new(bytes).leading_digits(n)` for a Git object ID abbreviation
or a short ID in a log. Five digits of `deadbeef1234` give `deadb`, ten give
`deadbeef12`, and larger counts stop at the end of the input. Only the bytes
needed for the prefix are encoded. For a unique Git abbreviation, the repository
determines the length to pass.

Use `view.encode_to(dst)` for a lowercase prefix in a caller-provided buffer,
or `write!(out, "{view:#X}")` for formatted output. Use `hex_encode` when
writing the complete value into a byte buffer.

Time per SHA-1 prefix written into a reusable buffer by `gix_hash::Prefix::hex_to_buf`
on an Apple M5 Pro, in nanoseconds. Each range spans the medians of default release
and ThinLTO builds with Rust 1.95.0.

| Implementation | 4 digits | 7 digits | 8 digits | 12 digits | 40 digits (full) |
| --- | ---: | ---: | ---: | ---: | ---: |
| gix-hash with faster-hex 2.0 | 3.86–3.90 | 4.91–4.98 | 4.44–4.51 | 6.19–6.24 | 5.05–5.80 |
| `leading_digits(n).encode_to(dst)` | 1.15–1.16 | 1.36–1.37 | 1.40–1.42 | 1.58–1.60 | 1.56–1.58 |

## Features

`std` and `serde` are enabled by default. Set `default-features = false` for a
dependency-free `no_std` build. Enable `alloc` for owned strings and vectors,
`heapless-09` for fixed-capacity strings, or `defmt` for defmt 1.x logging.

[API documentation](https://docs.rs/faster-hex) · [Changelog](CHANGELOG.md) · [Migration guide](MIGRATION.md)

## License

[MIT](LICENSE). See the [third-party notices](LICENSE-THIRD-PARTY).
