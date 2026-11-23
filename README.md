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

`let view = Hex::new(bytes).leading_digits(n)` selects up to `n` hex digits.
Use the repository's abbreviation length for a Git object ID, or choose a width
for a log. Zero selects an empty prefix. A count beyond the end selects the
whole input.

`view.encode_to(dst)` writes one lowercase ASCII byte per selected digit. For
`deadbeef1234`, seven digits use four input bytes and write `deadbee`. All
twelve digits use six input bytes. Use `write!(out, "{view:#X}")`
for formatted output or `hex_encode` for a complete value in a byte buffer.

Timings across prefix lengths are in the [2.1 benchmarks for SHA-1 and SHA-256](https://github.com/nervosnetwork/faster-hex/pull/77).

## Features

`std` and `serde` are enabled by default. Set `default-features = false` for a
dependency-free `no_std` build. Enable `alloc` for owned strings and vectors,
`heapless-09` for fixed-capacity strings, or `defmt` for defmt 1.x logging.

[API documentation](https://docs.rs/faster-hex) · [Changelog](CHANGELOG.md) · [Migration guide](MIGRATION.md)

## License

[MIT](LICENSE). See the [third-party notices](LICENSE-THIRD-PARTY).
