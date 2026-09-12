# faster-hex

[![Crates.io](https://img.shields.io/crates/v/faster-hex.svg)](https://crates.io/crates/faster-hex)
[![Documentation](https://docs.rs/faster-hex/badge.svg)](https://docs.rs/faster-hex)

Fast hexadecimal encoding and decoding with SIMD acceleration and a portable
fallback. Supports `no_std`. Requires Rust 1.95.0 or later.

## Usage

```toml
[dependencies]
faster-hex = "1.0.0-rc.2"
```

```rust
use faster_hex::{hex_decode, hex_encode};

let mut encoded = [0; 10];
let text = hex_encode(b"hello", &mut encoded).unwrap();
assert_eq!(text, "68656c6c6f");

let mut decoded = [0; 5];
assert_eq!(hex_decode(text.as_bytes(), &mut decoded).unwrap(), b"hello");
```

The default features are `std` and `serde`. Set `default-features = false` for a
dependency-free core. Optional features include `alloc`, `heapless-08` and `defmt-03`.

See the [API documentation](https://docs.rs/faster-hex), or run `cargo doc --open`
for this checkout. Upgrading from 0.10: [migration guide](MIGRATION.md).
Release history: [changelog](CHANGELOG.md).

## Testing changes

CI checks the API against the pinned 1.0 candidate baseline across all supported
feature combinations, including external trait and function-signature contracts.
It also runs libFuzzer on x86 and ARM and AFL on x86. Weekly and manual fuzz runs
use longer time limits, restore cached corpora, and save minimized inputs and
crash diagnostics as workflow artifacts.

Both fuzz engines share public-contract and core tests. Every input constructs
valid hex independently, exercises every available backend, and injects faults
after valid prefixes. Short inputs also drive multi-block payloads. Backend
adapters exist only under `cfg(fuzzing)`, not in normal or `--all-features` builds.
After minimization, LLVM coverage replay must still reach the scalar and available
SIMD kernels. JSON and HTML coverage reports are retained with the fuzz artifacts.

## License

[MIT](LICENSE). Third-party notices are in [LICENSE-THIRD-PARTY](LICENSE-THIRD-PARTY).
