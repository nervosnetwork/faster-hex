# faster-hex

[![Crates.io](https://img.shields.io/crates/v/faster-hex.svg)](https://crates.io/crates/faster-hex)
[![Documentation](https://docs.rs/faster-hex/badge.svg)](https://docs.rs/faster-hex)

Fast hexadecimal encoding and decoding with SIMD acceleration and a portable
fallback. Uses SSE4.1 or AVX2 on x86 and NEON on AArch64 when available, with
AVX-512BW acceleration for validation and decoding. Supports `no_std`.
Requires Rust 1.95.0 or later.

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

Both conversions process the complete input and leave the destination unchanged
on errors. Extra output capacity is allowed and remains untouched. Decoding
accepts mixed-case ASCII hex, reports the first invalid byte and its position,
and offers explicit lowercase/uppercase policies through `hex_decode_with_case`.

For a fixed hash, `hex_decode_array::<32>` returns an owned array without heap
allocation. For logging or an existing text writer, `Hex::new(&bytes)` formats
directly, including a prefix with `{:#x}`, without a temporary hex string. Use
`hex_append` to reuse a `String`'s capacity across calls.

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
adapters are shared with unit tests and exposed only under `cfg(fuzzing)`; normal
and `--all-features` builds have no backend API.
After minimization, LLVM coverage replay must still reach the scalar and available
SIMD kernels. JSON and HTML coverage reports are retained with the fuzz artifacts.

## Benchmarks

For development, run `cargo bench-dev` from this checkout. It measures eight
cases: encoding and decoding 8, 32, 256 and 4096 bytes through the public API.
Buffers are allocated before timing; validation and CPU dispatch are included.
Each case uses 0.2 seconds of warm-up and 1 second of sampling, so expect roughly
10–20 seconds after compilation.

Save a baseline before editing, then compare the same cases after your change:

```sh
cargo bench-dev --save-baseline before
# Edit the implementation.
cargo bench-dev --baseline before
```

Criterion's `change: time` reports the change in latency: negative is faster,
positive is slower. It also reports whether the change is statistically
significant. `--baseline before` keeps the saved baseline unchanged, so you can
compare multiple edits against it. Results live in `target/criterion`; keep that
directory when switching between commits. Use the same machine, Rust toolchain,
features and `Cargo.lock`, and run one benchmark process at a time.
Use the same benchmark code on both sides; recreate saved baselines after
changing the harness.

To compare with `hex`, `const-hex`, `hex-simd`, `fashex`, `better-hex` and
`data-encoding`, run:

```sh
cargo bench-compare
```

This runs 56 cases at the same four sizes, taking roughly 70 seconds after
compilation. All libraries receive the same input and reuse their output buffer.
Encoding is lowercase; decoding accepts mixed case. Sizes and throughput count
binary payload bytes: `decode/faster_hex_mixed/32` reads 64 hex characters and
produces 32 bytes. Append `--list` to a command to inspect the selected cases.

For a small performance difference, confirm the affected cases using Criterion's
longer default sampling, saving and comparing a new baseline as above:

```sh
cargo bench --bench hex -- '^encode/faster_hex/32$' --save-baseline confirm
# Edit the implementation, then rerun with --baseline confirm.
```

For Hash256 work, `cargo bench-hash` selects 24 cases at 32 binary bytes / 64
hex characters, taking roughly 30 seconds after compilation. It compares hot
encoding/decoding, rotation through 4096 different hashes, and validation-only
checks (fashex has no public checker). Rotation and buffer reuse happen inside
the timer; input generation and reference-output assertions happen before it.
Use `--save-baseline before` / `--baseline before` here too. Always rerun
`bench-dev` to check other lengths after a Hash256 optimization.

`cargo bench --bench format` compares borrowed `Hex`, an allocated hex string,
per-byte formatting and padded uppercase output. `cargo bench --bench serde`
measures JSON serialization/deserialization and Postcard serialization, including
reused output buffers. These test library operations directly; application and
network overhead are outside their scope.

When comparing separate checkouts, give them separate `CARGO_TARGET_DIR` values
and a shared `CRITERION_HOME` for reports. Reusing a build directory across copies
of the same package can select stale artifacts. Keep compiler flags, features
and the dependency lockfile identical on both sides.

The four benchmark targets cover conversion/owned strings (`hex`), validation
and invalid-byte positions (`check`), JSON/Postcard adapters (`serde`), and borrowed
formatting (`format`). Run a focused alias during development; the full matrix
uses Criterion's longer default sampling. CI runs `cargo bench --all-features
--benches -- --test` to execute cases without collecting timings. SIMD alignment
and boundary correctness belong to the forced-backend and guard-page tests.

## License

[MIT](LICENSE). Third-party notices are in [LICENSE-THIRD-PARTY](LICENSE-THIRD-PARTY).
