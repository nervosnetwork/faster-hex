# Native optimization results

Sizes count binary bytes. A 32-byte hash encodes to 64 hex digits. The codec
comparisons use the public APIs and the released 2.0.0 as the baseline. The
prefix comparisons also run against the branch before adding `encode_to`.

## Encoding on AArch64

One or two 16-byte NEON loads cover complete 16- and 32-byte inputs. Other
lengths use the existing block and tail handling. Reducing the bulk
loop's batch size in an earlier trial slowed 4 KiB encoding by about 10% on
the M5 Pro.

On an Apple M5 Pro, rotating through 4,096 different 32-byte hashes took
about 11% less time than 2.0.0 in both builds. The table averages two
estimates per revision, in nanoseconds per call.
[Measured revision](https://github.com/nervosnetwork/faster-hex/commit/62b102b026e74a7db3163d6d0581d01b1533fde7).

| Input | Default 2.0.0 | Default candidate | ThinLTO 2.0.0 | ThinLTO candidate |
|---|---:|---:|---:|---:|
| 32-byte hash, rotating | 1.86 | 1.66 | 1.88 | 1.68 |
| 4 KiB, same input | 92.0 | 91.7 | 92.8 | 92.9 |

In a comparison of seven crates on this machine, mixed-case decoding of a
32-byte hash took 2.29 ns with faster-hex and 2.95 ns with fashex. At 4 KiB,
fashex took 314 ns and faster-hex took 323 ns. Run `cargo bench-compare` to
compare the same inputs on another CPU.

## Rejected changes on x86

- An AVX2 shuffle improved some bulk encoding cases, but made a hot 32-byte
  hash 20–24% slower on a Xeon Platinum 8573C with ThinLTO in both paired
  measurements. The x86 encoder retains the released implementation.
  [AVX2 experiment](https://github.com/nervosnetwork/faster-hex/actions/runs/44681614329).
- Smaller scans located an invalid digit in a hash faster. On a 4 KiB input
  with an invalid final digit, narrowing 256-byte blocks to 16 bytes cost
  7% and 17% on an EPYC 9V45 with ThinLTO in separate runs.
  [First comparison](https://github.com/nervosnetwork/faster-hex/actions/runs/44683997182)
  and [repeat on the 9V45](https://github.com/nervosnetwork/faster-hex/actions/runs/44685729896).
- Selecting the checker once per scan also improved short errors, but the
  same 4 KiB failure went from 431 to 688 ns on a Xeon 6975P-C and from
  471 to 874 ns on an EPYC 9V74 in the default build. Decoding and the new
  `hex_validate` therefore share 2.0.0's error scan. Long inputs skip valid
  64-byte blocks before finding the exact byte. Improving this further
  requires checking successful hashes as well as early and late errors.
  [Checker experiment](https://github.com/nervosnetwork/faster-hex/actions/runs/44688664932).

In a release assembly comparison for `x86_64-unknown-linux-gnu` with no
Cargo features, the SSE4.1 and AVX2 encoder instructions matched 2.0.0.
The error path's instruction sequence also matched apart from the source
location passed to a bounds-check failure.

The native Linux comparisons for the earlier SIMD changes timed rejection of
the last digit of a 4 KiB payload in nanoseconds per call.
[Measured revision](https://github.com/nervosnetwork/faster-hex/commit/ec29e58b3e364d75e46cd158f64418c12e8f3388)
and [native comparison](https://github.com/nervosnetwork/faster-hex/actions/runs/44690188566).

| CPU | Default 2.0.0 | Default candidate | ThinLTO 2.0.0 | ThinLTO candidate |
|---|---:|---:|---:|---:|
| Intel Xeon 6975P-C | 431 | 435 | 427 | 427 |
| AMD EPYC 7763 | 603 | 601 | 611 | 611 |

## Costs of the new APIs

The M5 Pro default build gave the following Criterion estimates. The append
cases start with one byte already in a `Vec` with space for the result. The
formatting case writes into a reusable `String`.

| Operation | 32 bytes | 4 KiB |
|---|---:|---:|
| Decode into a fresh `Vec`, then extend the destination | 14.14 ns | 357 ns |
| `hex_decode_append` into the destination | 5.97 ns | 311 ns |
| `hex_check` on valid digits | 1.83 ns | 212 ns |
| `hex_validate` on valid byte pairs | 2.94 ns | 213 ns |

`Hex::new(&hash).leading_digits(7)` formatted a seven-digit prefix in 6.27 ns.
The validator adds an even-length check and reports the first invalid byte.

## Git prefixes and CKB bytes

`gix_hash::Prefix::hex_to_buf` can receive a buffer exactly as long as the
abbreviation. Seven digits need three complete bytes and the high nibble of
the fourth. `Hex::new(bytes).leading_digits(7).encode_to(dst)` writes directly
into those seven slots and returns their string view. The caller previously
selected the complete pairs, wrote the last digit and validated the resulting
UTF-8. A short buffer now reports the required size before writing any bytes.
[gitoxide's buffer implementation](https://github.com/GitoxideLabs/gitoxide/blob/a7e739482cd6fe357ca8ebdbf82da5f1945e3e38/gix-hash/src/prefix.rs#L41-L64).

The Git display formatter already owns enough stack space for the full ID.
Its existing full encode, slice and `write_str` sequence is a separate
workload. Substituting the buffer API there cost 3–9% on the M5 Pro in the
reverse-order retest of five display cases. On a Xeon 6975P-C the seven-digit
display cases cost 30–35% in the default build, even as the seven-digit buffer
cases improved by 62%. The final downstream experiment
uses the new method only in `Prefix::hex_to_buf`. A runtime tail option in
the shared encoder also took a hot 32-byte call from 1.37 to 2.45 ns. The
full encoder now runs its original byte-pair kernels independently of the
odd-prefix operation.
[gitoxide's formatter](https://github.com/GitoxideLabs/gitoxide/blob/a7e739482cd6fe357ca8ebdbf82da5f1945e3e38/gix-hash/src/oid.rs#L49-L59)
and [paired native experiment](https://github.com/nervosnetwork/faster-hex/actions/runs/44721581787).

The following ranges include two runs in each build profile on the M5 Pro,
using the real `gix-hash` types. Only `Prefix::hex_to_buf` changed at the
call site. Times are in nanoseconds per call.

| Git object ID | Digits | Previous implementation | Selected view written to a slice |
|---|---:|---:|---:|
| SHA-1 | 7 | 4.17–4.40 | 1.50 |
| SHA-256 | 7 | 4.26–4.51 | 1.50 |
| SHA-1 | 40 | 4.56–4.71 | 1.61–1.62 |
| SHA-256 | 64 | 3.40–3.66 | 1.61–1.62 |

CKB's `JsonBytes` visitor checks the protocol's `0x` prefix and takes
ownership of the result. In a local comparison using its real type and the
same JSON error handling, decoding into a fresh `Vec` with `hex_decode_vec`
took 736–749 ns at 4 KiB, against 770–803 ns for the existing slice decoder
with a freshly allocated destination. At 64 KiB the corresponding ranges
were 12.15–12.23 and 12.63–12.81 µs. An existing destination with spare
capacity has a different entry point, `hex_decode_append`. Streaming output
through Serde's `collect_str` also added work on small CKB hashes, so the
serializer still uses a stack buffer through 65 bytes.
[CKB's JSON visitor](https://github.com/nervosnetwork/ckb/blob/2061bc092a5dd447a741fad03b02628203b35e96/util/jsonrpc-types/src/bytes.rs#L85-L106).

The JSON writer can account for much of the time in a serialization
benchmark. On a Xeon 6975P-C, independent default builds took 43.7 and
51.5 ns to serialize a 32-byte field. Writing its pre-encoded text through
the same Serde payload took 38.7 and 46.6 ns without calling faster-hex.
In a shared executable the field took 43.4–43.6 and 44.2–44.3 ns, while
the plain-text control took 38.5–38.6 ns in both modes. The artifact retains
both experiments and the ThinLTO comparison.
[Codec and pre-encoded controls](https://github.com/nervosnetwork/faster-hex/actions/runs/44728944990).

## Reproducing the measurements

From a branch containing the comparison workflow, run

```sh
gh workflow run rust.yml --ref YOUR_BRANCH -f benchmark_base=v2.0.0
```

Each runner uses Rust 1.95.0, a shared dependency lock and matching Criterion
workloads. Both revisions build at the same path to keep Cargo's package
identity stable. The runner saves each executable and its SHA-256 digest
before rebuilding the package. Both profiles run baseline, candidate,
candidate, baseline on one CPU model. The rotating case cycles through 4,096 distinct
hashes. The reports cover raw encoders and decoders, error positions, Git
prefixes and JSON at both sides of the 65-byte stack-buffer boundary.
The artifacts include the CPU model, commit IDs, raw samples and sizes of the
linked benchmark executables. A suspected slowdown triggers longer samples in
the opposite order. The report retains differences reproduced in independent
builds. For those cases a third experiment links both revisions into one
consumer, then rebuilds with their call sites swapped. Its JSON adapter uses
a shared payload type and times the same writer on pre-encoded text as a
control. The workflow flags a regression when the candidate's 95% interval
is slower in both independent experiments and in both call-site assignments.
The reports keep timings that depend on the individual build. Hosted runner
CPU models vary.

For a local comparison, use two disposable checkouts. The script writes the
shared benchmark harness and dependency lock to those checkouts.

```sh
for lto in false thin; do
  CARGO_PROFILE_BENCH_LTO="$lto" python3 ci/bench_native.py ../base ../candidate "../results/$lto"
done
```

To time the new operations from a clean checkout, run

```sh
cargo bench --bench hex --bench check --bench format --bench prefix -- \
  '^(decode_append/.+/(32|4096)|check_valid/(either|byte_pairs)/(32|4096)|format/leading_digits/7|git_prefix/.+)$' \
  --warm-up-time 0.2 --measurement-time 2 --sample-size 40 --noplot
```
