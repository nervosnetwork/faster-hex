# Native optimization results

The baseline is faster-hex 2.0.0. Sizes count binary bytes, so a 32-byte hash
encodes to or decodes from 64 hex digits. Measurements use the public APIs.
[Measured revision](https://github.com/nervosnetwork/faster-hex/commit/ec29e58b3e364d75e46cd158f64418c12e8f3388)
and [native x86 comparison](https://github.com/nervosnetwork/faster-hex/actions/runs/44690188566).

## Encoding on AArch64

One or two 16-byte NEON loads cover inputs from 16 through 32 bytes. Larger
inputs keep their existing 64-byte loop and tail handling. Reducing the bulk
loop's batch size in an earlier trial slowed 4 KiB encoding by about 10% on
the M5 Pro.

With 4,096 different 32-byte hashes in rotation on an Apple M5 Pro, the new
encoder took 10% less time than 2.0.0 in the default build and 11% less with
ThinLTO. The table averages two estimates per revision, in nanoseconds per call.

| Input | Default 2.0.0 | Default candidate | ThinLTO 2.0.0 | ThinLTO candidate |
|---|---:|---:|---:|---:|
| 32-byte hash, rotating | 1.78 | 1.60 | 1.83 | 1.63 |
| 4 KiB, same input | 88.2 | 91.2 | 91.3 | 91.1 |

The 4 KiB default-build pairs varied from 87.2 → 93.5 ns to 89.2 → 88.9 ns.
A separate comparison of seven crates on this machine also shows why the
workload matters. For mixed-case decoding, faster-hex took 2.28 ns at 32
bytes against 2.81 ns for fashex. At 4 KiB, fashex took 310 ns against
319 ns for faster-hex.

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

The final native Linux runs timed rejection of the last digit of a 4 KiB
payload as follows. Each value is in nanoseconds per call.

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

## Reproducing the measurements

From a branch containing the comparison workflow, run

```sh
gh workflow run rust.yml --ref YOUR_BRANCH -f benchmark_base=v2.0.0
```

Each runner uses Rust 1.95.0, the same dependency lock and 2.0.0's Criterion
timers. Each profile runs baseline, candidate, candidate, baseline on one
host. The rotating case cycles through 4,096 distinct hashes. The artifacts
include the CPU model, commit IDs, raw samples, both paired estimates and
sizes of the linked benchmark executables. Hosted runner CPU models vary.
Dedicated Core i9-14900K measurements remain open.

For a local comparison, use two disposable checkouts. The script copies the
baseline's benchmarks and lockfile into the candidate checkout.

```sh
for lto in false thin; do
  CARGO_PROFILE_BENCH_LTO="$lto" python3 ci/bench_native.py ../base ../candidate "../results/$lto"
done
```

To time the three new APIs, run the candidate's own benchmarks from a clean
checkout.

```sh
cargo bench --bench hex --bench check --bench format -- \
  '^(decode_append/.+/(32|4096)|check_valid/(either|byte_pairs)/(32|4096)|format/leading_digits/7)$' \
  --warm-up-time 0.2 --measurement-time 2 --sample-size 40 --noplot
```
