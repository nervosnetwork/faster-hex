# Native codec measurements

Sizes count binary bytes. A 32-byte hash produces 64 hex digits. The
comparisons use Rust 1.95.0 in default and ThinLTO builds. The baselines
are the 2.0.0 release and the branch before adding `encode_to`.
[2.0.0](https://github.com/nervosnetwork/faster-hex/tree/v2.0.0),
[previous branch](https://github.com/nervosnetwork/faster-hex/commit/b16b8d86b3c170aa92bc2dd15c6ee727e6b7ad0c)
and [measured revision](https://github.com/nervosnetwork/faster-hex/commit/7562670e5023240675b71f742c55b8f5a67a3388).

## Git object IDs

A Git abbreviation can end halfway through a byte. Given a seven-byte output
buffer, `Hex::new(bytes).leading_digits(7).encode_to(dst)` writes three pairs
of hex digits and the high nibble of the fourth byte. It checks capacity
before writing and returns the written string. The previous caller split the
input, handled the odd digit and checked the result as UTF-8.
[gitoxide's buffer implementation](https://github.com/GitoxideLabs/gitoxide/blob/a7e739482cd6fe357ca8ebdbf82da5f1945e3e38/gix-hash/src/prefix.rs#L41-L64).

Whole-byte slice encoders are already familiar from `hex::encode_to_slice`
and `const_hex::encode_to_str`. Here the caller selects a digit count once and
can either format the view or write it into an exactly sized buffer.
[hex](https://docs.rs/hex/latest/hex/fn.encode_to_slice.html)
and [const-hex](https://docs.rs/const-hex/latest/const_hex/).

Only `gix_hash::Prefix::hex_to_buf` changed in the downstream experiment.
The ranges below cover two runs in each profile with the real `gix-hash`
types on an Apple M5 Pro. Times are nanoseconds per call.

| Object ID | Digits | Previous buffer implementation | `leading_digits(n).encode_to(dst)` |
|---|---:|---:|---:|
| SHA-1 | 7 | 4.12–4.39 | 1.50–1.53 |
| SHA-256 | 7 | 4.26–4.39 | 1.50–1.55 |
| SHA-1 | 40 | 4.52–4.62 | 1.38 |
| SHA-256 | 64 | 3.31–3.57 | 1.38 |

Git's `Display` implementation already owns a buffer for the full ID. Encoding
there and passing a slice to the formatter was faster than adapting this
writer to the new buffer method. The attempted substitution cost 3–9% on the
M5 Pro and 30–35% for seven digits on a Xeon 6975P-C in the default build.
Adding odd-digit handling to the shared encoder also took an ordinary hot
32-byte call from 1.37 to 2.45 ns. The selected view handles its own final
nibble. [gitoxide's formatter](https://github.com/GitoxideLabs/gitoxide/blob/a7e739482cd6fe357ca8ebdbf82da5f1945e3e38/gix-hash/src/oid.rs#L49-L59)
and [native prefix experiment](https://github.com/nervosnetwork/faster-hex/actions/runs/44721581787).

## CKB JSON and owned buffers

CKB's `JsonBytes` visitor checks the protocol's `0x` and returns owned bytes.
In a local experiment using the real `JsonBytes` type and its JSON error mapping,
`hex_decode_vec` took 809–810 ns for 4 KiB and 12.94–12.99 µs for 64 KiB.
The existing implementation, which allocates a destination for `hex_decode`,
took 823–832 ns and 13.66–13.69 µs respectively. At 32 bytes it took
24.63–24.67 ns, alongside 24.94–25.16 ns for the owned helper.
[CKB's visitor](https://github.com/nervosnetwork/ckb/blob/2061bc092a5dd447a741fad03b02628203b35e96/util/jsonrpc-types/src/bytes.rs#L85-L106).

Streaming the same 32-byte field through Serde's `collect_str` took
26.1–26.9 ns against 19.8–19.9 ns with CKB's existing serializer. Small
serialized values use the released stack-buffer path through 65 bytes.

An existing vector can reuse its spare capacity with `hex_decode_append`.
It returns the new suffix and restores the original length and contents on
an error. The following M5 Pro default-build estimates start with one byte
already in the vector. The validation rows measure successful inputs.

| Operation | 32 bytes | 4 KiB |
|---|---:|---:|
| Decode into a fresh vector, then extend the destination | 14.14 ns | 357 ns |
| `hex_decode_append` into the destination | 5.97 ns | 311 ns |
| `hex_check` on individual hex digits | 1.83 ns | 212 ns |
| `hex_validate` on complete byte pairs | 2.94 ns | 213 ns |

## Encoding and error diagnosis

On AArch64, one or two 16-byte NEON vectors cover 16–32-byte hashes. The
vectors overlap on a 20-byte SHA-1 and write identical digits. Longer inputs
enter the bulk loop directly. In an interleaved M5 Pro experiment, putting
the bulk check first cut 8–10% from several lengths between 33 and 63 bytes.
The suite covers 33, 48, 64 and 65 bytes at these transitions.

On the M5 Pro, the following values average the two independent estimates
for each revision, in nanoseconds per call. The rotating input cycles
through 4,096 distinct hashes.

| Workload | Default 2.0.0 | Default candidate | ThinLTO 2.0.0 | ThinLTO candidate |
|---|---:|---:|---:|---:|
| Encode 8 bytes, same input | 0.69 | 0.70 | 0.70 | 0.84 |
| Encode 8 bytes, rotating | 1.05 | 1.01 | 1.11 | 1.01 |
| Encode 32 bytes, rotating | 1.87 | 1.68 | 1.88 | 1.67 |
| Encode 65 bytes | 2.70 | 2.70 | 2.76 | 2.76 |
| Encode 4 KiB | 92.36 | 92.41 | 93.02 | 91.95 |
| Reject the last digit of a 32-byte hash | 20.00 | 12.66 | 17.77 | 12.83 |
| Reject the first digit of a 4 KiB payload | 4.99 | 3.65 | 4.96 | 3.43 |

The full M5 comparison against 2.0.0 flagged the hot 8-byte encoder and
32-byte JSON deserialization with ThinLTO. In the shared executables the
differences were 0.07–0.15 ns and 0.31–0.50 ns respectively. In the default
build only the pre-encoded JSON text control was flagged, by 0.08–0.17 ns.
Against the previous branch, the ThinLTO hot 8-byte case also measured
0.04–0.12 ns slower in the shared executables.
A separate four-workload repeat against 2.0.0 on the same M5 confirmed none
in either profile. Its two ThinLTO hot-encode pairs were 0.86 → 0.72
and 0.71 → 0.75 ns.

Testing inputs below 16 bytes ahead of the bulk branch still flagged the
hot 8-byte case and also slowed 48 bytes with ThinLTO. In that trial, the
two independent 48-byte pairs were 1.89 → 2.11 ns, and the shared pairs
were 1.88 → 1.93 and 1.90 → 2.09 ns. The bulk branch stays first.

The final x86 dispatcher and SSE4.1/AVX2 encoding kernels use the released
implementation. In an external crate targeting `x86_64-unknown-linux-gnu`,
the slice encoder, nine fixed-size encoder calls
from 2 to 65 bytes, the slice decoder and a four-character Git packet-length
decoder produced matching instructions against 2.0.0 after normalizing local
labels and symbol hashes. This held with core only, with `std` only and with
the default features, in both build profiles.

Against 2.0.0, the Intel Core i7-8700B, Xeon 6975P-C and AMD EPYC 7763
completed all 57 native comparisons in each profile without a confirmed
slowdown. On the Xeon, rotating 32-byte hashes took 3.14 ns on both
revisions in the default build. The seven-digit SHA-1 buffer workload
fell from 10.74 to 3.98 ns. [Native 2.0.0 comparison](https://github.com/nervosnetwork/faster-hex/actions/runs/44740764956).

The i7's initial rotating 32-byte estimates were higher for the candidate
with overlapping intervals. A focused repeat also passed on all three
runners. Its i7 default-build pairs went in opposite directions,
9.02 → 7.88 and 7.04 → 8.20 ns. [Raw encode repeat](https://github.com/nervosnetwork/faster-hex/actions/runs/44744120044).

Against the previous branch, one EPYC 9V74 ThinLTO case flagged the existing
seven-digit SHA-256 display path. The two shared assignments measured
13.76 → 13.97 and 13.78 → 13.92 ns. The same formatter and its caller
produced matching x86 instructions. An independent Git-workload repeat on
an EPYC 7763, a Xeon 6975P-C and an i7-8700B did not confirm the difference
on those machines. [Full branch comparison](https://github.com/nervosnetwork/faster-hex/actions/runs/44740789992)
and [focused repeat](https://github.com/nervosnetwork/faster-hex/actions/runs/44743498120).

The error path checks the first pair, skips valid 64-byte blocks with SIMD,
then tests four table entries at a time before identifying the exact byte.
Successful decoding avoids the diagnostic scan. Three experiments explain
the retained boundaries.

- An extra length check before x86 dispatch sped up some tiny encodes. On an
  EPYC 9V45, rotating 32-byte hashes took 2.13–2.16 ns before and
  2.35–2.39 ns after in the default-build shared executables. The short
  scalar decoder also kept its per-pair check after the combined check
  slowed a four-byte decode on an EPYC 9V74.
  [2.0.0 comparison](https://github.com/nervosnetwork/faster-hex/actions/runs/44735910991)
  and [previous branch comparison](https://github.com/nervosnetwork/faster-hex/actions/runs/44735916452).
- A different AVX2 shuffle made some bulk encodes faster and a hot 32-byte
  hash 20–24% slower on a Xeon Platinum 8573C with ThinLTO.
  [AVX2 experiment](https://github.com/nervosnetwork/faster-hex/actions/runs/44681614329).
- Smaller SIMD scans helped short errors, but cost 7–17% for an invalid
  last digit in a 4 KiB payload on an EPYC 9V45. Selecting one checker up
  front raised that same cost from 431 to 688 ns on a Xeon 6975P-C.
  [Scan-size repeat](https://github.com/nervosnetwork/faster-hex/actions/runs/44685729896)
  and [checker experiment](https://github.com/nervosnetwork/faster-hex/actions/runs/44688664932).

## Interpreting the measurements

In a seven-crate comparison on the M5 Pro, mixed-case decoding at 32 bytes
took 2.29 ns with faster-hex and 2.90 ns with fashex. At 4 KiB the two took
322 and 314 ns. Run `cargo bench-compare` to measure the same inputs on
another CPU.

The native comparison runs 57 workloads in each profile. Both revisions build
at the same path with the same dependency lock. Each runs twice on the same
host in opposite order. A suspected slowdown triggers longer samples in the
reverse order. If it persists, a shared consumer links both libraries and
repeats the measurement with their call sites exchanged. A workload is
flagged when the candidate's 95% intervals are slower in both independent
experiments and in both shared assignments. Artifacts include the CPU model,
binary hashes, raw samples and the differences seen only in independent builds.

The JSON comparison also times a shared writer on pre-encoded text. On a
Xeon 6975P-C, independent builds took 43.7 and 51.5 ns for the 32-byte
Serde field and 38.7 and 46.6 ns for the text control. In a shared
executable the field took 43.4–43.6 and 44.2–44.3 ns, with the control at
38.5–38.6 ns for both libraries. Even identical library source measured
29.0 against 47.7 ns for one late error on an EPYC 9V74, then 41.5 against
28.9 ns after exchanging slots. [JSON controls](https://github.com/nervosnetwork/faster-hex/actions/runs/44728944990)
and [same-revision comparison](https://github.com/nervosnetwork/faster-hex/actions/runs/44732274940).

For a native x86 comparison, dispatch the workflow from the branch containing
the harness. Use two disposable checkouts for local runs because the script
installs the shared benchmark sources and lock into them.

```sh
gh workflow run rust.yml --ref YOUR_BRANCH -f benchmark_base=v2.0.0
for lto in false thin; do
  CARGO_PROFILE_BENCH_LTO="$lto" python3 ci/bench_native.py ../base ../candidate "../results/$lto"
done
```
