# Native optimization results

The comparison uses 2.0.0 as its baseline. Sizes count binary bytes, so the
32-byte cases encode a hash or decode 64 hex digits. Each timing includes the
public API's validation and CPU dispatch where applicable.
[Measured revision](https://github.com/nervosnetwork/faster-hex/commit/3394238eca1e1753a1aa909e650685a4bb03230c)
and [native x86 results](https://github.com/nervosnetwork/faster-hex/actions/runs/44683997182).

## Encoding and diagnostics

On AArch64, one or two 16-byte NEON loads cover inputs from 16 through 32
bytes. Larger inputs keep the existing 64-byte loop and tail handling. A trial
that reduced the loop batch size slowed 4 KiB encoding on the M5 Pro. With the selected
implementation, encoding rotating 32-byte hashes took 1.80 → 1.62 ns in the
default profile and 1.85 → 1.65 ns with ThinLTO. The default 4 KiB encoder
stayed near 90 ns.

The x86 encoder retains the 2.0.0 implementation. An AVX2 shuffle change
improved several bulk cases, but the Xeon Platinum 8573C took 20–24% longer
to encode a hot 32-byte hash with ThinLTO in two paired runs.
[AVX2 experiment](https://github.com/nervosnetwork/faster-hex/actions/runs/44681614329).

After an invalid decode with at least 16 input digits, the diagnostic path
checks the first pair, skips valid 256-byte blocks, then narrows the search
to at most 16 bytes. It also supplies the first invalid byte's index for `hex_validate`.
Valid decoding uses the existing kernels.

The table shows the latency in nanoseconds to report an invalid last digit,
as 2.0.0 → this revision. Each value averages the two Criterion estimates for
that revision on the same runner.

| CPU | 32 bytes, default | 32 bytes, ThinLTO | 4 KiB, default | 4 KiB, ThinLTO |
| --- | ---: | ---: | ---: | ---: |
| Apple M5 Pro | 16.9 → 8.0 | 17.1 → 8.1 | 447 → 430 | 464 → 445 |
| AMD EPYC 9V45 | 19.9 → 17.6 | 18.6 → 17.2 | 330 → 319 | 289 → 309 |
| Intel Xeon 6975P-C | 37.6 → 23.9 | 36.9 → 25.5 | 430 → 395 | 427 → 375 |
| Intel Core i7-8700B | 51.1 → 44.8 | 85.0 → 77.1 | 856 → 617 | 1078 → 1045 |

The two i7 ThinLTO pairs moved in opposite directions at both sizes. The
workflow summary preserves the individual estimates. The 9V45's 4 KiB
ThinLTO result was 7% slower, while its default build improved. A previous
version that dispatched once per 64 bytes took about
760 ns for the same 4 KiB failure on an EPYC 7763, against 600 ns for 2.0.0.
[Earlier diagnostic comparison](https://github.com/nervosnetwork/faster-hex/actions/runs/44682638785).

## Costs of the new APIs

On the M5 Pro, decoding into a preallocated vector with `hex_decode_append`
took 5.82 ns for 32 bytes and 307 ns for 4 KiB. Decoding to a new vector and
extending the same destination took 13.93 ns and 352 ns. Both timers preserve
an existing prefix and verify the appended bytes.

Writing seven digits with `Hex::leading_digits(7)` to a reusable string took
6.21 ns. Checking the 64 digits of a valid hash took 2.90 ns with
`hex_validate` and 1.82 ns with `hex_check`. The former checks whole byte
pairs and can return the first invalid byte's position. The latter accepts
odd lengths and returns a boolean.

## Reproducing the measurements

Run the workflow on a branch that contains the comparison job.

```sh
gh workflow run rust.yml --ref YOUR_BRANCH -f benchmark_base=v2.0.0
```

Each runner uses Rust 1.95.0, the same dependency lock and the baseline's
Criterion timers for both commits. It runs baseline, candidate, candidate,
baseline on one host for each profile. The rotating test cycles through 4,096
hashes. The artifacts contain the CPU model, commit IDs, raw samples and sizes
of the linked benchmark executables. Hosted runner CPU models can vary.
On Linux the three benchmark executables grew by 384–2,352 bytes of text in
the default profile and by 16–1,600 bytes with ThinLTO.
The Core i9-14900K remains an open measurement for a dedicated machine.

For a local comparison, use two disposable checkouts. The script copies the
baseline's benchmarks and lockfile into the candidate checkout.

```sh
for lto in false thin; do
  CARGO_PROFILE_BENCH_LTO="$lto" python3 ci/bench_native.py ../base ../candidate "../results/$lto"
done
```
