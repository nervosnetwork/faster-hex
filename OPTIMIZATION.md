# Further optimization

Ideas to evaluate after the 1.0 candidate freeze; gains are not yet established.

- **Owned decoding:** extend array measurements beyond Hash256 and measure
  `hex_decode_vec` directly. Explore validating and decoding large inputs in
  one pass, starting with existing kernels. Private output can be discarded
  on failure; borrowed destinations must still remain entirely unchanged.
- **Late errors:** explore retaining the first failing block during validation
  so diagnostics can avoid scanning the valid prefix again. Preserve the first
  invalid byte, error precedence and the fast path for valid Hash256 input.
- **Remaining gaps:** revisit 4-byte, 65-byte and large-buffer differences on
  native Intel, AMD and ARM CPUs. Compare backend thresholds before adding
  special cases; preserve both hot and rotating Hash256 performance.
- **Calling contexts:** extend build-profile measurements to production settings,
  multiple call sites and generated code size. Separate codec changes from
  JSON-writing costs, code placement and hosted-runner variance.
- **Development feedback:** add a few short/boundary/error cases to the existing
  focused benchmarks. Keep baseline comparison quick; extend native validation
  to 32-bit x86 when hardware permits.

Keep APIs and checked contracts fixed. Use identical benchmark harnesses,
independent builds and repeated native x86/ARM comparisons. Retain a change only
when its benefit is reproducible and its complexity earns long-term maintenance.
A short-input gain can qualify without a Hash256 gain if hot/rotating Hash256 and
other important lengths show no reproducible regression. Prefer reusing safe code
and existing SIMD kernels over adding new unsafe paths.
