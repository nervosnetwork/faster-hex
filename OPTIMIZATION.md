# Further optimization

Remaining directions after the native optimization study. The 1.0 API is still
open to design changes until release; gains below are not established.

- **Owned decoding:** single-pass array/Vec loops improved some large inputs,
  but short-input regressions and inconsistent x86 gains ruled them out. Revisit
  a loop that leaves existing small kernels and their calling convention intact.
- **Error positions:** carrying a failing-block offset avoids rescanning, but
  changed return representations slowed valid short inputs. Coarse cold scans
  also regressed shorter errors. Seek a representation that retains precise
  diagnostics without adding work to successful Hash256 calls.
- **SIMD thresholds:** revisit short x86 and 65-byte tails on dedicated Intel/AMD
  hardware. AVX-512 batching helped large checks but hurt short paths; isolate
  those costs before adding backend-specific thresholds.
- **Native coverage:** reproduce marginal differences on dedicated Intel/AMD
  CPUs, especially the i9-14900K. Keep default and ThinLTO builds, multiple call
  sites and code size in the comparison. Add native 32-bit x86 execution when
  hardware is available.

Make API tradeoffs explicit. Use identical benchmark harnesses,
independent builds and repeated native x86/ARM comparisons. Retain a change only
when its benefit is reproducible and its complexity earns long-term maintenance.
A short-input gain can qualify without a Hash256 gain if hot/rotating Hash256 and
other important lengths show no reproducible regression. Prefer reusing safe code
and existing SIMD kernels over adding new unsafe paths.
