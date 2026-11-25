# Security Policy

## Reporting a Vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/nervosnetwork/faster-hex/security/advisories/new)
rather than opening a public issue. Include a minimal reproduction, affected
crate version, target architecture, and feature set where possible.

## Supported Versions

Security fixes are released on the latest `2.x` minor release line.

## Scope and Threat Model

In scope:

- Memory safety issues, undefined behavior, out-of-bounds reads or writes, or
  integer overflows across any supported architecture, CPU feature level, or
  feature combination.
- Violations of documented input validation or destination-preservation
  contracts (for example accepting malformed hex or modifying destination bytes
  on error in slice conversions).

Out of scope (explicit non-goals):

- **Constant-time execution**: `faster-hex` is a throughput-oriented codec.
  Scalar and short-input paths use data-dependent lookup tables, and checked
  decoders/validators return early on the first failing block. Do not use it
  where cache-timing or branch-timing side channels on secret keys or tokens
  are part of your threat model; use a dedicated constant-time codec (such as
  `ct-codecs`) instead.
- **Automatic memory zeroization**: stack buffers used by formatting and Serde
  adapters, as well as spare `Vec` capacity touched before an error in
  `hex_decode_append` or owned decoders, are not zeroized.
- **Unbounded allocation from untrusted input**: allocating helpers
  (`hex_decode_vec`, `hex_decode_append`, unbounded Serde adapters) reserve
  output storage based on the input length before character validation. Callers
  handling untrusted input must enforce application-level size limits first (or
  use `deserialize_bounded` / caller-owned slices).
