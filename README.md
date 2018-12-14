# faster-hex

[![License]](#license)
[![crate-badge]](https://crates.io/crates/faster-hex)

[crate-badge]: https://img.shields.io/crates/v/faster-hex.svg
[license]: https://img.shields.io/badge/License-MIT-green.svg

This program implements hex encoding a slice into a predetermined
destination using various different instruction sets.

## License

This project is licensed under the [MIT license](LICENSE).

### Third party software

This product includes copies and modifications of software developed by third parties:

* [src/encode.rs](src/encode.rs) is based on
  [stdsimd](https://github.com/rust-lang-nursery/stdsimd), licensed
  under the MIT license or the Apache License (Version 2.0).

See the source code files for more details.

Copies of third party licenses can be found in [LICENSE-THIRD-PARTY](LICENSE-THIRD-PARTY).
