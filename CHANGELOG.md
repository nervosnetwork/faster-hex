# [0.8.2](https://github.com/nervosnetwork/faster-hex/compare/v0.8.1...v0.8.2) (2023-11-19)

### Bug Fixes

* Fix `hex_decode` panic when `dst.len` > `src.len * 2` [pr#38](https://github.com/nervosnetwork/faster-hex/pull/38)

# [0.8.1](https://github.com/nervosnetwork/faster-hex/compare/v0.8.0...v0.8.1) (2023-11-19)

### Bug Fixes

* Fix Fails to build on x86 without SSE2 [pr#33](https://github.com/nervosnetwork/faster-hex/pull/33)
* Fix deserializing owned hex string [pr#35](https://github.com/nervosnetwork/faster-hex/pull/35)

# [0.8.0](https://github.com/nervosnetwork/faster-hex/compare/v0.7.0...v0.8.0) (2023-02-27)

### Features

* Add serde feature for faster-hex ([pr#28](https://github.com/nervosnetwork/faster-hex/pull/28))

# [0.7.0](https://github.com/nervosnetwork/faster-hex/compare/v0.6.1...v0.7.0) (2023-02-27)

### Features

* Allow faster-hex encode/decode to/from lower/uppercase  ([pr#26](https://github.com/nervosnetwork/faster-hex/pull/26))
### Bug Fixes
* Improve encode/decode length check ([pr#27](https://github.com/nervosnetwork/faster-hex/pull/27))

### Features

* Improve performance of fallback implementation ([pr#19](https://github.com/nervosnetwork/faster-hex/pull/19))

### Bug Fixes

* hex_string should not return Result ([0a5b5f4](https://github.com/nervosnetwork/faster-hex/commit/0a5b5f4e60ba149b30991e322f2e474c63813d21))



# [0.5.0](https://github.com/nervosnetwork/faster-hex/compare/v0.4.1...v0.5.0) (2021-01-13)



# [0.4.0](https://github.com/nervosnetwork/faster-hex/compare/v0.3.1...v0.4.0) (2019-09-10)


### Bug Fixes

* Do not expose hex_check_see on non-supported platform ([3e1cc75](https://github.com/nervosnetwork/faster-hex/commit/3e1cc75c1352e604709f32162ca55bdb64544779))



## [0.3.1](https://github.com/nervosnetwork/faster-hex/compare/v0.1.0...v0.3.1) (2019-03-12)


### Features

* check decode length ([857b0f7](https://github.com/nervosnetwork/faster-hex/commit/857b0f7511ce3b33a315768972b155385f823d1e))
* fuzz test ([b888363](https://github.com/nervosnetwork/faster-hex/commit/b888363adb3e3734bce2a8e2b3469191cdf20f5d))
* impl hex decode ([abb37fa](https://github.com/nervosnetwork/faster-hex/commit/abb37fa99e2346059218a32d62d25ac4d28f1d91))



# [0.1.0](https://github.com/nervosnetwork/faster-hex/compare/6c884911ba875ba3ac15f02fbba094cd9efef49a...v0.1.0) (2018-10-30)


### Features

* leverage simd to hex faster ([6c88491](https://github.com/nervosnetwork/faster-hex/commit/6c884911ba875ba3ac15f02fbba094cd9efef49a))
