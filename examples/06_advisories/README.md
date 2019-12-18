# 06_advisories

This example shows cargo-deny's default behavior when checking security advisories

## Config

```toml
[dependencies]
# ammonia had a stack overflow < 2.1.0
# https://github.com/RustSec/advisory-db/blob/01ac6725d549dbc7873250fe2a55e54d528fe945/crates/ammonia/RUSTSEC-2019-0001.toml
ammonia = "1.0.0"
# libusb is unmaintained
# https://github.com/RustSec/advisory-db/blob/5b35b71cf74eed58696aeeb5a764a9f0a66fe7ba/crates/libusb/RUSTSEC-2016-0004.toml
libusb = "0.3.0"
```

## Description

When checking security advisories (by default from https://github.com/RustSec/advisory-db) via `cargo deny check advisories`, the default behavior is to **deny** security vulnerabilities and **warn** on unmaintained crates. In this example, we have one crate with a security vulnerability, `ammonia`, and one unmaintained crate, `libusb`, so we get one error and one warning by default.