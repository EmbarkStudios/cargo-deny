# 09_bans

This example shows how to ban particular crates, and handle duplicate versions.

## Config

```ini
[dependencies.reqwest]
version = "0.10.1"
# Uncomment these to "fix" cargo deny check bans.
# 1. By disabling default features we remove the use of native-tls, which
# is implemented via openssl-sys on linux
# 2. openssl-sys also depends on an old version of autocfg, so we remove a
# duplicate as well!
# default-features = false
# features = ["rustls"]
```

```ini
# We restrict the platforms, this primarily gets rid of wasm32, which pulls
# in additional crates that include more duplicates
targets = [
    { triple = "x86_64-unknown-linux-musl" },
    { triple = "x86_64-pc-windows-msvc" },
    { triple = "x86_64-apple-darwin" },
]

[bans]
# We want duplicates to be errors rather than warnings
multiple-versions = "deny"
deny = [
    # We never want to use openssl
    { name = "openssl-sys" },
]
skip = [
    # rustls uses an old version of base64
    { name = "base64", version = "0.10" },
    # miow unfortunately still uses the ancient 0.2 version of winapi
    { name = "winapi", version = "=0.2.8" },
]
```

## Description

This example shows how the `bans` check works. `reqwest` by default uses native-tls, which on linux uses openssl. But we've decided to **deny** openssl, so adding a dependency on it triggers the lint. It also happens to pull in multiple
versions of a couple of dependencies, so we skip those. To "fix" this check, we would need to disable `reqwest`'s default features, and then enable the `"rustls"` feature, because we still want TLS!