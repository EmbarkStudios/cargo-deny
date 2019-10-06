# 01_allow_license

This example shows how to selectively allow certain licenses that will be checked against
the license requirements of every crate in your dependency graph.

## Requirement

```toml
license = "MIT OR Apache-2.0"
```

## Config

```toml
[license]
allow = [ "MIT" ]
```

## Description

The example crate uses the same dual-licensing of the actual cargo-deny project, namely `MIT OR Apache-2.0`,
and this expression is checked against our configured allow list, which is simply `MIT`. This license check
passes because the license expression allows you to license it under either `MIT` or `Apache-2.0` at your option.
