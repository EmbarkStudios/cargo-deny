# 07_deny_sources

This example shows how to use cargo-deny to deny and only support explicitly allowed sources for crates

## Config

```ini
[dependencies]
bitflags = { git = "https://github.com/bitflags/bitflags.git" }
```

```ini
[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-git = [
    "https://github.com/bitflags/bitflags.git"
]
```

## Description

TODO