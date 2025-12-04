# 07_deny_sources

This example shows how to use cargo-deny to deny crate sources not explicitly allowed.

## Config

```ini
[dependencies]
# this works, crates.io is allowed by default
log = "0.4.8"

# this would also work, because crates.io is allowed by default
#spdx = "0.13"

# this will fail as our deny.toml is denying unknown git repos
# and this URL is not in the allow list
cfg-expr = { git = "https://github.com/EmbarkStudios/cfg-expr" }

# This is allowed because we explicitly specified it
spdx = { git = "https://github.com/EmbarkStudios/spdx" }
```

```ini
[sources]
unknown-registry = "deny"
unknown-git = "deny"

# here we can explicitly enable registries we allow,
# crates.io is already added by default though - so this is not needed
# allow-registry = [
#     "https://github.com/rust-lang/crates.io-index"
# ]

allow-git = [
    "https://github.com/EmbarkStudios/spdx",
    #"https://github.com/EmbarkStudios/cfg-expr",
]

# Or we could allow the entire org
#[sources.allow-org]
#github = ["EmbarkStudios"]
```

## Description

In some cases it is useful to restrict the source of a crates in your graph, disallowing crates sourced from anywhere not explicitly allowed. By default, crates from crates.io are allowed, but crates source from git must be explicitly allowed either by their full url, or via their organization in cases like github, gitlab, or similar.
