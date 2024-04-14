# `bans`

**Type:** `object`<br>
**Required:** `no`

Checks for specific crates in your graph, as well as duplicates.

This section is considered when running `cargo deny check bans`.


## `bans.allow`

**Type:** `array`<br>
**Required:** `no`

Determines specific crates that are allowed. If the `allow` list has one or more entries, then
any crate not in that list will be denied, so use with care. Each entry uses the same
[PackageSpec](https://embarkstudios.github.io/cargo-deny/checks/cfg.html#package-spec)
as other parts of cargo-deny's configuration.


### Array item

**Type:** [`PackageSpec`](/checks2/type-index.html#packagespec) `(string)`