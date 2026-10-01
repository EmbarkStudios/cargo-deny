# Advisories Diagnostics

<!-- markdownlint-disable-next-line heading-increment -->

### `vulnerability`

A `vulnerability` advisory was detected for a crate.

### `notice`

A `notice` advisory was detected for a crate.

### `unmaintained`

An [`unmaintained`](cfg.md#unmaintained) advisory was detected for a crate.

### `unsound`

An `unsound` advisory was detected for a crate.

### `yanked`

A crate using a version that has been [yanked](cfg.md#yanked) from the registry index was detected.

### `index-failure`

An error occurred trying to read or update the registry index (typically crates.io) so cargo-deny was unable to check the current yanked status for any crate.

### `index-cache-load-failure`

Failed to load the cached index details for a crate.

### `advisory-not-detected`

An advisory in [`advisories.ignore`](cfg.md#ignore) didn't apply to any crate. This could happen if the advisory was [withdrawn](https://docs.rs/rustsec/latest/rustsec/advisory/struct.Metadata.html#structfield.withdrawn), or the version of the crate no longer falls within the range of affected versions the advisory applies to.

This diagnostic can be silenced by configuring the [`advisories.unused-ignored-advisory`](cfg.md#unused-ignored-advisory) field to `'allow'`.

### `advisory-ignored`

An advisory in [`advisories.ignore`](cfg.md#ignore) was encountered.

### `advisory-ignore-expired`

An advisory in [`advisories.ignore`](cfg.md#ignore) was published over the limit specified in either the ignore's [`expiry`](cfg.md#expiry) or the default [`ignore-expiry`](cfg.md#ignore-expiry).

### `advisory-ignore-disallowed-dependent`

A direct dependent of a crate that an advisory applied to was not present in the [`ignore.allow`](cfg.md#allow) list.

### `advisory-ignore-allowed-dependent-missing`

A [PackageSpec](../cfg.md#package-specs) in the [`ignore.allow`](cfg.md#allow) list was not a direct dependent of any crate that the advisory applies to.

### `unknown-advisory`

An advisory in [`advisories.ignore`](cfg.md#ignore) wasn't found in any of the configured advisory databases, usually indicating a typo, as advisories, at the moment, are never deleted from the database, at least the canonical [advisory-db](https://github.com/rustsec/advisory-db).

### `yanked-ignored`

A yanked crate version was ignored via [`advisories.ignore`](cfg.md#ignore).

### `yanked-not-detected`

A yanked crate version was ignored via [`advisories.ignore`](cfg.md#ignore), but it was not found in the crate graph.

This diagnostic can be silenced by configuring the [`advisories.unused-ignored-advisory`](cfg.md#unused-ignored-advisory) field to `'allow'`.
