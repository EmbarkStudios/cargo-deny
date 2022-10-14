# Advisories Diagnostics

### `vulnerability`

A [`vulnerability`](cfg.md#the-vulnerability-field-optional) advisory was detected for a crate.

### `notice`

A [`notice`](cfg.md#the-notice-field-optional) advisory was detected for a crate.

### `unmaintained`

An [`unmaintained`](cfg.md#the-unmaintained-field-optional) advisory was detected for a crate.

### `unsound`

An [`unsound`](cfg.md#the-unsound-field-optional) advisory was detected for a crate.

### `yanked`

A crate using a version that has been [yanked](cfg.md#the-yanked-field-optional) from the registry index was detected.

### `index-failure`

An error occurred trying to read or update the registry index (typically crates.io) so cargo-deny was unable to check the current yanked status for any crate.

### `advisory-not-detected`

An advisory in [`advisories.ignore`](cfg.md#the-ignore-field-optional) didn't apply to any crate. This could happen if the advisory was [withdrawn](https://docs.rs/rustsec/latest/rustsec/advisory/struct.Metadata.html#structfield.withdrawn), or the version of the crate no longer falls within the range of affected versions the advisory applies to.

### `unknown-advisory`

An advisory in [`advisories.ignore`](cfg.md#the-ignore-field-optional) wasn't found in any of the configured advisory databases, usually indicating a typo, as advisories, at the moment, are never deleted from the database, at least the canonical [advisory-db](https://github.com/rustsec/advisory-db).
