# Advisories Diagnostics

### `vulnerability` - security vulnerability detected

A [`vulnerability`](cfg.md#the-vulnerability-field-optional) advisory was detected for a crate.

### `notice` - notice advisory detected

A [`notice`](cfg.md#the-notice-field-optional) advisory was detected for a crate.

### `unmaintained` - unmaintained advisory detected

An [`unmaintained`](cfg.md#the-unmaintained-field-optional) advisory was detected for a crate.

### `unsound` - unsound advisory detected

An [`unsound`](cfg.md#the-unsound-field-optional) advisory was detected for a crate.

### `yanked` - detected yanked crate

A crate using a version that has been [yanked](cfg.md#the-yanked-field-optional) from the registry index was detected.

### `index_failure` - unable to check for yanked crates

An error occurred trying to read or update the registry index (typically crates.io) so cargo-deny was unable to check the current yanked status for any crate.

### `advisory_not_detected` - advisory was not detected

An advisory in [`advisories.ignore`](cfg.md#the-ignore-field-optional) didn't apply to any crate. This could happen if the advisory was [withdrawn](https://docs.rs/rustsec/latest/rustsec/advisory/struct.Metadata.html#structfield.withdrawn), or the version of the crate no longer falls within the range of affected versions the advisory applies to.

### `unknown_advisory` - advisory not found in any advisory database

An advisory in [`advisories.ignore`](cfg.md#the-ignore-field-optional) wasn't found in any of the configured advisory databases, usually indicating a typo, as advisories, at the moment, are never deleted from the database, at least the canonical [advisory-db](https://github.com/rustsec/advisory-db).
