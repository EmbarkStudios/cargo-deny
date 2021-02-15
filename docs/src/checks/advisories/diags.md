# Advisories Diagnostics

### `A001` - security vulnerability detected

A [`vulnerability`](cfg.md#the-vulnerability-field-optional) advisory was detected for a crate.

### `A002` - notice advisory detected

A [`notice`](cfg.md#the-notice-field-optional) advisory was detected for a crate.

### `A003` - unmaintained advisory detected

An [`unmaintained`](cfg.md#the-unmaintained-field-optional) advisory was detected for a crate.

### `A004` - unsound advisory detected

An [`unsound`](cfg.md#the-unsound-field-optional) advisory was detected for a crate.

### `A005` - detected yanked crate

A crate using a version that has been [yanked](cfg.md#the-yanked-field-optional) from the registry index was detected.

### `A006` - unable to check for yanked crates

An error occurred trying to read or update the registry index (typically crates.io) so cargo-deny was unable to check the current yanked status for any crate.

### `A007` - advisory was not encountered

An advisory in [`advisories.ignore`](cfg.md#the-ignore-field-optional) didn't apply to any crate.

### `A008` - advisory not found in any advisory database

An advisory in [`advisories.ignore`](cfg.md#the-ignore-field-optional) wasn't found in any of the configured advisory databases.
