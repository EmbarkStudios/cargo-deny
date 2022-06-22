# Bans diagnostics

### `B001` - crate is explicitly banned

A crate which is [explicitly banned](cfg.md#the-allow-and-deny-fields-optional) was detected.

### `B002` - crate is explicitly allowed

A crate which is [explicitly allowed](cfg.md#the-allow-and-deny-fields-optional) was detected.

### `B003` - crate is implicitly banned

When using [`bans.allow`](cfg.md#the-allow-and-deny-fields-optional), a crate was detected that wasn't in that list.

### `B004` - found duplicate entries for crate

One or more [duplicate versions](cfg.md#the-multiple-versions-field-optional) of the same crate were detected.

### `B005` - crate skipped when checking for duplicates

A crate version that matched an entry in [`bans.skip`](cfg.md#the-skip-field-optional) was encountered.

### `B006` - found wildcard dependency for crate

A crate was included via a [wildcard dependency](cfg.md#the-wildcards-field-optional) by one or more crates.

### `B007` - skipped crate was not encountered

A crate version in [`bans.skip`](cfg.md#the-skip-field-optional) was not encountered.

### `B008` - banned crate allowed by wrapper

A crate in `bans.deny` was allowed since it was referenced by a [`wrappers`](cfg.md#the-wrappers-field-optional) crate.

### `B009` - direct parent of banned crate was not marked as a wrapper

A crate in `bans.deny` had one or more [`wrappers`](cfg.md#the-wrappers-field-optional) crates, but a crate not in that list had a direct dependency on the banned crate.

### `B010` - skip tree root was not found in the dependency graph

A crate version in [`bans.skip-tree`](cfg.md#the-skip-tree-field-optional) was not encountered.

### `B011` - skipping crate due to root skip

A crate was skipped from being checked as a duplicate due to being transitively referenced by a crate version in [`bans.skip-tree`](cfg.md#the-skip-tree-field-optional).

### `B012` - crate has build script but is not allowed to have one

A crate which has been denied because it has a build script but is not part of the [`bans.allow-build-script`](cfg.md#the-allow-build-scripts-field-optional) list.
