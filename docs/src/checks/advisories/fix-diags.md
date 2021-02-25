# Fix diagnostics

### `AF001` - advisory has no available patches

An advisory does not reference any patched versions of the crate that fix the issue the advisory pertains to.

### `AF002` - affected crate has no available patched versions

None of the patched versions for the crate can be found in the registry index.

### `AF003` - unable to patch crate

A crate could not be patched because it was either not found in the registry index, or, more likely, no published version of the crate was semver compatible with any of the versions of a dependency that we need update to include a patched version of the crate the advisory applies to.

### `AF004` - unpatchable source

The source for a crate was `git` or `local registry` and we are unable to patch it.

### `AF005` - local crate requirement does not match any required versions

Can't apply a patch to a local Cargo.toml manifest because it none of the version(s) that are required for the dependency are semver compatible with the version in it. This can be ignored by passing [`--allow-incompatible`](../../cli/fix.md#--allow-incompatible).

### `AF006` - no newer versions are available

There are no newer versions of a crate available to patch to.
