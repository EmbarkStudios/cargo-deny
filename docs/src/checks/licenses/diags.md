# Licenses Diagnostics

<!-- markdownlint-disable-next-line heading-increment -->

### `rejected`

One or more licenses for a crate were rejected because they were not configured to be [allowed](cfg.md#allow).

### `accepted`

The license expression for a crate was [allowed](cfg.md#allow), though there may be warnings.

### `unlicensed`

No license expression could be found or synthesized for a crate and it is considered unlicensed.

### `skipped-private-workspace-crate`

A workspace member is `publish = false` and was [skipped](cfg.md#private).

### `license-not-encountered`

A license in [`licenses.allow`](cfg.md#allow) was not found in any crate.

This diagnostic can be silenced by configuring the [`licenses.unused-allowed-license`](cfg.md#unused-allowed-license) field to `'allow'`.

### `license-exception-not-encountered`

A [`licenses.exception`](cfg.md#exceptions) was not used as the crate it applied to was not encountered.

### `empty-license-field`

The `license` field of a package was present but empty. This is a bug that used to be allowed by crates.io, and possibly other registry implementations. cargo-deny will attempt to fallback to finding license files in the package's source.

### `gather-failure`

There was an error when trying to find one or more license files in a package's source.

### `no-license-field`

The package did not use the `license` field, cargo-deny will attempt to fallback to finding license files in the package's source.

### `missing-clarification-file`

A file referenced by a [clarification](cfg.md#clarify) was not found.

### `parse-error`

The SPDX expression for a crate could not be parsed.
