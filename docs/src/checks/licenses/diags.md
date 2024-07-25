# Licenses Diagnostics

<!-- markdownlint-disable-next-line heading-increment -->
### `rejected`

One or more licenses for a crate were rejected because they were not configured to be [allowed](cfg.md#the-allow-and-deny-fields-optional).

### `accepted`

The license expression for a crate was [allowed](cfg.md#the-allow-and-deny-fields-optional), though there may be warnings.

### `unlicensed`

No license expression could be found for a crate and it is considered [unlicensed](cfg.md#the-unlicensed-field-optional).

### `skipped-private-workspace-crate`

A workspace member is `publish = false` and was [skipped](cfg.md#the-private-field-optional).

### `license-not-encountered`

A license in [`licenses.allow`](cfg.md#the-allow-and-deny-fields-optional) was not found in any crate.

This diagnostic can be silenced by configuring the [`licenses.unused-allowed-license`](cfg.md#the-unused-allowed-license-field-optional) field to "allow".

### `license-exception-not-encountered`

A [`licenses.exception`](cfg.md#the-exceptions-field-optional) was not used as the crate it applied to was not encountered.
