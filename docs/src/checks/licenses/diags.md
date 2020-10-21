# Licenses Diagnostics

### `L001` - failed to satisfy license requirements

One or more licenses for a crate were rejected because they were not configured
to be [allowed](cfg.md#the-allow-and-deny-fields-optional).

### `L002` - license requirements satisfied

The license expression for a crate was [allowed](cfg.md#the-allow-and-deny-fields-optional), though there may be warnings.

### `L003` - unlicensed crate

No license expression could be found for a crate and it is considered [unlicensed](cfg.md#the-unlicensed-field-optional).

### `L004` - skipping private workspace crate

A workspace member is `publish = false` and was [skipped](cfg.md#the-private-field-optional).

### `L005` - license exception was not encountered

A [`licenses.exception`](cfg.md#the-exceptions-field-optional) was not used as
the crate it applied to was not encountered.

### `L006` - license was not encountered

A license in [`licenses.allow`](cfg.md#the-allow-and-deny-fields-optional) was
not found in any crate.
