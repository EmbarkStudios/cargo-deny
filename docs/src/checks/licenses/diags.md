# License Diagnostics

## `L001` - failed to satisfy license requirements

One or more licenses for a crate were rejected because they were not configured
to be accepted.

## `L002` - license requirements satisfied

The license expression for a crate was accepted, though there may be warnings.

## `L003` - unlicensed crate

No license expression could be found for a crate and it is considered unlicensed.

## `L004` - skipping private workspace crate

A workspace member is `publish = false` and `licenses.private.ignore = true`.

## `L005` - license exception was not encountered

A `licenses.exception` was not used as the crate it applied to was not encountered.

## `L006` - license was not encountered

A license in `licenses.allow` was not found in any crate.
