# 02_deny_copyleft

This example shows how to explicitly deny certain licenses that will be checked against
the license requirements of every crate in your dependency graph.

## Requirement

```ini
license = "MIT AND Apache-2.0"
```

## Config

```ini
[licenses]
allow = [ "MIT" ]
deny = [ "Apache-2.0" ]
```

## Description

Just as we can allow specific licenses, we can deny specific ones via `[licenses.deny]`. Note that the license requirement
has changed to use the operator `AND` instead of `OR` which means that the user is required to license the crate under
both of the licenses, so even though we still allow `MIT`, our denial of `Apache-2.0` causes the expression to fail and
cargo-deny to emit an error that we did not accede to the license requirements of the crate.
