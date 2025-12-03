# 02_deny_license

This example shows how the license check will fail when all required licenses have not been explicitly allowed.

## Requirement

```ini
license = "MIT AND Apache-2.0"
```

## Config

```ini
[licenses]
allow = ["MIT"]
```

## Description

Due to the license requirements of the crate being both `MIT` **AND** `Apache-2.0`, we would need to accept both licenses, but since we only accept `MIT`, the license check fails because `Apache-2.0` is required if we want to use the crate, but we didn't specify that. This is the mechanism that allows you to only specify licenses you want to allow, and the license check will fail when a crate changes its licensing terms to something that does not match your acceptance list.
