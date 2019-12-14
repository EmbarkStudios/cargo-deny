# 04_gnu_licenses

This example shows how to deal with the GNU style licenses such as GPL, AGPL, LGPL, and GFDL

## Requirement

```toml
license = "GPL-2.0-or-later AND LGPL-3.0-only"
```

## Config

```toml
[licenses]
allow = [ "GPL-3.0" ]
copyleft = "deny"
```

## Description

GNU style licenses deviate from most of the other licenses in the SPDX license list due to the
way they use the `-only` and `-or-later` suffixes appended to the root name and version of the license.
In this example, by allowed `GPL-3.0` we satisfy the requirement of `GPL-2.0-or-later`, but because
we `deny` `copyleft`, the `LGPL-3.0-only` is still rejected.
