# 04_gnu_licenses

This example shows how to deal with the GNU style licenses such as GPL, AGPL, LGPL, and GFDL

## Requirement

```ini
license = "Apache-2.0/GPL-2.0+ AND LGPL-3.0-only or gnu gpl v3"
```

## Config

```ini
[licenses]
allow = [
    "GPL-2.0-or-later",
    #"GPL-3.0-only",
]
```

## Description

GNU style licenses deviate from most of the other licenses in the SPDX license list due to the way they use the `-only` and `-or-later` suffixes appended to the root name and version of the license. In this example, by allowing `GPL-2.0-or-later` we satisfy the requirement of `GPL-2.0+` (which is the deprecated form), but we _don't_ satisfy the right hand side of the expression, because GNU license are checked pedantically, due to the GNU licenses being so incredibly annoying to deal with, so `GPL-2.0-or-later` does not allow `gnu gpl v3` (corrected to `GPL-3.0-only`).
