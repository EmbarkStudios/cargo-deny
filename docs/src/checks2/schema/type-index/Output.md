# `Output`

**Type:** `object`

The output table provides options for how/if diagnostics are outputted

## `feature-depth`

**Type:** `integer`<br>
**Key:** `optional`

The maximum depth that features will be displayed when inclusion graphs are shown in
diagnostics, unless specified via `--feature-depth` on the command line. Only applies to
diagnostics that actually print features.


### Default

```toml
feature-depth = 1
```