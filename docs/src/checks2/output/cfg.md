# `output` (optional)

`object`

The output table provides options for how/if diagnostics are outputted

## `output.feature-depth` (optional)

`integer`

The maximum depth that features will be displayed when inclusion graphs are shown in
diagnostics, unless specified via `--feature-depth` on the command line. Only applies to
diagnostics that actually print features.


### Default

```toml
[output]
feature-depth = 1
```