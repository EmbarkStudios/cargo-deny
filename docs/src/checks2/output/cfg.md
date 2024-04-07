# The `[output]` section

The output table provides options for how/if diagnostics are outputted

## `output.feature-depth` (optional)

`integer`

### Default

```toml
[output]
feature-depth = 1
```

The maximum depth that features will be displayed when inclusion graphs are shown in
diagnostics, unless specified via `--feature-depth` on the command line. Only applies to
diagnostics that actually print features.

