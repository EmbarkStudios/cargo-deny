# Common options

The subcommands share some common options that can be used before the subcommand.

#### `--manifest-path`

The path to a `Cargo.toml` file which is used as the context for operations.

#### `--all-features` (single crate or workspace)

Enables all features when determining which crates to consider. Works for both single crates and workspaces.

#### `--no-default-features` (single crate only)

Disables the `default` feature for a crate when determing which crates to consider.

#### `--features` (single crate only)

Space-separated list of features to enable when determining which crates to consider.

#### `--workspace`

Forces all workspace crates to be used as roots in the crate graph that we operate on, unless they are excluded by other means. By default, if you specify a [virtual manifest](https://doc.rust-lang.org/cargo/reference/manifest.html#virtual-manifest), all crates in the workspace will be used as roots. However, if you specify a normal package manifest somewhere inside a workspace, only that crate will be used as a graph root, and only other workspaces crates it depends on will be included in the graph. If you want to specify a sub-crate in a workspace, but still include all other crates in the workspace, you can use this flag.

#### `--exclude`

Exclude the specified package(s) from the crate graph. Unlike other cargo subcommands, it doesn't have to be used in conjunction with the `--workspace` flag. This flag may be specified multiple times.

This uses a similar (though slightly more strict) [Package ID specification](https://doc.rust-lang.org/cargo/commands/cargo-pkgid.html) to other cargo subcommands.

Packages can also be excluded in your [configuration](../checks/cfg.md#the-exclude-field-optional) files, specifying this on the command line will append the package ID to the list that may exist in your configuration.

#### `-L, --log-level`

The log level for messages, only log messages at or above the level will be emitted.

Possible values:

* `off` - No output will be emitted
* `error`
* `warn` (default)
* `info`
* `debug`
* `trace`

### `--format`

The format of the output of both log and diagnostic messages.

Possible values:

* `human` (default) - Output for the pesky humans
* `json` - Each log message/diagnostic is outputted as a single line JSON object

### `--color`

Whether coloring is applied to human-formatted output, using it on JSON output has no effect.

Possible values:

* `auto` (default) - Coloring is applied if the output stream is a TTY
* `always` - Coloring is always applied
* `never` - No coloring is applied for any output

#### `-t, --target`

One or more platforms to filter crates with. If a dependency is target specific, it will be ignored if it does not match at least 1 of the specified targets. This overrides the top-level [`targets = []`](../checks/cfg.md) configuration value.
