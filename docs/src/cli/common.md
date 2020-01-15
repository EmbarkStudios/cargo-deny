# Common options

The subcommands share some common options that can be used before the
subcommand.

#### `--context`

The directory used as the context for the deny, if not specified, the current 
working directory is used instead. Must contain a Cargo.toml file.

#### `-L, --log-level`

The log level for messages, only log messages at or above the level will be 
emitted.

Possible values:
* `off` - No output will be emitted
* `error`
* `warn` (default)
* `info`
* `debug`
* `trace`

#### `-t, --target`

One or more platforms to filter crates with. If a dependency is target specific,
it will be ignored if it does match 1 or more of the specified targets. This 
overrides the top-level `targets = []` configuration value.
