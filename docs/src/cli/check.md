# The `check` command

The check command is the primary subcommand of cargo-deny as it is what actually runs through all of the crates in your project and checks them against your configuration.

## Args

### `<which>`

The check(s) to perform. By default, **all** checks will be performed, unless one or more checks are specified here.

See [checks](../checks/index.html) for the list of available checks.

## Options

### `-A, --allow <ALLOW>`

Set lint allowed

### `--audit-compatible-output`

To ease transition from cargo-audit to cargo-deny, this flag will tell cargo-deny to output the exact same output as cargo-audit would, to `stdout` instead of `stderr`, just as with cargo-audit.

Note that this flag only applies when the output format is JSON, and note that since cargo-deny supports multiple advisory databases, instead of a single JSON object, there will be 1 for each unique advisory database.

### `-c, --config <CONFIG>`

Path to the config to use

Defaults to `<cwd>/deny.toml` if not specified

### `-d, --disable-fetch`

Disable fetching of the advisory database

When running the `advisories` check, the configured advisory database will be fetched and opened. If this flag is passed, the database won't be fetched, but an error will occur if it doesn't already exist locally.

### `-D, --deny <DENY>`

Set lint denied

### `--feature-depth <FEATURE_DEPTH>`

Specifies the depth at which feature edges are added in inclusion graphs

### `-g, --graph <GRAPH>`

Path to graph_output root directory

If set, a dotviz graph will be created for whenever multiple versions of the same crate are detected.

Each file will be created at `<dir>/graph_output/<crate_name>.dot`. `<dir>/graph_output/*` is deleted and recreated each run.

### `--hide-inclusion-graph`

Hides the inclusion graph when printing out info for a crate

By default, if a diagnostic message pertains to a specific crate, cargo-deny will append an inverse dependency graph to the diagnostic to show you how that crate was pulled into your project.

```text
some diagnostic message

the-crate
├── a-crate
└── b-crate
    └── c-crate
```

### `-s, --show-stats`

Show stats for all the checks, regardless of the log-level

### `-W, --warn <WARN>`

Set lint warnings
