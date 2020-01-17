# The `check` command

The check command is the primary subcommand of cargo-deny as it is what actually
runs through all of the crates in your project and checks them against your
configuration.

## Args

### `<which>`

The check(s) to perform. By default, **all** checks will be performed, unless 
one or more specific checks are specified.

See [checks](../checks/index.html) for the possible checks available.

## Flags

### `-d, --disable-fetch`

Disables fetching of advisory databases, if they would be loaded. If disabled, 
and there is not already an existing advisory database locally, an error will 
occur

### `-h, --hide-inclusion-graph`

Hides the inclusion graph when printing out info for a crate.

By default, if a diagnostic message pertains to a specific crate, cargo-deny 
will append an inverse dependency graph to the diagnostic to show you how that 
crate was pulled into your project.

```
some diagnostic message

the-crate
├── a-crate
└── b-crate
    └── c-crate
```

## Options

### `-c, --config`

The path to the config file used to determine which crates are allowed or 
denied. Will default to <context>/deny.toml if not specified.

### `-g, --graph`

A root directory to place dotviz graphs into when duplicate crate versions are
detected. Will be <dir>/graph_output/<crate_name>.dot. The /graph_output/* is 
deleted and recreated each run.
