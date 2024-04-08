# config

The top level config for cargo-deny, by default called `deny.toml`.

## Example - cargo-deny's own configuration

```ini
{{#include ../../../deny.toml}}
```

## The `[advisories]` section

Checks advisory databases for crates with security vulnerabilities,
or that have been marked as Unmaintained, or which have been yanked from
their source registry.

This section is considered when running `cargo deny check advisories`.


See [advisories config](advisories/cfg.html) for more info.

## The `[bans]` section

Checks for specific crates in your graph, as well as duplicates.

This section is considered when running `cargo deny check bans`.


See [bans config](bans/cfg.html) for more info.

## The `[graph]` section

The graph table configures how the dependency graph is constructed and thus which crates the
checks are performed against


See [graph config](graph/cfg.html) for more info.

## The `[output]` section

The output table provides options for how/if diagnostics are outputted

See [output config](output/cfg.html) for more info.