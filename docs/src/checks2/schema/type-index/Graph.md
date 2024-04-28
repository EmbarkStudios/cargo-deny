# `Graph`

**Type:** `object`

The graph table configures how the dependency graph is constructed and thus which crates the
checks are performed against


## `targets`

**Type:** `array`<br>
**Key:** `optional`

By default, cargo-deny will consider every single crate that is resolved by cargo, including
target specific dependencies e.g.

```toml
[target.x86_64-pc-windows-msvc.dependencies]
winapi = "0.3.8"

[target.'cfg(target_os = "fuchsia")'.dependencies]
fuchsia-cprng = "0.1.1"
```

But unless you are actually targeting `x86_64-fuchsia` or `aarch64-fuchsia`, the `fuchsia-cprng` is
never actually going to be compiled or linked into your project, so checking it is pointless for you.

The `targets` field allows you to specify one or more targets which you **actually** build for.
Every dependency link to a crate is checked against this list, and if none of the listed targets
satisfy the target constraint, the dependency link is ignored. If a crate has no dependency links
to it, it is not included into the crate graph that the checks are
executed against.


### `targets[N]`

**Type:** [`Target`](/checks2/schema/type-index/Target.md)

## `exclude`

**Type:** `array<string>`<br>
**Key:** `optional`

Just as with the [`--exclude`](https://embarkstudios.github.io/cargo-deny/cli/common.html#--exclude-dev)
command line option, this field allows you to specify one or more [Package ID specifications](https://doc.rust-lang.org/cargo/commands/cargo-pkgid.html)
that will cause the crate(s) in question to be excluded from the crate graph that is used
for the operation you are performing.

Note that excluding a crate is recursive, if any of its transitive dependencies are only referenced
via the excluded crate, they will also be excluded from the crate graph.


### Example

```toml
exclude = "some-crate@0.1.0"
```

### `exclude[N]`

**Type:** `string`

## `all-features`

**Type:** `boolean`<br>
**Key:** `optional`

If set to `true`, `--all-features` will be used when collecting metadata.

## `no-default-features`

**Type:** `boolean`<br>
**Key:** `optional`

If set to `true`, `--no-default-features` will be used when collecting metadata.

## `features`

**Type:** `array<string>`<br>
**Key:** `optional`

If set, and `--features` is not specified on the cmd line, these features will be used when
collecting metadata.


### Example

```toml
features = "some-feature"
```

### `features[N]`

**Type:** `string`

## `exclude-dev`

**Type:** `boolean`<br>
**Key:** `optional`

If set to `true`, all `dev-dependencies`, even one for workspace crates, are not included
in the crate graph used for any of the checks. This option can also be enabled on cmd line
with `--exclude-dev` either [before](https://embarkstudios.github.io/cargo-deny/cli/common.html#--exclude-dev)
or [after](https://embarkstudios.github.io/cargo-deny/cli/check.html#--exclude-dev)
the `check` subcommand.
