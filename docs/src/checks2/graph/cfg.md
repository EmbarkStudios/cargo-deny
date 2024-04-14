# `graph`

**Type:** `object`<br>
**Required:** `no`

The graph table configures how the dependency graph is constructed and thus which crates the
checks are performed against


## `graph.targets`

**Type:** `array`<br>
**Required:** `no`

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


### Array item



#### Variant: `TargetString`

**Type:** [`TargetString`](/checks2/type-index.html#targetstring) `(string)`

#### Variant: `TargetAdvanced`

**Type:** `object`

Advanced configurations to apply for the target triple

##### Examples

- ```toml
  [[graph.targets]]
  triple = "aarch64-apple-darwin"
  ```
- ```toml
  [[graph.targets]]
  triple = "x86_64-pc-windows-msvc"
  features = ["some-feature"]
  ```

##### `graph.targets array item as TargetAdvanced.triple`

**Type:** [`TargetString`](/checks2/type-index.html#targetstring) `(string)`<br>
**Required:** `yes`

##### `graph.targets array item as TargetAdvanced.features`

**Type:** `string`<br>
**Required:** `no`

Rust `cfg()` expressions support the [`target_feature = "feature-name"`](https://doc.rust-lang.org/reference/attributes/codegen.html#the-target_feature-attribute)
predicate, but at the moment, the only way to actually pass them when compiling is to use
the `RUSTFLAGS` environment variable. The `features` field allows you to specify 1 or more
`target_feature`s you plan to build with, for a particular target triple. At the time of
this writing, cargo-deny does not attempt to validate that the features you specify are
actually valid for the target triple, but this is [planned](https://github.com/EmbarkStudios/cfg-expr/issues/1).


## `graph.exclude`

**Type:** `array<string>`<br>
**Required:** `no`

Just as with the [`--exclude`](https://embarkstudios.github.io/cargo-deny/cli/common.html#--exclude-dev)
command line option, this field allows you to specify one or more [Package ID specifications](https://doc.rust-lang.org/cargo/commands/cargo-pkgid.html)
that will cause the crate(s) in question to be excluded from the crate graph that is used
for the operation you are performing.

Note that excluding a crate is recursive, if any of its transitive dependencies are only referenced
via the excluded crate, they will also be excluded from the crate graph.


### Example

```toml
[graph]
exclude = "some-crate@0.1.0"
```

## `graph.all-features`

**Type:** `boolean`<br>
**Required:** `no`

If set to `true`, `--all-features` will be used when collecting metadata.

## `graph.no-default-features`

**Type:** `boolean`<br>
**Required:** `no`

If set to `true`, `--no-default-features` will be used when collecting metadata.

## `graph.features`

**Type:** `array<string>`<br>
**Required:** `no`

If set, and `--features` is not specified on the cmd line, these features will be used when
collecting metadata.


### Example

```toml
[graph]
features = "some-feature"
```

## `graph.exclude-dev`

**Type:** `boolean`<br>
**Required:** `no`

If set to `true`, all `dev-dependencies`, even one for workspace crates, are not included
in the crate graph used for any of the checks. This option can also be enabled on cmd line
with `--exclude-dev` either [before](https://embarkstudios.github.io/cargo-deny/cli/common.html#--exclude-dev)
or [after](https://embarkstudios.github.io/cargo-deny/cli/check.html#--exclude-dev)
the `check` subcommand.
