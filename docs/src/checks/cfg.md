# config

The top level config for cargo-deny, by default called `deny.toml`.

## Example - cargo-deny's own configuration

```ini
{{#include ../../../deny.toml}}
```

## The `graph` field (optional)

The graph tables provides configuration options for how the dependency graph that the various checks are executed against is constructed.

```ini
[graph]
targets = [
    "x86_64-unknown-linux-gnu",
    { triple = "aarch64-apple-darwin" },
    { triple = "x86_64-pc-windows-msvc", features = ["sse2"] },
]
exclude = ["some-crate@0.1.0"]
all-features = true
no-default-features = false
features = ["some-feature"]
exclude-dev = true
```

### The `targets` field (optional)

By default, cargo-deny will consider every single crate that is resolved by cargo, including target specific dependencies eg

```ini
[target.x86_64-pc-windows-msvc.dependencies]
winapi = "0.3.8"

[target.'cfg(target_os = "fuchsia")'.dependencies]
fuchsia-cprng = "0.1.1"
```

But unless you are actually targeting `x86_64-fuchsia` or `aarch64-fuchsia`, the `fuchsia-cprng` is never actually going to be compiled or linked into your project, so checking it is pointless for you.

The `targets` field allows you to specify one or more targets which you **actually** build for. Every dependency link to a crate is checked against this list, and if none of the listed targets satisfy the target constraint, the dependency link is ignored. If a crate has no dependency links to it, it is not included into the crate graph that the checks are executed against.

#### The `targets.triple` field (optional) or `"<triple_string>"`

The [target triple](https://forge.rust-lang.org/release/platform-support.html) for the target you wish to filter target specific dependencies with. If the target triple specified is **not** one of the targets builtin to `rustc`, the configuration check for that target will be limited to only the raw `[target.<target-triple>.dependencies]` style of target configuration, as `cfg()` expressions require us to know the details about the target.

#### The `targets.features` field (optional)

Rust `cfg()` expressions support the [`target_feature = "feature-name"`](https://doc.rust-lang.org/reference/attributes/codegen.html#the-target_feature-attribute) predicate, but at the moment, the only way to actually pass them when compiling is to use the `RUSTFLAGS` environment variable. The `features` field allows you to specify 1 or more `target_feature`s you plan to build with, for a particular target triple. At the time of this writing, cargo-deny does not attempt to validate that the features you specify are actually valid for the target triple, but this is [planned](https://github.com/EmbarkStudios/cfg-expr/issues/1).

### The `exclude` field (optional)

Just as with the [`--exclude`](../cli/common.md#--exclude) command line option, this field allows you to specify one or more [Package ID specifications](https://doc.rust-lang.org/cargo/commands/cargo-pkgid.html) that will cause the crate(s) in question to be excluded from the crate graph that is used for the operation you are performing.

Note that excluding a crate is recursive, if any of its transitive dependencies are only referenced via the excluded crate, they will also be excluded from the crate graph.

### The `all-features` field (optional)

If set to `true`, `--all-features` will be used when collecting metadata.

### The `no-default-features` field (optional)

If set to `true`, `--no-default-features` will be used when collecting metadata.

### The `features` field (optional)

If set, and `--features` is not specified on the cmd line, these features will be used when collecting metadata.

### The `exclude-dev` field (optional)

If set to `true`, all `dev-dependencies`, even one for workspace crates, are not included in the crate graph used for any of the checks. This option can also be enabled on cmd line with `--exclude-dev` either [before](../cli/common.md#--exclude-dev) or [after](../cli/check.md#--exclude-dev) the `check` subcommand.

## The `output` field (optional)

### The `feature-depth` field (optional)

The maximum depth that features will be displayed when inclusion graphs are included in diagnostics, unless specified via `--feature-depth` on the command line. Only applies to diagnostics that actually print features. If not specified defaults to `1`.

## Package Specs

Many configuration options require a package specifier at a minimum, which we'll describe here. The options that use package specifiers will be called out in their individual documentation. We'll use the [`bans.deny`](bans/cfg.md#the-deny-field-optional) option in the following examples.

### String format

If the particular only requires a package spec at a minimum, then the string format can be used, which comes in three forms.

#### Simple

```ini
# Will match any version of the simple crate
deny = ["simple"]
```

The simplest string is one which is just the crate name. In this case, the version requirement used when checking will be `*` meaning it will match against all versions of that crate in the graph.

#### With Version Requirements

```ini
# Will match only this versions of the simple crate that match the predicate(s)
deny = ["simple:<=0.1,>0.2"]
```

If you want to apply version requirements (predicates) to the crate, simply append them following a `:` separator.

#### Exact

```ini
# Will match only this exact version of the simple crate
deny = [
    "simple@0.1.0",
    # This is semantically equivalent to the above
    "simple:=0.1.0",
]
```

The exact form is a specialization of the version requirements, where the semver after the `@` is transformed to be [= (Exact)](https://docs.rs/semver/latest/semver/enum.Op.html#opexact).

### Table format

#### Crate format

```ini
deny = [
    { crate = "simple@0.1.0" }, # equivalent to "simple@0.1.0"
    { crate = "simple", wrappers = ["example"] },
]
```

The crate format is a replacement for the old `name` and/or `version` table format. It uses the string format described above in a single `crate` key.

#### Old format

```ini
deny = [
    { name = "simple" },
    { name = "simple", version = "*" }
    { name = "simple", wrappers = ["example"] }
]
```

The old format uses a required `name` key and an optional `version` key. This format is deprecated and should not be used.

## The `[licenses]` section

See the [licenses config](licenses/cfg.html) for more info.

## The `[bans]` section

See the [bans config](bans/cfg.html) for more info.

## The `[advisories]` section

See the [advisories config](advisories/cfg.html) for more info.

## The `[sources]` section

See the [sources config](sources/cfg.html) for more info.
