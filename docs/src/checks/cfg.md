# config

The top level config for cargo-deny, by default called `deny.toml`.

## Example

```ini
# cargo-deny is really only ever intended to run on the "normal" tier-1 targets
targets = [
    { triple = "x86_64-unknown-linux-gnu" },
    { triple = "x86_64-unknown-linux-musl" },
    { triple = "x86_64-apple-darwin" },
    { triple = "x86_64-pc-windows-msvc" },
]

[advisories]
vulnerability = "deny"
unmaintained = "deny"
notice = "deny"

[bans]
multiple-versions = "deny"
deny = [
]
skip = [
    # clap uses an older version of ansi_term
    { name = "ansi_term", version = "=0.11.0" },
    # crossbeam (but also openssl-sys!) use pre-1.0 versions of autocfg
    { name = "autocfg", version = "=0.1.7" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-git = [
    "https://github.com/RustSec/rustsec-crate.git"
]


[licenses]
unlicensed = "deny"
allow-osi-fsf-free = "neither"
copyleft = "deny"
# We want really high confidence when inferring licenses from text
confidence-threshold = 0.93
allow = [
    "Apache-2.0",
    "MIT",
]
```

### The `targets` field (optional)

By default, cargo-deny will consider every single crate that is resolved by
cargo, including target specific dependencies eg

```ini
[target.x86_64-pc-windows-msvc.dependencies]
winapi = "0.3.8"

[target.'cfg(target_os = "fuchsia")'.dependencies]
fuchsia-cprng = "0.1.1"
```

But unless you are actually targetting `x86_64-fuchsia` or `aarch64-fuchsia`,
the `fuchsia-cprng` is never actually going to be compiled or linked into your
project, so checking it pointless for you.

The `targets` field allows you to specify one or more targets which you actually
build for. Every dependency link to a crate is checked against this list, if
none of the listed targets satisfy the target constraint, the dependency link
is ignored. If a crate has no dependency links to it, it is not included in
the crate graph that checks are executed against.

#### The `triple` field

The [target triple](https://forge.rust-lang.org/release/platform-support.html)
for the target you wish to filter target specific dependencies with. If the
target triple specified is **not** one of the targets builtin to `rustc`, the
configuration check for that target will be limited to only the raw 
`[target.<target-triple>.dependencies]` style of target configuration, as 
`cfg()` expressions require us to know the details about the target.

#### The `features` field (optional)

Rust `cfg()` expressions support the [`target_feature = 
"feature-name"`](https://doc.rust-lang.org/reference/attributes/codegen.html#the-target_feature-attribute)
predicate, but at the moment, the only way to actually pass them when compiling 
is to use the `RUSTFLAGS` environment variable. The features field allows you
to specify 1 or more `target_feature`s you plan to build with. At the time of
this writing, cargo-deny does not attempt to validate that the features you
specify are actually valid for the target triple, but this is
[planned](https://github.com/EmbarkStudios/cfg-expr/issues/1).

### The `[licenses]` section

See the [licenses config](licenses/cfg.html) for more info.

### The `[bans]` section

See the [bans config](bans/cfg.html) for more info.

### The `[advisories]` section

See the [advisories config](advisories/cfg.html) for more info.

### The `[sources]` section

See the [sources config](sources/cfg.html) for more info.
