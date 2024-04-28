# `Advisories`

**Type:** `object`

Checks advisory databases for crates with security vulnerabilities,
or that have been marked as unmaintained, or which have been yanked from
their source registry.

This section is considered when running `cargo deny check advisories`.


## Example

```toml
db-path = "~/.cargo/advisory-dbs"
db-urls = ["https://github.com/RustSec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
unsound = "warn"
yanked = "warn"
notice = "warn"
ignore = [
    "RUSTSEC-0000-0000",
    "crate@0.1",
    { crate = "yanked", reason = "a new version has not been released" },
]
severity-threshold = "medium"
```

## `db-urls`

**Type:** `array<string (uri)>`<br>
**Key:** `optional`

URLs to one or more advisory databases.

### Default

```toml
db-urls = ["https://github.com/RustSec/advisory-db"]
```

### Array item

**Type:** `string (uri)`

## `db-path`

**Type:** `string`<br>
**Key:** `optional`

Path to the root directory into which one or more advisory databases are cloned into.

This value supports basic shell expansion:

- `~` - Expands to [`home::home_dir`](https://docs.rs/home/latest/home/fn.home_dir.html)
- `$VARNAME` - Expands to [`std::env::var("VARNAME")`](https://doc.rust-lang.org/std/env/fn.var.html)
- `${VARNAME}` - Expands to [`std::env::var("VARNAME")`](https://doc.rust-lang.org/std/env/fn.var.html)
- `${VARNAME:-fallback}` - Expands to [`std::env::var("VARNAME")`](https://doc.rust-lang.org/std/env/fn.var.html)
  or the fallback value if it doesn't exist (everything between the `:-` and `}`)
- `$CARGO_HOME` - Expands to [`std::env::var("CARGO_HOME")`](https://doc.rust-lang.org/std/env/fn.var.html)
  if it exists, otherwise expands to `$(home::home_dir())/.cargo`

Note that the path must be valid utf-8, after expansion.


### Default

```toml
db-path = "$CARGO_HOME/advisory-dbs"
```

## `version`

**Type:** `integer (enum)`<br>
**Key:** `optional`

The advisories section has an upcoming breaking change, with deprecation warnings for several
fields that will be removed. Setting `version = 2` will opt-in to the future default behavior.

The breaking change is as follows:

- `vulnerability` - Removed, all vulnerability advisories now emit errors.
- `unmaintained` - Removed, all unmaintained advisories now emit errors.
- `unsound` - Removed, all unsound advisories now emit errors.
- `notice` - Removed, all notice advisories now emit errors.
- `severity-threshold` - Removed, all vulnerability advisories now emit errors.

As before, if you want to ignore a specific advisory, add it to the `ignore` field.


### Possible values

- `2`

## `vulnerability`

**Type:** [`LintLevel`](/checks2/type-index/LintLevel.md) `string (enum)`

## `unmaintained`

**Type:** [`LintLevel`](/checks2/type-index/LintLevel.md) `string (enum)`

## `unsound`

**Type:** [`LintLevel`](/checks2/type-index/LintLevel.md) `string (enum)`

## `notice`

**Type:** [`LintLevel`](/checks2/type-index/LintLevel.md) `string (enum)`

## `yanked`

**Type:** [`LintLevel`](/checks2/type-index/LintLevel.md) `string (enum)`

## `ignore`

**Type:** `array`<br>
**Key:** `optional`

Every advisory in the advisory database contains a unique identifier, eg. `RUSTSEC-2019-0001`.
Putting an identifier in this array will cause the advisory to be treated as a note, rather
than a warning or error.

In addition, yanked crate versions can be ignored by specifying a [PackageSpec](https://embarkstudios.github.io/cargo-deny/checks/cfg.html#package-spec)
with an optional `reason`.


### Example

```toml
ignore = [
    "RUSTSEC-0000-0000",
    { id = "RUSTSEC-0000-0000", reason = "this vulnerability does not affect us as we don't use the particular code path" },
    "yanked@0.1.1",
    { crate = "yanked-crate@0.1.1", reason = "a semver compatible version hasn't been published yet" },
]
```

### Array item

**Type:** [`AdvisoriesIgnoreItem`](/checks2/type-index/AdvisoriesIgnoreItem.md)