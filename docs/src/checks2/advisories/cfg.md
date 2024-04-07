# The `[advisories]` section

Checks advisory databases for crates with security vulnerabilities,
or that have been marked as Unmaintained, or which have been yanked from
their source registry.

This section is considered when running `cargo deny check advisories`.


## Example

```toml
[advisories]
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

## `advisories.db-urls` (optional)

`array of string (uri)`

#### Default

```toml
[advisories]
db-urls = ["https://github.com/RustSec/advisory-db"]
```

URLs to one or more advisory databases.

## `advisories.db-path` (optional)

`string`

### Default

```toml
[advisories]
db-path = "$CARGO_HOME/advisory-dbs"
```

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


## `advisories.version` (optional)



### Possible values

* `2`
---
The advisories section has an upcoming breaking change, with deprecation warnings for several
fields that will be removed. Setting `version = 2` will opt-in to the future default behavior.

The breaking change is as follows:

- `vulnerability` - Removed, all vulnerability advisories now emit errors.
- `unmaintained` - Removed, all unmaintained advisories now emit errors.
- `unsound` - Removed, all unsound advisories now emit errors.
- `notice` - Removed, all notice advisories now emit errors.
- `severity-threshold` - Removed, all vulnerability advisories now emit errors.

As before, if you want to ignore a specific advisory, add it to the `ignore` field.


## `advisories.vulnerability` (optional)



### Possible values

* `"deny"` - Emit an error with details about the problem, and fail the check.
* `"warn"` - Print a warning for each propblem, but don't fail the check.
* `"allow"` - Print a note about the problem, but don't fail the check.
---
#### Default

```toml
[advisories]
vulnerability = "deny"
```

**DEPRECATED** (see `version` field)

Determines what happens when a crate with a security vulnerability is encountered.


## `advisories.unmaintained` (optional)



### Possible values

* `"deny"` - Emit an error with details about the problem, and fail the check.
* `"warn"` - Print a warning for each propblem, but don't fail the check.
* `"allow"` - Print a note about the problem, but don't fail the check.
---
#### Default

```toml
[advisories]
unmaintained = "warn"
```

**DEPRECATED** (see `version` field)

Determines what happens when a crate with an `unmaintained` advisory is encountered.


## `advisories.unsound` (optional)



### Possible values

* `"deny"` - Emit an error with details about the problem, and fail the check.
* `"warn"` - Print a warning for each propblem, but don't fail the check.
* `"allow"` - Print a note about the problem, but don't fail the check.
---
#### Default

```toml
[advisories]
unsound = "warn"
```

**DEPRECATED** (see `version` field)

Determines what happens when a crate with an `unsound` advisory is encountered.


## `advisories.notice` (optional)



### Possible values

* `"deny"` - Emit an error with details about the problem, and fail the check.
* `"warn"` - Print a warning for each propblem, but don't fail the check.
* `"allow"` - Print a note about the problem, but don't fail the check.
---
#### Default

```toml
[advisories]
notice = "warn"
```

**DEPRECATED** (see `version` field)

Determines what happens when a crate with a `notice` advisory is encountered.

**NOTE**: As of 2019-12-17 there are no `notice` advisories in the
[RustSec Advisory DB](https://github.com/RustSec/advisory-db)


## `advisories.yanked` (optional)



### Possible values

* `"deny"` - Emit an error with details about the problem, and fail the check.
* `"warn"` - Print a warning for each propblem, but don't fail the check.
* `"allow"` - Print a note about the problem, but don't fail the check.
---
#### Default

```toml
[advisories]
yanked = "warn"
```

Determines what happens when a crate with a version that has been yanked from its source
registry is encountered.


## `advisories.ignore` (optional)

`array`

Every advisory in the advisory database contains a unique identifier, eg. `RUSTSEC-2019-0001`.
Putting an identifier in this array will cause the advisory to be treated as a note, rather
than a warning or error.

In addition, yanked crate versions can be ignored by specifying a [PackageSpec](https://embarkstudios.github.io/cargo-deny/checks/cfg.html#package-spec)
with an optional `reason`.


#### Example

```toml
[advisories]
ignore = [
    "RUSTSEC-0000-0000",
    { id = "RUSTSEC-0000-0000", reason = "this vulnerability does not affect us as we don't use the particular code path" },
    "yanked@0.1.1",
    { crate = "yanked-crate@0.1.1", reason = "a semver compatible version hasn't been published yet" },
]
```

### Items

**One of the following:**

`string`

Either an advisory ID (e.g. `RUSTSEC-2019-0001`) or a package spec (e.g. `yanked@0.1.1`).


##### `advisories.ignore[N].id` (required)

`string`

The unique identifier of the advisory to ignore

###### Example

```toml
[[advisories.ignore]]
id = "RUSTSEC-2019-0001"
```

##### `advisories.ignore[N].reason` (optional)

`string`

Free-form string that can be used to describe the reason why the advisory is ignored.


##### `advisories.ignore[N].crate` (required)

`string`

Many configuration options require a package specifier at a minimum, which we'll describe here.
The options that use package specifiers will be called out in their individual documentation.
We'll use the [`bans.deny`](bans/cfg.md#the-deny-field-optional) option in the following examples.

### String format

If the particular only requires a package spec at a minimum, then the string format can be used,
which comes in three forms.

#### Simple

```toml
# Will match any version of the simple crate
deny = ["simple"]
```

The simplest string is one which is just the crate name. In this case, the version requirement
used when checking will be `*` meaning it will match against all versions of that crate in the graph.

#### With Version Requirements

```toml
# Will match only these versions of the simple crate that match the predicate(s)
deny = ["simple:<=0.1,>0.2"]
```

If you want to apply version requirements (predicates) to the crate, simply append them following
a `:` separator.

#### Exact

```toml
# Will match only this exact version of the simple crate
deny = [
    "simple@0.1.0",
    # This is semantically equivalent to the above
    "simple:=0.1.0",
]
```

The exact form is a specialization of the version requirements, where the semver after the `@`
is transformed to be [= (Exact)](https://docs.rs/semver/latest/semver/enum.Op.html#opexact).

### Table format

#### Crate format

```toml
deny = [
    { crate = "simple@0.1.0" }, # equivalent to "simple@0.1.0"
    { crate = "simple", wrappers = ["example"] },
]
```

The crate format is a replacement for the old `name` and/or `version` table format. It uses
the string format described above in a single `crate` key.

#### Old format

```toml
deny = [
    { name = "simple" },
    { name = "simple", version = "*" }
    { name = "simple", wrappers = ["example"] }
]
```

The old format uses a required `name` key and an optional `version` key. This format is deprecated
and should not be used.


##### `advisories.ignore[N].reason` (optional)

`string`

Free-form string that can be used to describe the reason why the advisory is ignored.
