# The `[advisories]` section

Contains all of the configuration for `cargo deny check advisories`

## Example Config

```ini
{{#include ../../../../tests/cfg/advisories.toml}}
```

### The `db-urls` field (optional)

URLs to one or more advisory databases.

Default: [RustSec Advisory DB](https://github.com/RustSec/advisory-db)

### The `db-path` field (optional)

Path to the root directory into which one or more advisory databases are cloned into.

This value supports basic shell expansion:

- `~` - Expands to [`home::home_dir`](https://docs.rs/home/latest/home/fn.home_dir.html)
- `$VARNAME` - Expands to [`std::env::var("VARNAME")`](https://doc.rust-lang.org/std/env/fn.var.html)
- `${VARNAME}` - Expands to [`std::env::var("VARNAME")`](https://doc.rust-lang.org/std/env/fn.var.html)
- `${VARNAME:-fallback}` - Expands to [`std::env::var("VARNAME")`](https://doc.rust-lang.org/std/env/fn.var.html) or the fallback value if it doesn't exist (everything between the `:-` and `}`)
- `$CARGO_HOME` - Expands to [`std::env::var("CARGO_HOME")`](https://doc.rust-lang.org/std/env/fn.var.html) if it exists, otherwise expands to `$(home::home_dir())/.cargo`

Note that the path must be valid utf-8, after expansion.

Default: `$CARGO_HOME/advisory-dbs`

### The `version` field (optional)

```ini
version = 2
```

The version field is (at the time of this writing) no longer used, the following fields have been removed and will now emit errors.

- `vulnerability` - Removed, all vulnerability advisories now emit errors.
- `unsound` - Removed, all unsound advisories now emit errors.
- `notice` - Removed, all notice advisories now emit errors.
- `severity-threshold` - Removed, all vulnerability advisories now emit errors.

As before, if you want to ignore a specific advisory, add it to the `ignore` field.

### The `yanked` field (optional)

Determines what happens when a crate with a version that has been yanked from its source registry is encountered.

- `deny` - Will emit an error with the crate name and version that was yanked, and fail the check.
- `warn` (default) - Prints a warning with the crate name and version that was yanked, but does not fail the check.
- `allow` - Prints a note about the yanked crate, but does not fail the check.

### The `ignore` field (optional)

```ini
ignore = [
   "RUSTSEC-0000-0000",
   { id = "RUSTSEC-0000-0000", reason = "this vulnerability does not affect us as we don't use the particular code path" },
   "yanked@0.1.1",
   { crate = "yanked-crate@0.1.1", reason = "a semver compatible version hasn't been published yet" },
]
```

Every advisory in the advisory database contains a unique identifier, eg. `RUSTSEC-2019-0001`. Putting an identifier in this array will cause the advisory to be treated as a note, rather than a warning or error.

In addition, yanked crate versions can be ignored by specifying a [PackageSpec](../cfg.md#package-spec) with an optional `reason`.

### The `unmaintained` field (optional)

```ini
unmaintained = 'workspace'
```

Determines if ummaintained advisories will result in an error. An unmaintained error can still be ignored specifically via the [`ignore`](#the-ignore-field-optional) option.

- `all` (default) - Any crate that matches an unmaintained advisory will fail
- `workspace` - Unmaintained advisories will only fail if they apply to a crate which is a direct dependency of one or more workspace crates.
- `transitive` - Unmaintained advisories will only fail if they apply to a crate which is **not** a direct dependency of one or more workspace crates.
- `none` - Unmaintained advisories are completely ignored.

### The `git-fetch-with-cli` field (optional)

Similar to cargo's [net.git-fetch-with-cli](https://doc.rust-lang.org/cargo/reference/config.html#netgit-fetch-with-cli), this field allows you to opt-in to fetching advisory databases with the git CLI rather than using `gix`.

- `false` (default) - Fetches advisory databases via `gix`
- `true` - Fetches advisory databases using `git`. Git must be installed and in `PATH`.

### The `maximum-db-staleness` field (optional)

A duration in RFC3339 format that specifies the maximum amount of time that can pass before the database is considered stale and an error is emitted. This is only checked when advisory database fetching has been disabled via the `--offline` or `check --disable-fetch` flags, as otherwise the database is always cloned or fetched to be up to date with the remote git repository.

The default if not specified is the same value that `cargo-audit` uses, and `cargo-deny` has been using, which is `P90D`, or 90 days.

The RFC3339 duration format is...not well documented. The official grammar is as follows:

```txt
   dur-second        = 1*DIGIT "S"
   dur-minute        = 1*DIGIT "M" [dur-second]
   dur-hour          = 1*DIGIT "H" [dur-minute]
   dur-time          = "T" (dur-hour / dur-minute / dur-second)
   dur-day           = 1*DIGIT "D"
   dur-week          = 1*DIGIT "W"
   dur-month         = 1*DIGIT "M" [dur-day]
   dur-year          = 1*DIGIT "Y" [dur-month]
   dur-date          = (dur-day / dur-month / dur-year) [dur-time]

   duration          = "P" (dur-date / dur-time / dur-week)
```

However, as far as I can tell, there are no official spec compliance tests one can run for the duration formation, and several parsers I found written in other languages seemed to...not actually properly follow the grammar, so the implementation in cargo-deny _may_ be wrong according to the spec, but at least it will be consistently wrong.

Note that while the spec supports `,` as a decimal separator, for simplicity cargo-deny only supports `.` as a decimal separator.

One final note, there are 2 units available in the format that are not exact, namely, year 'Y' and month 'M'. It's not recommended to use either of them for that reason, but if you do they are calculated as follows.

- 1 year = 365 days
- 1 month = 30.43 days

### The `unused-ignored-advisory` field (optional)

Determines what happens when one of the advisories that appears in the `ignore` list is not encountered in the dependency graph.

- `warn` (default) - A warning is emitted for each advisory that appears in `advisories.ignore` but which is not used in any crate.
- `allow` - Unused advisories in the `advisories.ignore` list are ignored.
- `deny` - An unused advisory in the `advisories.ignore` list triggers an error, and cause the advisory check to fail.
