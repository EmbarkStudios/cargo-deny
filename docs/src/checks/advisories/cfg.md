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

The advisories section has an upcoming breaking change, with deprecation warnings for several fields that will be removed. Setting `version = 2` will opt-in to the future default behavior.

The breaking change is as follows:

- `vulnerability` - Removed, all vulnerability advisories now emit errors.
- `unmaintained` - Removed, all unmaintained advisories now emit errors.
- `unsound` - Removed, all unsound advisories now emit errors.
- `notice` - Removed, all notice advisories now emit errors.
- `severity-threshold` - Removed, all vulnerability advisories now emit errors.

As before, if you want to ignore a specific advisory, add it to the `ignore` field.

### The `vulnerability` field (optional)

[**DEPRECATED**](#the-version-field-optional)

Determines what happens when a crate with a security vulnerability is encountered.

- `deny` (default) - Will emit an error with details about each vulnerability, and fail the check.
- `warn` - Prints a warning for each vulnerability, but does not fail the check.
- `allow` - Prints a note about the security vulnerability, but does not fail the check.

### The `unmaintained` field (optional)

[**DEPRECATED**](#the-version-field-optional)

Determines what happens when a crate with an `unmaintained` advisory is encountered.

- `deny` - Will emit an error with details about the unmaintained advisory, and fail the check.
- `warn` (default) - Prints a warning for each unmaintained advisory, but does not fail the check.
- `allow` - Prints a note about the unmaintained advisory, but does not fail the check.

### The `unsound` field (optional)

[**DEPRECATED**](#the-version-field-optional)

Determines what happens when a crate with an `unsound` advisory is encountered.

- `deny` - Will emit an error with details about the unsound advisory, and fail the check.
- `warn` (default) - Prints a warning for each unsound advisory, but does not fail the check.
- `allow` - Prints a note about the unsound advisory, but does not fail the check.

### The `yanked` field (optional)

Determines what happens when a crate with a version that has been yanked from its source registry is encountered.

- `deny` - Will emit an error with the crate name and version that was yanked, and fail the check.
- `warn` (default) - Prints a warning with the crate name and version that was yanked, but does not fail the check.
- `allow` - Prints a note about the yanked crate, but does not fail the check.

### The `notice` field (optional)

[**DEPRECATED**](#the-version-field-optional)

Determines what happens when a crate with a `notice` advisory is encountered.

**NOTE**: As of 2019-12-17 there are no `notice` advisories in the [RustSec Advisory DB](https://github.com/RustSec/advisory-db)

- `deny` - Will emit an error with details about the notice advisory, and fail the check.
- `warn` (default) - Prints a warning for each notice advisory, but does not fail the check.
- `allow` - Prints a note about the notice advisory, but does not fail the check.

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

### The `severity-threshold` field (optional)

[**DEPRECATED**](#the-version-field-optional)

The threshold for security vulnerabilities to be turned into notes instead of warnings or errors, depending upon its [CVSS](https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System) score. So having a high threshold means some vulnerabilities might not fail the check, but having a log level `>= info` will mean that a note will be printed instead of a warning or error, depending on `[advisories.vulnerability]`.

- `None` (default) - CVSS Score 0.0
- `Low` - CVSS Score 0.1 - 3.9
- `Medium` - CVSS Score 4.0 - 6.9
- `High` - CVSS Score 7.0 - 8.9
- `Critical` - CVSS Score 9.0 - 10.0

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
