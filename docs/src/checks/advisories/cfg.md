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

Path to the root directory into which one or more advisory databases are cloned into

Default: `~/.cargo/advisory-db`

### The `vulnerability` field (optional)

Determines what happens when a crate with a security vulnerability is encountered.

* `deny` (default) - Will emit an error with details about each vulnerability, and fail the check.
* `warn` - Prints a warning for each vulnerability, but does not fail the check.
* `allow` - Prints a note about the security vulnerability, but does not fail the check.

### The `unmaintained` field (optional)

Determines what happens when a crate with an `unmaintained` advisory is encountered.

* `deny` - Will emit an error with details about the unmaintained advisory, and fail the check.
* `warn` (default) - Prints a warning for each unmaintained advisory, but does not fail the check.
* `allow` - Prints a note about the unmaintained advisory, but does not fail the check.

### The `unsound` field (optional)

Determines what happens when a crate with an `unsound` advisory is encountered.

* `deny` - Will emit an error with details about the unsound advisory, and fail the check.
* `warn` (default) - Prints a warning for each unsound advisory, but does not fail the check.
* `allow` - Prints a note about the unsound advisory, but does not fail the check.

### The `yanked` field (optional)

Determines what happens when a crate with a version that has been yanked from its source registry is encountered.

* `deny` - Will emit an error with the crate name and version that was yanked, and fail the check.
* `warn` (default) - Prints a warning with the crate name and version that was yanked, but does not fail the check.
* `allow` - Prints a note about the yanked crate, but does not fail the check.

### The `notice` field (optional)

Determines what happens when a crate with a `notice` advisory is encountered.

**NOTE**: As of 2019-12-17 there are no `notice` advisories in the [RustSec Advisory DB](https://github.com/RustSec/advisory-db)

* `deny` - Will emit an error with details about the notice advisory, and fail the check.
* `warn` (default) - Prints a warning for each notice advisory, but does not fail the check.
* `allow` - Prints a note about the notice advisory, but does not fail the check.

### The `ignore` field (optional)

Every advisory in the advisory database contains a unique identifier, eg. `RUSTSEC-2019-0001`. Putting an identifier in this array will cause the advisory to be treated as a note, rather than a warning or error.

### The `severity-threshold` field (optional)

The threshold for security vulnerabilities to be turned into notes instead of warnings or errors, depending upon its [CVSS](https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System) score. So having a high threshold means some vulnerabilities might not fail the check, but having a log level `>= info` will mean that a note will be printed instead of a warning or error, depending on `[advisories.vulnerability]`.

* `None` (default) - CVSS Score 0.0
* `Low` - CVSS Score 0.1 - 3.9
* `Medium` - CVSS Score 4.0 - 6.9
* `High` - CVSS Score 7.0 - 8.9
* `Critical` - CVSS Score 9.0 - 10.0

### The `git-fetch-with-cli` field (optional)

Similar to cargo's [net.git-fetch-with-cli](https://doc.rust-lang.org/cargo/reference/config.html#netgit-fetch-with-cli), this field allows you to opt-in to fetching advisory databases with the git CLI rather than using `git2`, for example if you are using SSH authentication.

* `false` (default) - Fetches advisory databases via `git2`
* `true` - Fetches advisory databases using `git`. Git must be installed and in `PATH`.
