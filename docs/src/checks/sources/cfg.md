# The `[sources]` section

Contains all of the configuration for `cargo deny check sources`

## Example Config

```ini
{{#include ../../../../tests/cfg/sources.toml}}
```

### The `unknown-registry` field (optional)

Determines what happens when a crate from a crate registry that is not in the 
`allow-registry` list is encountered.

* `deny` - Will emit an error with the URL of the source, and fail the check.
* `warn` (default) - Prints a warning for each crate, but does not fail the 
check.
* `allow` - Prints a note for each crate, but does not fail the check.

### The `unknown-git` field (optional)

Determines what happens when a crate from a git repository not in the 
`allow-git` list is encountered.

* `deny` - Will emit an error with the URL of the repository, and fail the 
check.
* `warn` (default) - Prints a warning for each crate, but does not fail the 
check.
* `allow` - Prints a note for each crate, but does not fail the check.

### The `allow-registry` field (optional)

The list of registries that are allowed. If a crate is not found in the list,
then the `unknown-registry` setting will determine how it is handled.

If not specified, this list will by default contain the
[crates.io](http://crates.io) registry, equivalent to this:

```toml
[sources]
allow-registry = [
    "https://github.com/rust-lang/crates.io-index"
]
```

To not allow any crates registries, set it to empty:

```toml
[sources]
unknown-registry = "deny"
allow-registry = []
```

### The `allow-git` field

Configure which crate registries that are known and allowed.
