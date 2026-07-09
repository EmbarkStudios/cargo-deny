# The `fetch` command

Fetches remote datat that may be used by the `check` and/or `list` subcommands.

## Args

### `SOURCES`

Possible values:

- db - Fetches the configured advisory databases. Defaults to <https://github.com/RustSec/advisory-db>.
- index - Fetches the crate sources and index information for the crates in the graph.
- std-replacement - Fetches the std-replacement-data from <https://github.com/EmbarkStudios/std-replacement-data/tree/collated>
- all (default) - Fetches all of the above sources.
