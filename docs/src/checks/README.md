# Checks

cargo-deny supports several different classes of checks that can be performed
on your project's crate graph. By default, `cargo deny check` will execute
**all** of the supported checks, falling back to the default configuration for
that check if one is not explicitly specified.

## [licenses](licenses/index.html)

Checks the license information for each crate.

## [bans](bans/index.html)

Checks for specific crates in your graph, as well as duplicates.

## [advisories](advisories/index.html)

Checks advisory databases for crates with security vulnerabilities, or that
have been marked as `Unmaintained`, or which have been yanked from their source
registry.

## [sources](sources/index.html)

Checks the source location for each crate.
