# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
### Added
- Resolved [#137](https://github.com/EmbarkStudios/cargo-deny/issues/137) by adding a `--format <human|json>` option. All diagnostic and log messages from the `check` subcommand respect this flag.

### Changed
- The `--color` option for the `list` subcommand has been moved to the top level arguments.

### Fixed
- Resolved [#211](https://github.com/EmbarkStudios/cargo-deny/issues/211) by adding a top-level `--color <auto|always|never>` option, if stderr is not a TTY or `never` is passed, no colors will be present in the output stream.

## [0.6.8] - 2020-06-06
### Added
- A one line summary of the state of each check is now output at the very end of the `check` subcommand unless the `--log-level` is `off`. If the `--log-level` is `info` or higher, a summary of the state, errors, warnings, and notes for each check are outputted on their own line instead.
- Added the `-s | --show-stats` flag to the `check` subcommand, which will print out the more detailed summary, regardless of the `--log-level`.

### Changed
- Updated crates.
- Updated `cfg-expr`, which should allow for filtering of crates for *most* custom targets that aren't built-in to rustc.

## [0.6.7] - 2020-05-01
### Fixed
- [PR#183](https://github.com/EmbarkStudios/cargo-deny/pull/183) resolved an infinite loop issue which could be caused by cyclic dependencies in a crate graph. Thanks [@Veetaha](https://github.com/Veetaha)!

## [0.6.6] - 2020-02-25
### Changed
- Updated crates. Mainly to force a new version because the Windows release messed up. Yay!

## [0.6.5] - 2020-02-25
### Added
- Added a `fetch` subcommand that can be used to fetch external data, currently the crates.io index and the configured advisory database

### Changed
- Upgraded to rustsec 0.18.0, which slighly reworks how yanked crate detection is done

## [0.6.4] - 2020-02-08
### Fixed
- Resolved [#131](https://github.com/EmbarkStudios/cargo-deny/issues/131) by removing an unnecessary path canonicalization

## [0.6.3] - 2020-02-05
### Added
- Added the `--manifest-path` option to specify the Cargo.toml you want to use as the context for the operation to fit with how other cargo subcommands work. Takes precedence over the (deprecated) `--context`.
- Added the `--workspace` flag to give the user a workaround in cases where a manifest is both a package and a workspace.
- Added the `--exclude` option to allow users to explicitly remove packages from the final crate graph.

### Changed
- The configuration used for the command is recursively searched for in parent directories starting in the same directory as the `Cargo.toml` (unless explicitly specified).
- The target list used when evaluating cfg expressions for dependencies has been updated to the list of targets supported by 1.41.0. This will give undesired behavior if you happen to use a target triple that has been removed from 1.41.0 that is available in the Rust version you have.

### Fixed
- Resolved [#122](https://github.com/EmbarkStudios/cargo-deny/issues/122) by pruning the packages that are checked against the advisory database to the same set used by all other checks

### Deprecated
- `--context` has been deprecated in favor of `--manifest-path`, to align cargo-deny more with all other cargo subcommands

## [0.6.2] - 2020-01-25
### Added
- Resolved [#116](https://github.com/EmbarkStudios/cargo-deny/issues/116) by adding the `[licenses.default]` field, which allows you to configure how to handle licenses that don't match any other predicate
- Resolved [#117](https://github.com/EmbarkStudios/cargo-deny/issues/117) by allowing the `list` subcommand to also use the normal configuration used by the `check` subcommand. Only the `targets` field is used, to determine which crates have their licenses listed.

## [0.6.1] - 2020-01-24
### Added
- Added `[advisories.yanked]` field in [PR#114](https://github.com/EmbarkStudios/cargo-deny/pull/114) for linting yanked crates.

## [0.6.0] - 2020-01-20
### Added
- Added the `sources` check and configuration, which allows linting of crate sources
- Resolved [#63](https://github.com/EmbarkStudios/cargo-deny/issues/63) by adding a dependency on [`krates`](https://crates.io/crates/krates), which allows us to easily filter out dependencies that don't match a target specified by the user via the `targets` config value.
- Resolved [#75](https://github.com/EmbarkStudios/cargo-deny/issues/75), a warning is now printed for license exceptions and allowed licenses, if they aren't encountered when checking crate license information.
- Resolved [#50](https://github.com/EmbarkStudios/cargo-deny/issues/50), private workspace members (anything that is not published publicly) can now be ignored during the license check.

### Changed
- Resolved [#85](https://github.com/EmbarkStudios/cargo-deny/issues/85) by changing the max column width from 120 to 80 and reformatting some of the help text for the CLI.
- Resolved [#109](https://github.com/EmbarkStudios/cargo-deny/issues/109) by only printing a single diagnostic message for each set of duplicate versions

### Fixed
- Fixed [#96](https://github.com/EmbarkStudios/cargo-deny/issues/96) by allowing expansion of '~' rooted paths for the `[advisories.db-path]` configuration variable.

## [0.5.2] - 2019-12-20
### Added
- Resolved [#53](https://github.com/EmbarkStudios/cargo-deny/issues/53) by adding `[licenses.exceptions]`, which lets you allow 1 or more licenses only for a particular crate. Thanks for reporting [@iliana](https://github.com/iliana)!

## [0.5.1] - 2019-12-19
### Fixed
- Fixed issue where both `--manifest-path` and working directory were set when executing `cargo-metadata`, causing it to fail if a executed in a subdirectory.

## [0.5.0] - 2019-12-18
### Added
- Added the `advisories` check and configuration section for checking crates against an advisory database to detect security vulnerabilities, unmaintained crates, and crates with security notices
- A warning will now be emitted if a crate that isn't in the graph is specified in `[bans.skip-tree]`

### Fixed
- [PR#58](https://github.com/EmbarkStudios/cargo-deny/pull/58) Fixed [#55](https://github.com/EmbarkStudios/cargo-deny/issues/55) to handle license requirements for GPL, AGPL, LGPL, and GFDL better. Thank for reporting [@pikajude](https://github.com/pikajude)!
- [PR#62](https://github.com/EmbarkStudios/cargo-deny/pull/62) Fixed [#56](https://github.com/EmbarkStudios/cargo-deny/issues/56), the `[metadata]` section in `Cargo.lock` is now gone in nightly to improve merging, the previous reporting mechanism that required this section has been reworked.

### Changed
- The `check` subcommand now takes multiple values eg `cargo deny check bans advisories`
- Specifying either `cargo deny check` or `cargo deny check all` will now run the additional `advisories` check
- Previously, if you hadn't specified the `[licenses]` or `[bans]` section then running that check would have done nothing. Now if any section (including `[advisories]`) is not specified, the default configuration will be used.

### Deprecated
- `check ban` has been deprecated in favor of `check bans`
- `check license` has been deprecated in favor of `check licenses`

## [0.4.2] - 2019-12-02
### Added
- [PR#48](https://github.com/EmbarkStudios/cargo-deny/pull/48) Added an `init` subcommand to generate a cargo-deny template file with guiding comments. Thanks [@foresterre](https://github.com/foresterre)!

## [0.4.1] - 2019-11-28
### Fixed
- [PR#46](https://github.com/EmbarkStudios/cargo-deny/pull/46) Fixed issue where `license-file` was not being turned into an absolute path like the normal license file scanning, causing a crash. Thanks [@foresterre](https://github.com/foresterre)!
- Fixed an out of bounds panic when skipping a crate which wasn't present in the crate graph, that would have been sorted last if it had existed

## [0.4.0] - 2019-11-07
### Changed
- Replaced usage of `failure` with `anyhow`
- Upgraded askalono and spdx to newer versions that both use version 3.7 of the SPDX license list

## [0.3.0] - 2019-10-30
### Added
- Added `[licenses.copyleft]` config, which can be used to determine what happens when a copyleft license is encountered.
- Added `[bans.skip-tree]` config, which can be used to skip entire subtrees of a dependency graph when considering duplicates

### Fixed
- Fixed displaying of duplicate errors in the presence of a `skip`ped crate

## [0.3.0-beta] - 2019-10-07
### Added
- Output that pertains to a particular crate now outputs the inclusion graph for that crate, similarly to how [cargo tree](https://github.com/sfackler/cargo-tree) shows the inverse dependency graph. This can be turned off with the `--hide-inclusion-graphs` flag on the `check` subcommand.
- All configuration problems that aren't directly related to actual toml parsing now pretty print the location and cause(s) of the problem so that you can more easily fix the issue.
- Added the ``[licenses.clarify]]` key to the configuration, which allows users to specify the license expression for a crate that will be used as long as the version requirements are met, and the hash of the license file(s) are the same
- Added the `licenses.allow-osi-fsf-free` key, which can be used to specify blanket allowance of licenses based on whether they are [OSI Approved](https://opensource.org/licenses) or [FSF/Free Libre](https://www.gnu.org/licenses/license-list.en.html). It defaults to `neither`.

### Changed
- The output of the tool as a whole is dramatically different. Previously, all logging was done via `slog`, which is great for structured logging of high volume output, but wasn't really appropriate for a user facing tool. Some normal log output still exists, but almost all output is now done with the excellent [codespan](https://github.com/brendanzab/codespan) crate to give more user-friendly output.
- All configuration keys are now `kebab-case` instead of `snake_case`
- Improved the checking of [SPDX license expressions](https://spdx.org/spdx-specification-21-web-version#h.jxpfx0ykyb60), previously the expression was just lexed and all the requirements that could be understood were required, but now the operators in the expression are actually respected.
- Added proper support for license exceptions, you must now allow or deny licenses including their exception, which treated as a different case than the same license without the exception. eg `allow = [ "Apache-2.0 WITH LLVM-exception" ]` will not also allow `Apache-2.0` without the exception.
- The usage of `+` is now properly supported, eg. `Apache-2.0+` will now match `Apache-2.0` or a hypothetical `Apache-3.0` in the future.
- The `list` subcommand now treats licenses with exceptions as unique licenses.
- When `bans.multiple-versions` is either `deny` or `warn`, duplicates are printed out, including their particular inclusion graphs, in addition to optionally writing a dotgraph to a file on disk for more thorough inspection.
- LICENSE(-*)? files are no longer eagerly evaluated, rather the crate's license expression is retrieved via
  1. `license`
  2. Matching user override as specified via `licenses.clarify`
  3. Compounding all licenses together via `AND` only if **all** detected LICENSE files can be scored with confidence

### Fixed
- Previously, just having an empty `licenses.deny` and `licenses.allow` meant that **every** license would be accepted.
Now each license has to be explicitly approved, either by listing them in `licenses.allow` or `licenses.allow-osi-fsf-free`.

### Removed
- Removed the `licenses.ignore` key from the configuration, as this was [confusing](https://github.com/EmbarkStudios/cargo-deny/issues/16) to [users](https://github.com/EmbarkStudios/cargo-deny/issues/24). Supplanted by `licenses.clarify`.
- Removed the `licenses.skip` key from the configuration, supplanted by `licenses.clarify`.
- Removed the `licenses.unknown` key from the configuration, if a license cannot be inferred from a file, the path, score, and hash are now shown to the user as additional info for why a crate is considered "unlicensed".

## [0.2.5] - 2019-07-01
### Fixed
- Removed duplicate version of `rand`

## [0.2.4] - 2019-07-01
### Fixed
- Fixed banning specific crates via `bans.deny`

## [0.2.3] - 2019-07-01
### Changed
- Fixed up README in published crate

## [0.2.2] - 2019-06-28
### Added
- Added more badges to published crate

## [0.2.1] - 2019-06-28
### Added
- Initial implementation release

<!-- next-url -->
[Unreleased]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.8...HEAD
[0.6.8]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.7...0.6.8
[0.6.7]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.6...0.6.7
[0.6.6]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.5...0.6.6
[0.6.5]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.4...0.6.5
[0.6.4]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.3...0.6.4
[0.6.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.2...0.6.3
[0.6.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.1...0.6.2
[0.6.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.5.2...0.6.0
[0.5.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.5.1...0.5.2
[0.5.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.4.2...0.5.0
[0.4.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.3.0-beta...0.3.0
[0.3.0-beta]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.5...0.3.0-beta
[0.2.5]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.4...0.2.5
[0.2.4]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.3...0.2.4
[0.2.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.2...0.2.3
[0.2.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.2.1
