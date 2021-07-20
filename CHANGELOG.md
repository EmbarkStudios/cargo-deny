# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
### Changed
- [PR#358](https://github.com/EmbarkStudios/cargo-deny/pull/358) bumped the Minimum Stable Rust Version to **1.53.0**.
- [PR#358](https://github.com/EmbarkStudios/cargo-deny/pull/358) bumped various dependencies, notably `semver` to `1.0.3`.

## [0.9.1] - 2021-03-26
### Changed
- Updated dependencies

## [0.9.0] - 2021-03-11
### Changed
- Updated `krates`, which in turn uses an updated `cargo_metadata` which uses [`camino`](https://docs.rs/camino) for utf-8 paths. Rather than support both vanilla Path/Buf and Utf8Path/Buf, cargo-deny now just uses Utf8Path/Buf, which means that non-utf-8 paths for things like your Cargo.toml manifest or license paths will no longer function. This is a breaking change, that can be reverted if it is disruptive for users, but the assumption is that cargo-deny is operating on normal checkouts of rust repositories that are overwhelmingly going to be utf-8 compatible paths.

## [0.8.9] - 2021-03-08
### Fixed
- Updated rustsec crate to address fetch failures due to the renaming of the `master` branch to `main` for https://github.com/rustsec/advisory-db

## [0.8.8] - 2021-02-25
### Changed
- Updated dependencies, notably `cargo` and `rustsec`.
- Increase MSRV to `1.46.0` due to bump of `smol_str`/`rustsec`.
- Updated SPDX license list supported from 3.8 to 3.11 due to update of `spdx`.
- Add use of the `--locked` flag in all `cargo install` instructions, to avoid the default (broken) behavior as shown in [#331](https://github.com/EmbarkStudios/cargo-deny/issues/331).

## [0.8.7] - 2021-02-18
### Fixed
- Resolved [#331](https://github.com/EmbarkStudios/cargo-deny/issues/331) by updating `bitvec` and `funty`.

## [0.8.6] - 2021-02-17
### Changed
- Updated dependencies, notably `cargo`.
- Updated documentation to clarify SPDX identifiers, and how to use custom ones.

## [0.8.5] - 2020-12-15
### Added
- [PR#315](https://github.com/EmbarkStudios/cargo-deny/pull/315) resolved [#312](https://github.com/EmbarkStudios/cargo-deny/issues/312) by adding support for excluding packages in the deny configuration file, in addition to the existing support for the `--exclude` CLI option. Thanks [@luser](https://github.com/luser)!

### Fixed
- [PR#318](https://github.com/EmbarkStudios/cargo-deny/pull/318) fixed [#316](https://github.com/EmbarkStudios/cargo-deny/issues/316) by adding a workaround for crate versions with pre-release identifiers in them that could be erroneously marked as matching advisories in an advisory database. Thanks for reporting this [@djc](https://github.com/djc)!

## [0.8.4] - 2020-11-11
### Changed
- Updated dependencies, notably `rustsec`, `crossbeam`*, and `cargo`.
- Bumped the Minimum Stable Rust Version to **1.44.1**.

## [0.8.3] - 2020-11-09
### Fixed
- Fix `deny.template.toml` to use `db-urls` instead of `db-url`.

## [0.8.2] - 2020-10-22
### Fixed
- [PR#303](https://github.com/EmbarkStudios/cargo-deny/pull/303) fixed [#302](https://github.com/EmbarkStudios/cargo-deny/issues/302) by reverting an unintended behavior change in how the default path for advisory databases was resolved.

## [0.8.1] - 2020-10-21
### Fixed
- [PR#297](https://github.com/EmbarkStudios/cargo-deny/pull/297) fixed a couple of diagnostics to have codes.
- [PR#296](https://github.com/EmbarkStudios/cargo-deny/pull/296) resolved [#288](https://github.com/EmbarkStudios/cargo-deny/issues/288) by improving the information in diagnostics pertaining to advisories. Thanks [@tomasfarias](https://github.com/tomasfarias)!

## [0.8.0] - 2020-10-20
### Added
- [PR#238](https://github.com/EmbarkStudios/cargo-deny/pull/238) resolved [#225](https://github.com/EmbarkStudios/cargo-deny/issues/225) by adding a `wrappers` field to `[bans.deny]` entries, which allows the banned crate to be used only if it is a direct dependency of one of the wrapper crates. Thanks [@Stupremee](https://github.com/Stupremee)!
- [PR#244](https://github.com/EmbarkStudios/cargo-deny/pull/244) resolved [#69](https://github.com/EmbarkStudios/cargo-deny/issues/69) by adding support for multiple advisory databases, which will all be checked during the `advisory` check. Thanks [@Stupremee](https://github.com/Stupremee)!
- [PR#243](https://github.com/EmbarkStudios/cargo-deny/pull/243) resolved [#54](https://github.com/EmbarkStudios/cargo-deny/issues/54) by adding support for compiling and using `cargo` crate directly via the `standalone` feature. This allows `cargo-deny` to be used without cargo being installed, but it still requires [**rustc**](https://github.com/EmbarkStudios/cargo-deny/issues/295) to be available. Thanks [@Stupremee](https://github.com/Stupremee)!
- [PR#275](https://github.com/EmbarkStudios/cargo-deny/pull/275) resolved [#64](https://github.com/EmbarkStudios/cargo-deny/issues/64) by adding a diagnostic when a user tries to ignore an advisory identifier that doesn't exist in any database.
- [PR#262](https://github.com/EmbarkStudios/cargo-deny/pull/262) added the `fix` subcommand, which was added to bring `cargo-deny` to feature parity with `cargo-audit` so that it can take over for `cargo-audit` as the [official frontend](https://github.com/EmbarkStudios/cargo-deny/issues/194) for the the [RustSec Advisory Database](https://github.com/RustSec/advisory-db).

### Changed
- `advisories.db-url` has been deprecated in favor of `advisories.db-urls` since multiple databses are now supported.
- `advisories.db-path` is now no longer the directory into which the advisory database is cloned into, but rather a root directory where each unique database is placed in a canonicalized directory similar to how `.cargo/registry/index` directories work.
- [PR#274](https://github.com/EmbarkStudios/cargo-deny/pull/274) resolved [#115](https://github.com/EmbarkStudios/cargo-deny/issues/115) by normalizing git urls. Thanks [@senden9](https://github.com/senden9)!

### Fixed
- [#265](https://github.com/EmbarkStudios/cargo-deny/issues/265) A transitive dependency (`smol_str`) forced the usage of the latest Rust stable version (1.46) which was unintended. We now state the MSRV in the README and check for it in CI so that changing the MSRV is a conscious decision.
- [PR#287](https://github.com/EmbarkStudios/cargo-deny/pull/287) fixed [#286](https://github.com/EmbarkStudios/cargo-deny/issues/286), which could happen if using a git source where the representation differed slightly between the user specified id and the id used for dependencies.
- [PR#249](https://github.com/EmbarkStudios/cargo-deny/pull/249) fixed [#190](https://github.com/EmbarkStudios/cargo-deny/issues/190) by printing a different diagnostic for when the path specified for a clarification license file could not be found. Thanks [@khodzha](https://github.com/khodzha)!

## [0.7.3] - 2020-08-06
### Added
- [PR#237](https://github.com/EmbarkStudios/cargo-deny/pull/237) added the ability to allow git sources from entire `github.com`, `gitlab.com`, or `bitbucket.org` organizations.
- [PR#237](https://github.com/EmbarkStudios/cargo-deny/pull/237) added the ability to lint the specifiers used for git sources.

## [0.7.2] - 2020-07-28
### Added
- [PR#227](https://github.com/EmbarkStudios/cargo-deny/pull/227) Added a new `bans.wildcards` check to lint for version requirements of `"*"`, which can happen when using local or patched crates that aren't published to a registry. Thanks [@khodzha](https://github.com/khodzha)!

### Fixed
- Fix incompatible crate versions due to `cargo_metadata`.

## [0.7.1] - 2020-07-21
### Fixed
- Fix issue due to incompatible semver versioning with relation to...the semver crate.

## [0.7.0] - 2020-06-25
### Added
- Resolved [#137](https://github.com/EmbarkStudios/cargo-deny/issues/137) by adding a `--format <human|json>` option. All diagnostic and log messages from the `check` subcommand respect this flag.

### Changed
- Resolved [#216](https://github.com/EmbarkStudios/cargo-deny/issues/216) by adding support for the `--all-features`, `--features`, and `--no-default-features` flags to specify the exact features to have enabled when gathering the crates in your dependency graph to actually run checks against. This is a **BREAKING CHANGE** as previously crates were gathered with `--all-features`.
- The `--color` option for the `list` subcommand has been moved to the top level arguments.

### Removed
- The `--context` option , which was deprecated in `0.6.3`, has been removed.

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
[Unreleased]: https://github.com/EmbarkStudios/cargo-deny/compare/0.9.1...HEAD
[0.9.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.9.0...0.9.1
[0.9.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.9...0.9.0
[0.8.9]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.8...0.8.9
[0.8.8]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.7...0.8.8
[0.8.7]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.6...0.8.7
[0.8.6]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.5...0.8.6
[0.8.5]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.4...0.8.5
[0.8.4]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.3...0.8.4
[0.8.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.2...0.8.3
[0.8.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.1...0.8.2
[0.8.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.7.3...0.8.0
[0.7.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.7.2...0.7.3
[0.7.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.7.1...0.7.2
[0.7.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.7.0...0.7.1
[0.7.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.6.8...0.7.0
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
