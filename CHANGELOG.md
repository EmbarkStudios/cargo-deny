# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2019-11-28
### Fixed
- [PR#46](https://github.com/EmbarkStudios/cargo-deny/pull/46) Fixed issue where `license-file` was not being
turned into an absolute path like the normal license file scanning, causing a crash. Thanks [@foresterre](https://github.com/foresterre)!
- Fixed an out of bounds panic when skipping a crate which wasn't present in the crate graph, that would
have been sorted last if it had existed

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
- All configuration problems that aren't directly related to actual toml parsing now pretty print the location and cause(s)
of the problem so that you can more easily fix the issue.
- Added the ``[licenses.clarify]]` key to the configuration, which allows users to specify the license expression
for a crate that will be used as long as the version requirements are met, and the hash of the license file(s) are the same
- Added the `licenses.allow-osi-fsf-free` key, which can be used to specify blanket allowance of licenses based on whether they are [OSI Approved](https://opensource.org/licenses) or [FSF/Free Libre](https://www.gnu.org/licenses/license-list.en.html). It defaults to `neither`.

### Changed
- The output of the tool as a whole is dramatically different. Previously, all logging was done via `slog`, which is
great for structured logging of high volume output, but wasn't really appropriate for a user facing tool. Some normal log output still exists, but almost all output is now done with the excellent [codespan](https://github.com/brendanzab/codespan) crate to give more user-friendly output.
- All configuration keys are now `kebab-case` instead of `snake_case`
- Improved the checking of [SPDX license expressions](https://spdx.org/spdx-specification-21-web-version#h.jxpfx0ykyb60),
previously the expression was just lexed and all the requirements that could be understood were required, but now the operators in the expression are actually respected.
- Added proper support for license exceptions, you must now allow or deny licenses including their exception, which treated as a different case than the same license without the exception. eg `allow = [ "Apache-2.0 WITH LLVM-exception" ]` will not also allow `Apache-2.0` without the exception.
- The usage of `+` is now properly supported, eg. `Apache-2.0+` will now match `Apache-2.0` or a hypothetical `Apache-3.0` in the future.
- The `list` subcommand now treats licenses with exceptions as unique licenses.
- When `bans.multiple-versions` is either `deny` or `warn`, duplicates are printed out, including their particular
inclusion graphs, in addition to optionally writing a dotgraph to a file on disk for more thorough inspection.
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

[Unreleased]: https://github.com/EmbarkStudios/cargo-deny/compare/0.4.1...HEAD
[0.4.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.3.0-beta...0.3.0
[0.3.0-beta]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.5...0.3.0-beta
[0.2.5]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.4...0.2.5
[0.2.4]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.3...0.2.4
[0.2.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.2...0.2.3
[0.2.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.2.1
