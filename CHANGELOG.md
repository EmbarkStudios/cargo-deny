<!-- markdownlint-disable blanks-around-headings blanks-around-lists no-duplicate-heading -->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
## [0.14.4] - 2024-01-19
### Fixed
- [PR#586](https://github.com/EmbarkStudios/cargo-deny/pull/586) resolved 2 issues with crate graph creation, see [krates#60](https://github.com/EmbarkStudios/krates/issues/60) and [krates#64](https://github.com/EmbarkStudios/krates/issues/64) for more details.

## [0.14.3] - 2023-09-29
### Fixed
- [PR#566](https://github.com/EmbarkStudios/cargo-deny/pull/566) updated `tame-index` to obtain support OS file locking, resolving [#537](https://github.com/EmbarkStudios/cargo-deny/issues/537). This change means that cargo-deny should not encounter issues such as those described [here](https://github.com/rustsec/rustsec/issues/1011) since we no longer use `gix::lock` locking advisory databases, and makes reading the crates.io index safer by respecting the lock used by cargo itself.

## [0.14.2] - 2023-09-04
### Added
- [PR#545](https://github.com/EmbarkStudios/cargo-deny/pull/545) added the ability to specify additional license exceptions via [additional configuration files](https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html#additional-exceptions-configuration-file).
- [PR#549](https://github.com/EmbarkStudios/cargo-deny/pull/549) added the [`bans.build`](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-build-field-optional) configuration option, opting in to checking for [file extensions](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-script-extensions-field-optional), [native executables](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-executables-field-optional), and [interpreted scripts](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-interpreted-field-optional). This resolved [#43](https://github.com/EmbarkStudios/cargo-deny/issues/43).

### Changed
- [PR#557](https://github.com/EmbarkStudios/cargo-deny/pull/557) introduced changes to how [`dev-dependencies`](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#development-dependencies) are handled. By default, crates that are only used as dev-dependencies (ie, there are no normal nor build dependency edges linking them to other crates) will no longer be considered when checking for [`multiple-versions`](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-multiple-versions-field-optional) violations. This can be re-enabled via the [`bans.multiple-versions-include-dev`](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-multiple-versions-include-dev-field-optional) config field. Additionally, licenses are no longer checked for `dev-dependencies`, but can be re-enabled via [`licenses.include-dev`](https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html#the-include-dev-field-optional) the config field. `dev-dependencies` can also be completely disabled altogether, but this applies to all checks, including `advisories` and `sources`, so is not enabled by default. This behavior can be enabled by using the [`exclude-dev`](https://embarkstudios.github.io/cargo-deny/checks/cfg.html#the-exclude-dev-field-optional) field, or the `--exclude-dev` command line flag. This change resolved [#322](https://github.com/EmbarkStudios/cargo-deny/issues/322), [#329](https://github.com/EmbarkStudios/cargo-deny/issues/329), [#413](https://github.com/EmbarkStudios/cargo-deny/issues/413) and [#497](https://github.com/EmbarkStudios/cargo-deny/issues/497).

### Fixed
- [PR#549](https://github.com/EmbarkStudios/cargo-deny/pull/549) fixed [#548](https://github.com/EmbarkStudios/cargo-deny/issues/548) by correctly locating cargo registry indices from an git ssh url.
- [PR#549](https://github.com/EmbarkStudios/cargo-deny/pull/549) fixed [#552](https://github.com/EmbarkStudios/cargo-deny/issues/552) by correctly handling signal interrupts and removing the advisory-dbs lock file.
- [PR#549](https://github.com/EmbarkStudios/cargo-deny/pull/549) fixed [#553](https://github.com/EmbarkStudios/cargo-deny/issues/553) by adding the `native-certs` feature flag that can enable the OS native certificate store.

### Deprecated
- [PR#549](https://github.com/EmbarkStudios/cargo-deny/pull/549) moved `bans.allow-build-scripts` to [`bans.build.allow-build-scripts`](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-allow-build-scripts-field-optional). `bans.allow-build-scripts` is still supported, but emits a warning.

## [0.14.1] - 2023-08-02
### Fixed
- [PR#544](https://github.com/EmbarkStudios/cargo-deny/pull/544) updated dependencies, notably `tame-index 0.2.5` which fixed [this issue](https://github.com/EmbarkStudios/tame-index/issues/8)

### Changed
- [PR#538](https://github.com/EmbarkStudios/cargo-deny/pull/538) resolved [#483](https://github.com/EmbarkStudios/cargo-deny/issues/483) by emitting exit codes as a bitset of the individual checks that failed, allowing scripts to handle checks separately from a single run. This could affect users who check exactly for the exit code being 1, as that will now only be emitted if the `advisories`, but no other, check fails.

## [0.14.0] - 2023-07-28
### Changed
- [PR#520] resolved [#522](https://github.com/EmbarkStudios/cargo-deny/issues/522) by completely removing all dependencies upon `git2` and `openssl`. This was done by transitioning from `git2` -> `gix` for all git operations, both directly in this crate, as well as replacing [`crates-index`](https://github.com/frewsxcv/rust-crates-index) with [`tame-index`](https://github.com/EmbarkStudios/tame-index).
- [PR#520] bumped the MSRV from `1.65.0` -> `1.70.0`
- [PR#523](https://github.com/EmbarkStudios/cargo-deny/pull/523) added "(try `cargo update -p <crate_name>`)" when an advisory is detected for a crate. Thanks [@Victor-N-Suadicani](https://github.com/Victor-N-Suadicani)!

### Fixed
- [PR#520] resolved [#361](https://github.com/EmbarkStudios/cargo-deny/issues/361) by printing output when a fetch is being performed to clarify what is taking time.
- [PR#520] (possibly) resolved [#435](https://github.com/EmbarkStudios/cargo-deny/issues/435) by switching all git operations from `git2` to `gix`.
- [PR#520] resolved [#439](https://github.com/EmbarkStudios/cargo-deny/issues/439) by using minimal refspecs for cloning and fetching all remote git repositories (indices or advisory databases) where only the remote HEAD is needed to update the local repository, regardless of the default remote branch pointed to by HEAD.
- [PR#520] resolved [#446](https://github.com/EmbarkStudios/cargo-deny/issues/446) by ensuring (and testing) that crates from non-registry sources are not checked for advisories, eg. in the case that a local crate is named and versioned the same as a crate from crates.io that has an advisory that affects it.
- [PR#520] resolved [#515](https://github.com/EmbarkStudios/cargo-deny/issues/515) by always opening the correct registry index based upon the environment.
- [PR#531](https://github.com/EmbarkStudios/cargo-deny/pull/531) resolved [#210](https://github.com/EmbarkStudios/cargo-deny/issues/210) by adding `osi` and `fsf` options to `licenses.allow-osi-fsf-free`. Thanks [@zkxs](https://github.com/zkxs)!
- [PR#533](https://github.com/EmbarkStudios/cargo-deny/pull/533) resolved [#521](https://github.com/EmbarkStudios/cargo-deny/issues/521) and [#524](https://github.com/EmbarkStudios/cargo-deny/issues/524) by allowing clarifications to add files that are used to verify the license information is up to date, rather than needing to match one of the license files that was discovered.
- [PR#534](https://github.com/EmbarkStudios/cargo-deny/pull/534) resolved [#479](https://github.com/EmbarkStudios/cargo-deny/issues/479) by improving how advisory databases are cloned and/or fetched, notably each database now uses `gix`'s [file-based locking](https://docs.rs/gix-lock/7.0.2/gix_lock/struct.Marker.html#method.acquire_to_hold_resource) to ensure that only one process has mutable access to an advisory database repo at a time.

### Removed
- [PR#520] removed all features, notably `standalone`. This is due to cargo still being in transition from `git2` -> `gix` and having no way to compiled _without_ OpenSSL. Once cargo is a better state with regards to this we can add back that feature.

[PR#520]: https://github.com/EmbarkStudios/cargo-deny/pull/520

## [0.13.9] - 2023-04-12
### Fixed
- [PR#506](https://github.com/EmbarkStudios/cargo-deny/pull/506) replaced `atty` (unmaintained) with `is-terminal`. Thanks [@tottoto](https://github.com/tottoto)!
- [PR#511](https://github.com/EmbarkStudios/cargo-deny/pull/511) resolved [#494](https://github.com/EmbarkStudios/cargo-deny/issues/494), [#507](https://github.com/EmbarkStudios/cargo-deny/issues/507), and [#510](https://github.com/EmbarkStudios/cargo-deny/issues/510) by fixing up how and when urls are normalized.
- [PR#512](https://github.com/EmbarkStudios/cargo-deny/pull/512) resolved [#509](https://github.com/EmbarkStudios/cargo-deny/issues/509) by fixing casing of the root configuration keys.
- [PR#513](https://github.com/EmbarkStudios/cargo-deny/pull/513) resolved [#508](https://github.com/EmbarkStudios/cargo-deny/issues/508) by correctly using the crates.io sparse index when checking for yanked crates if specified by the user, as well as falling back to the regular git index if the sparse index is not present.

## [0.13.8] - 2023-04-06
### Added
- [PR#504](https://github.com/EmbarkStudios/cargo-deny/pull/504) (though really [PR#365](https://github.com/EmbarkStudios/cargo-deny/pull/365)) resolved [#350](https://github.com/EmbarkStudios/cargo-deny/issues/350) by adding the `deny-multiple-versions` field to `bans.deny` entries, allowing specific crates to deny multiple versions while allowing/warning on them more generally. Thanks [@leops](https://github.com/leops)!
- [PR#493](https://github.com/EmbarkStudios/cargo-deny/pull/493) resolved [#437](https://github.com/EmbarkStudios/cargo-deny/issues/437) by also looking for deny configuration files in `.cargo`. Thanks [@DJMcNab](https://github.com/DJMcNab)!
- [PR#502](https://github.com/EmbarkStudios/cargo-deny/pull/502) resolved [#500](https://github.com/EmbarkStudios/cargo-deny/issues/500) by adding initial support for [sparse indices](https://blog.rust-lang.org/inside-rust/2023/01/30/cargo-sparse-protocol.html).

### Fixed
- [PR#503](https://github.com/EmbarkStudios/cargo-deny/pull/503) resolved [#498](https://github.com/EmbarkStudios/cargo-deny/issues/498) by falling back to more lax parsing of the SPDX expression of crate if fails to parse according to the stricter but more correct rules.

## [0.13.7] - 2023-01-11
### Fixed
- [PR#491](https://github.com/EmbarkStudios/cargo-deny/pull/491) resolved [#490](https://github.com/EmbarkStudios/cargo-deny/issues/490) by building libgit2 from vendored sources instead of relying on potentially outdated packages.

## [0.13.6] - 2023-01-11
### Changed
- [PR#489](https://github.com/EmbarkStudios/cargo-deny/pull/489) updated dependencies, notably `clap`, `cargo`, and `git2`

### Added
- [PR#485](https://github.com/EmbarkStudios/cargo-deny/pull/485) added this project and repository to our Security Bug Bounty Program and has Private vulnerability reporting enabled. See [`SECURITY.md`](./SECURITY.md) for more details.
- [PR#487](https://github.com/EmbarkStudios/cargo-deny/pull/487) added `allow-wildcard-paths`, fixing [#488](https://github.com/EmbarkStudios/cargo-deny/issues/448) by allowing wildcards to be denied, but allowing them for internal, private crates. Thanks [@sribich](https://github.com/sribich)!

### Fixed
- [PR#489](https://github.com/EmbarkStudios/cargo-deny/pull/489) fixed an issue where git sources where `branch=master` would be incorrectly categorized as not specifying the branch (ie use HEAD of default branch).

## [0.13.5] - 2022-11-08
### Fixed
- [PR#481](https://github.com/EmbarkStudios/cargo-deny/pull/481) bumped `krates` to 0.12.5 to fix an issue where features present (and enabled) for a crate could be remove if the index entry for the crate didn't contain that feature. The features are now merged to (hopefully) more accurately reflect the features that are "truly" available according to both the index and the actual crate manifest on disk.
- [PR#481](https://github.com/EmbarkStudios/cargo-deny/pull/481) fixed an issue where gathering licenses from files would fail if any license file could not have its license determined, even if one or more license files _could_ be successfully identified. This now no longer fails, and the license files that fail to be identified are now shown as additional labels in any diagnostic that is shown for that crate's licenses.

## [0.13.4] - 2022-11-03
### Fixed
- [PR#477](https://github.com/EmbarkStudios/cargo-deny/pull/477) resolved [#476](https://github.com/EmbarkStudios/cargo-deny/issues/476) by replacing bad test code with the correct code.

## [0.13.3] - 2022-11-02
### Fixed
- [PR#475](https://github.com/EmbarkStudios/cargo-deny/pull/475) updated `krates` to 0.12.4, which fixes an issue where cycles in a crate's feature set would result in an infinite loop.

## [0.13.2] - 2022-11-01
### Fixed
- [PR#473](https://github.com/EmbarkStudios/cargo-deny/pull/473) updated `krates` to 0.12.3, which addresses an issue where a crate's feature set can differ between the version in the registry, and same version on disk.

## [0.13.1] - 2022-10-28
### Fixed
- [PR#471](https://github.com/EmbarkStudios/cargo-deny/pull/471) fixed a bug where optional dependencies could be pruned if the feature that enabled it was named differently from the crate.
- [PR#471](https://github.com/EmbarkStudios/cargo-deny/pull/471) resolved an issue where `skip-tree` entries weren't properly ignoring all of their transitive dependencies, resolving [#469](https://github.com/EmbarkStudios/cargo-deny/issues/469).

## [0.13.0] - 2022-10-26
### Added
- [PR#434](https://github.com/EmbarkStudios/cargo-deny/pull/434) together with [PR#461](https://github.com/EmbarkStudios/cargo-deny/pull/461) resolved [#206](https://github.com/EmbarkStudios/cargo-deny/issues/206) and [#226](https://github.com/EmbarkStudios/cargo-deny/issues/226) by adding support for checking the feature sets enabled for crates. See [the docs](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-features-field-optional) for configuration options. Thanks [@Stupremee](https://github.com/Stupremee)!
- [PR#464](https://github.com/EmbarkStudios/cargo-deny/pull/464) added the `-A, --allow`, `-D, --deny` and `-W, --warn` options to the `check` subcommand. This allows one to override the severity level of both specific diagnostics, eg. `-D unmaintained` would fail if there was an unmaintained dependency, even if `advisories.unmaintained` was `allow` or `warn`. One can also change an entire severity itself, the typical case being `-D warnings` to upgrade all warnings to errors. Resolved [#454](https://github.com/EmbarkStudios/cargo-deny/issues/454).
- [PR#466](https://github.com/EmbarkStudios/cargo-deny/pull/466) added the `all-features`, `no-default-features`, `features`, and `feature-depth` configuration options, allowing configuration of features so that one doesn't need to always specify them via the command line.

### Changed
- [PR#447](https://github.com/EmbarkStudios/cargo-deny/pull/447) add more details to the diagnostic reported when a `bans.skip` crate was not located in the graph. Thanks [@daviddrysdale](https://github.com/daviddrysdale)!
- [PR#464](https://github.com/EmbarkStudios/cargo-deny/pull/464) changed all error codes from the previous rustc style eg. `B001` style to more clippy style descriptive names, eg. `banned`, resolving [#61](https://github.com/EmbarkStudios/cargo-deny/issues/61).

### Fixed
- [PR#465](https://github.com/EmbarkStudios/cargo-deny/pull/465) fixed an issue where inclusion graphs would not be printed in diagnostics if the same crate had an earlier associated diagnostic, even if that diagnostic was not printed due to the log level.
- [PR#464](https://github.com/EmbarkStudios/cargo-deny/pull/464) fixed [#455](https://github.com/EmbarkStudios/cargo-deny/issues/455) by removing code. The best kind of fix.

## [0.12.2] - 2022-08-05
### Added
- [PR#431](https://github.com/EmbarkStudios/cargo-deny/pull/432) resolved [#19](https://github.com/EmbarkStudios/cargo-deny/issues/19) by adding support for an allow list for build scripts, allowing a project to opt in (or deny completely) build scripts on a case by case basis rather than blanket allowing all build scripts. See the [`bans.allow-build-scripts`](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html#the-allow-build-scripts-field-optional) config option for more details. Thanks [@Stupremee](https://github.com/Stupremee)!

### Fixed
- [PR#430](https://github.com/EmbarkStudios/cargo-deny/pull/430) fixed an issue where local/git crates could be flagged as "yanked" if they shared a name and version with a crates.io crate that was yanked from the registry, resolving [#441](https://github.com/EmbarkStudios/cargo-deny/issues/441) before it was even opened. Thanks [@khuey](https://github.com/khuey)!
- [PR#440](https://github.com/EmbarkStudios/cargo-deny/pull/440) fixed [#438](https://github.com/EmbarkStudios/cargo-deny/issues/438) by ensuring git cli output was piped properly rather than polluting the output of cargo-deny itself.
- [PR#443](https://github.com/EmbarkStudios/cargo-deny/pull/443) fixed [#442](https://github.com/EmbarkStudios/cargo-deny/issues/442) by removing the signature check on the HEAD commit an advisory databases. This check didn't add meaningful security and could cause spurious failures if an unsigned commit was pushed to an advisory database.

### Changed
- [PR#431](https://github.com/EmbarkStudios/cargo-deny/pull/431) updated clap to 3.2. Thanks [@epage](https://github.com/epage)!

## [0.12.1] - 2022-05-19
### Fixed
- [PR#426](https://github.com/EmbarkStudios/cargo-deny/pull/426) fixed an oversight in [PR#422](https://github.com/EmbarkStudios/cargo-deny/pull/422), fully resolving [#412](https://github.com/EmbarkStudios/cargo-deny/issues/412) by allowing both `https` and `ssh` URLs for advisory databases. Thanks [@jbg](https://github.com/jbg)!

### Changed
- [PR#427](https://github.com/EmbarkStudios/cargo-deny/pull/427) updated dependencies.

## [0.12.0] - 2022-05-17
### Removed
- [PR#423](https://github.com/EmbarkStudios/cargo-deny/pull/423) removed the `fix` subcommand. This functionality was far too complicated for far too little benefit.

### Fixed
- [PR#420](https://github.com/EmbarkStudios/cargo-deny/pull/420) resolved [#388](https://github.com/EmbarkStudios/cargo-deny/issues/388) by adding the ability to fetch advisory databases via the `git` CLI. Thanks [@danielhaap83](https://github.com/danielhaap83)!
- [PR#422](https://github.com/EmbarkStudios/cargo-deny/pull/422) fixed [#380](https://github.com/EmbarkStudios/cargo-deny/issues/380) and [#410](https://github.com/EmbarkStudios/cargo-deny/issues/410) by updating a few transitive dependencies that use `git2`, as well as removing the usage of `rustsec`'s `git` feature so that we now use `git2 v0.14`, resolving a crash issue in new `libgit2` versions available in eg. rolling release distros such as Arch. This should also make it easier to update and improve git related functionality since more of it is inside cargo-deny itself now.
- [PR#424](https://github.com/EmbarkStudios/cargo-deny/pull/424) _really_ fixed (there's even a test now!) [#384](https://github.com/EmbarkStudios/cargo-deny/issues/384) by adding each version's reverse dependency graph in the ascending order.

## [0.11.4] - 2022-04-11
### Fixed
- [PR#414](https://github.com/EmbarkStudios/cargo-deny/pull/414) resolved [#384](https://github.com/EmbarkStudios/cargo-deny/issues/384) by always sorting crates with the same name by their version so they are always deterministically sorted. Thanks [@Veykril](https://github.com/Veykril)!
- [PR#418](https://github.com/EmbarkStudios/cargo-deny/pull/418) fixed an issue where duplicate crate versions would not be detected if the crate was sorted last in the crate graph.

### Changed
- [PR#415](https://github.com/EmbarkStudios/cargo-deny/pull/415) updated dependencies, notably `regex` to fix [RUSTSEC-2022-0013](https://rustsec.org/advisories/RUSTSEC-2022-0013.html).

## [0.11.3] - 2022-02-14
### Fixed
- [PR#407](https://github.com/EmbarkStudios/cargo-deny/pull/407) resolved [#406](https://github.com/EmbarkStudios/cargo-deny/issues/406) by always checking license exceptions first.

## [0.11.2] - 2022-02-07
### Changed
- [PR#403](https://github.com/EmbarkStudios/cargo-deny/pull/403) added support for the [`CARGO_TERM_COLOR`](https://doc.rust-lang.org/cargo/reference/config.html#termcolor) environment variable. Thanks [@svenstaro](https://github.com/svenstaro)!
- [PR#404](https://github.com/EmbarkStudios/cargo-deny/pull/404) updated dependencies.

### Fixed
- [PR#398](https://github.com/EmbarkStudios/cargo-deny/pull/398) resolved [#135](https://github.com/EmbarkStudios/cargo-deny/issues/135) by making [`licenses.exceptions`] additive to the global allow list. Thanks [@senden9](https://github.com/senden9)!
- [PR#404](https://github.com/EmbarkStudios/cargo-deny/pull/404) resolved [#401](https://github.com/EmbarkStudios/cargo-deny/issues/401) by trimming quotes from spans before serializing them as JSON.
- [PR#404](https://github.com/EmbarkStudios/cargo-deny/pull/404) resolved [#402](https://github.com/EmbarkStudios/cargo-deny/issues/402) by updating crossbeam-utils to a non-yanked version.

## [0.11.1] - 2022-01-28
### Added
- [PR#391](https://github.com/EmbarkStudios/cargo-deny/pull/391) resolved [#344](https://github.com/EmbarkStudios/cargo-deny/issues/344) by adding `[licenses.ignore-sources]` to ignore license checking for crates sourced from 1 or more specified registries. Thanks [@ShellWowza](https://github.com/ShellWowza)!
- [PR#396](https://github.com/EmbarkStudios/cargo-deny/pull/396) resolved [#366](https://github.com/EmbarkStudios/cargo-deny/issues/366) by also looking for `.deny.toml` in addition to `deny.toml` if a config file is not specified.

### Changed
- [PR#392](https://github.com/EmbarkStudios/cargo-deny/pull/392) updated all dependencies.

### Fixed
- [PR#393](https://github.com/EmbarkStudios/cargo-deny/pull/393) resolved [#371](https://github.com/EmbarkStudios/cargo-deny/issues/371) by changing the default for version requirements specified in config files to accept all versions, rather than using the almost-but-not-quite default of `*`.
- [PR#394](https://github.com/EmbarkStudios/cargo-deny/pull/394) resolved [#147](https://github.com/EmbarkStudios/cargo-deny/issues/147) by ignore _all_ private crates, not only the ones in the workspace.
- [PR#395](https://github.com/EmbarkStudios/cargo-deny/pull/395) resolved [#375](https://github.com/EmbarkStudios/cargo-deny/issues/375) by fixing a potential infinite loop when using `[bans.skip-tree]`.

## [0.11.0] - 2021-12-06
### Changed
- [PR#382](https://github.com/EmbarkStudios/cargo-deny/pull/382) updated dependencies and bumped the Minimum Stable Rust Version to **1.56.1**.

## [0.10.3] - 2021-11-22
### Changed
- [PR#379](https://github.com/EmbarkStudios/cargo-deny/pull/379) updated `askalono` which got rid of the `failure` dependency, which was pulling in a lot of additional crates that are now gone.

### Fixed
- [PR#379](https://github.com/EmbarkStudios/cargo-deny/pull/379) fixed [#378](https://github.com/EmbarkStudios/cargo-deny/issues/378) which was an edge case where the `sources` check was executed against a crate that didn't use any crates from crates.io, and the config file was shorter than the crates.io URL.

## [0.10.2] - 2021-11-21
### Fixed
- [PR#376](https://github.com/EmbarkStudios/cargo-deny/pull/376) fixed the JSON formatting when using `--format json` output option. Thanks [@dnaka91](https://github.com/dnaka91)!

### Changed
- [PR#377](https://github.com/EmbarkStudios/cargo-deny/pull/377) updated dependencies.

## [0.10.1] - 2021-11-10
### Fixed
- [PR#347](https://github.com/EmbarkStudios/cargo-deny/pull/374) resolved [#372](https://github.com/EmbarkStudios/cargo-deny/issues/372) by correcting a slight mistake that resulted in an incorrect hash making cargo-deny unable to lookup index or crate information from the local file system.

## [0.10.0] - 2021-10-29
### Added
- [PR#353](https://github.com/EmbarkStudios/cargo-deny/pull/353) resolved [#351](https://github.com/EmbarkStudios/cargo-deny/issues/351) by adding the `sources.private` field to blanket allow git repositories sourced from a particular url.
- [PR#359](https://github.com/EmbarkStudios/cargo-deny/pull/359) resolved [#341](https://github.com/EmbarkStudios/cargo-deny/issues/341) and [#357](https://github.com/EmbarkStudios/cargo-deny/issues/357) by adding support for the [`--frozen`, `--locked`, and `--offline`](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html#manifest-options) flags to determine whether network access is allowed, and whether the `Cargo.lock` file can be created and/or modified.
- [PR#368](https://github.com/EmbarkStudios/cargo-deny/pull/368) added the `licenses.unused-allowed-license` field to control whether the [L006 - license was not encountered](https://embarkstudios.github.io/cargo-deny/checks/licenses/diags.html#l006---license-was-not-encountered) diagnostic. Thanks [@thomcc](https://github.com/thomcc)!

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
- Updated rustsec crate to address fetch failures due to the renaming of the `master` branch to `main` for <https://github.com/rustsec/advisory-db>

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
- Updated `cfg-expr`, which should allow for filtering of crates for _most_ custom targets that aren't built-in to rustc.

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
[Unreleased]: https://github.com/EmbarkStudios/cargo-deny/compare/0.14.4...HEAD
[0.14.4]: https://github.com/EmbarkStudios/cargo-deny/compare/0.14.3...0.14.4
[0.14.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.14.2...0.14.3
[0.14.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.14.1...0.14.2
[0.14.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.14.0...0.14.1
[0.14.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.9...0.14.0
[0.13.9]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.8...0.13.9
[0.13.8]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.7...0.13.8
[0.13.7]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.6...0.13.7
[0.13.6]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.5...0.13.6
[0.13.5]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.4...0.13.5
[0.13.4]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.3...0.13.4
[0.13.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.2...0.13.3
[0.13.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.1...0.13.2
[0.13.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.13.0...0.13.1
[0.13.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.12.2...0.13.0
[0.12.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.12.1...0.12.2
[0.12.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.12.0...0.12.1
[0.12.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.11.4...0.12.0
[0.11.4]: https://github.com/EmbarkStudios/cargo-deny/compare/0.11.3...0.11.4
[0.11.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.11.2...0.11.3
[0.11.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.11.1...0.11.2
[0.11.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.11.0...0.11.1
[0.11.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.10.3...0.11.0
[0.10.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.10.2...0.10.3
[0.10.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.10.1...0.10.2
[0.10.1]: https://github.com/EmbarkStudios/cargo-deny/compare/0.10.0...0.10.1
[0.10.0]: https://github.com/EmbarkStudios/cargo-deny/compare/0.9.1...0.10.0
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
[0.2.3]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.2...0.2.3
[0.2.2]: https://github.com/EmbarkStudios/cargo-deny/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.2.1
