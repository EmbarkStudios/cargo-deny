# Bans diagnostics

<!-- markdownlint-disable-next-line heading-increment -->

### `banned`

A crate which is [explicitly banned](cfg.md#deny) was detected.

### `allowed`

A crate which is [explicitly allowed](cfg.md#allow) was detected.

### `not-allowed`

When using [`bans.allow`](cfg.md#allow), a crate was detected that wasn't in that list.

### `duplicate`

More than one [version](cfg.md#multiple-versions) of the same crate were detected.

### `skipped`

A crate version that matched an entry in [`bans.skip`](cfg.md#skip) was encountered.

### `wildcard`

A crate was included via a [wildcard dependency](cfg.md#wildcards) by one or more crates.

### `workspace-duplicate`

A direct workspace dependency was referred to more than once and all declarations did not use [`workspace = true`](cfg.md#workspace-duplicates)

### `unresolved-workspace-dependency`

We were unable to determine the exact crate a workspace dependency (or patch) was resolved to. This most likely indicates a bug in cargo-deny.

### `unused-workspace-dependency`

A [`[workspace.dependencies]`](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-dependencies-table) was declared, but not actually used anywhere in the workspace.

### `unmatched-skip`

A crate version in [`bans.skip`](cfg.md#skip) was not encountered.

### `unmatched-skip-root`

A crate version in [`bans.skip-tree`](cfg.md#skip-tree) was not encountered.

### `unnecessary-skip`

A crate specified in [`bans.skip`](cfg.md#skip) was in the graph, but that crate only had one version, making the `skip` entry useless.

### `allowed-by-wrapper`

A crate in `bans.deny` was allowed since it was directly depended on by a [`wrappers`](cfg.md#wrappers) crate.

### `unmatched-wrapper`

A crate in `bans.deny` had one or more [`wrappers`](cfg.md#wrappers) crates, but a crate not in that list had a direct dependency on the banned crate.

### `unused-wrapper`

A crate in `bans.deny` used a [`wrapper`](cfg.md#wrappers) that was not matched.

### `skipped-by-root`

A crate was skipped from being checked as a duplicate due to being transitively referenced by a crate version in [`bans.skip-tree`](cfg.md#skip-tree).

### `unmatched-root`

A crate version in [`bans.skip-tree`](cfg.md#skip-tree) was not encountered.

### `build-script-not-allowed`

A crate which has been denied because it has a build script but is not part of the [`bans.allow-build-script`](cfg.md#allow-build-scripts) list.

### `exact-features-mismatch`

A crate's features do not exactly match the configured feature set, and [`bans.features.exact`](cfg.md#featuresexact) is `true`.

### `feature-not-explicitly-allowed`

A crate's features used a feature not in the [`bans.features.allow`](cfg.md#featuresallow) set.

### `feature-banned`

An enabled crate feature is present in the [`bans.features.deny`](cfg.md#features-deny) list.

### `unknown-feature`

A feature in either [`bans.features.deny`](cfg.md#features-deny) or [`bans.features.allow`](cfg.md#features-allow) does not exist for the crate.

### `default-feature-enabled`

The `default` feature was enabled on a crate, and the [`bans.external-default-features`](cfg.md#external-default-features) or [`bans.workspace-default-features`](cfg.md#workspace-default-features) was configured.

### `path-bypassed`

A path specified by [`bans.build.bypass.allow.path`](cfg.md#path) was bypassed, optionally ensuring its contents matched a SHA-256 checksum.

### `path-bypassed-by-glob`

A path was bypassed due to matching one or more [glob patterns](cfg.md#allow-globs).

### `checksum-match`

The SHA-256 checksum calculated for the contents of a file matched the checksum in the configuration.

### `checksum-mismatch`

The SHA-256 checksum calculated for the contents of a file did not match the checksum in the configuration.

### `denied-by-extension`

The file extension matched either a [user specified](cfg.md#script-extensions) or [builtin](cfg.md#enable-builtin-globs) extension.

### `detected-executable`

A [native executable](cfg.md#executables) was detected.

### `detected-executable-script`

An [interpreted script](cfg.md#interpreted) was detected.

### `unable-to-check-path`

An I/O error occurred when opening or reading a file from disk.

### `features-enabled`

One or more [`required-features`](cfg.md#build-script-and-required-features) were enabled, causing the [`build-script`](cfg.md#build-script-and-required-features) bypass to be ignored.

### `unmatched-bypass`

A [crate bypass](cfg.md#bypass) did not match any crate in the graph.

### `unmatched-path-bypass`

A [path bypass](cfg.md#bypassallow) did not match a file in the crate.

### `unmatched-glob`

A [glob bypass](cfg.md#allow-globs) did not match any files in the crate.

### `unmatched-allow-build-script`

A [allow-build-scripts](cfg.md#allow-build-scripts) specified a crate not found in the graph.

### `allowed-crate-without-build-script`

A [allow-build-scripts](cfg.md#allow-build-scripts) specified a crate that does not have a build script.

### `non-root-path`

A path in the package's source was not rooted in the package source.

### `non-utf8-path`

A non-utf8 path was encountered in the package source.
