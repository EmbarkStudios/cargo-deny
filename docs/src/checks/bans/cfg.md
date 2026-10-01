# The `[bans]` section

Contains all of the configuration for `cargo deny check bans`

## Example Config

```toml
{{#include ../../../../tests/cfg/bans.toml}}
```

### `multiple-versions`

Determines what happens when multiple versions of the same crate are encountered.

- `deny` - Will emit an error for each crate with duplicates and fail the check.
- `warn` (default) - Prints a warning for each crate with duplicates, but does not fail the check.
- `allow` - Ignores duplicate versions of the same crate.

### `multiple-versions-include-dev`

If `true`, `dev-dependencies` are included when checking for multiple versions of crates. By default this is false, and any crates that are only reached via dev dependency edges are ignored when checking for multiple versions. Note that this also means that `skip` and `skip` tree are not used, which may lead to warnings about unused configuration.

### `wildcards`

Determines what happens when a dependency is specified with the `*` (wildcard) version.

- `deny` - Will emit an error for each crate specified with a wildcard version.
- `warn` (default) - Prints a warning for each crate with a wildcard version, but does not fail the check.
- `allow` - Ignores all wildcard version specifications.

### `allow-wildcard-paths`

If specified, alters how the `wildcard` field behaves:

- [path](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies) or [git](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories) `dependencies` in **private** crates will no longer emit a warning or error.
- path or git `dev-dependencies` in both public and private crates will no longer emit a warning or error.
- path or git `dependencies` and `build-dependencies` in **public** crates will continue to produce warnings and errors.

Being limited to private crates is due to crates.io not allowing packages to be published with `path` or `git` dependencies except for `dev-dependencies`.

### `workspace-dependencies`

Used to configure how [`[workspace.dependencies]`](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-dependencies-table) are treated.

```toml
[bans.workspace-dependencies]
duplicates = 'deny'
include-path-dependencies = true
unused = 'deny'
```

#### `duplicates`

Determines what happens when more than 1 direct workspace dependency is resolved to the same crate and 1 or more declarations do not use `workspace = true`

- `deny` (default) - Will emit an error for each dependency declaration that does not use `workspace = true`
- `warn` - Will emit a warning for each dependency declaration that does not use `workspace = true`, but does not fail the check.
- `allow` - Ignores checking for `workspace = true` for dependencies in workspace crates

#### `include-path-dependencies`

If `true`, path dependencies will be included in the duplication check, otherwise they are completely ignored.

#### `unused`

Determines what happens when a dependency in [`[workspace.dependencies]`](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-dependencies-table) is not used in the workspace.

- `deny` (default) - Will emit an error for each dependency that is not actually used in the workspace.
- `warn` - Will emit a warning for each dependency that is not actually used in the workspace, but does not fail the check.
- `allow` - Ignores checking for unused workspace dependencies.

### `highlight`

When multiple versions of the same crate are encountered and `multiple-versions` is set to `warn` or `deny`, using the `-g <dir>` option will print out a [dotgraph](https://www.graphviz.org/) of each of the versions and how they were included into the graph. This field determines how the graph is colored to help you quickly spot good candidates for removal or updating.

- `lowest-version` - Highlights the path to the lowest duplicate version. Highlighted in ![red](https://placehold.it/15/ff0000/000000?text=+)
- `simplest-path` - Highlights the path to the duplicate version with the fewest number of total edges to the root of the graph, which will often be the best candidate for removal and/or upgrading. Highlighted in ![blue](https://placehold.it/15/0000FF/000000?text=+).
- `all` - Highlights both the `lowest-version` and `simplest-path`. If they are the same, they are only highlighted in ![red](https://placehold.it/15/ff0000/000000?text=+).

![Imgur](https://i.imgur.com/xtarzeU.png)

### `deny`

```toml
deny = ["package-spec"]
```

Determines specific crates that are denied. Each entry uses the same [PackageSpec](../cfg.md#package-specs) as other parts of cargo-deny's configuration.

#### `wrappers`

```toml
deny = [{ crate = "crate-you-don't-want:<=0.7.0", wrappers = ["this-can-use-it"] }]
```

This field allows specific crates to have a direct dependency on the banned crate but denies all transitive dependencies on it.

#### `deny-multiple-versions`

```toml
multiple-versions = 'allow'
deny = [{ crate = "crate-you-want-only-one-version-of", deny-multiple-versions = true }]
```

This field allows specific crates to deny multiple versions of themselves, but allowing or warning on multiple versions for all other crates. This field cannot be set simultaneously with `wrappers`.

#### `deny.reason`

```toml
deny = [{ crate = "package-spec", reason = "the reason this crate is banned"}]
```

This field provides the reason the crate is banned as a string (eg. a simple message or even a url) that is surfaced in diagnostic output so that the user does not have to waste time digging through history or asking maintainers why this is the case.

#### `deny.use-instead`

```toml
deny = [{ crate = "openssl", use-instead = "rustls"}]
```

This is a shorthand for the most common case for banning a particular crate, which is that your project has chosen to use a different crate for that functionality.

### `allow`

```toml
allow = ["package-spec"]
```

Determines specific crates that are allowed. If the `allow` list has one or more entries, then any crate not in that list will be denied, so use with care. Each entry uses the same [PackageSpec](../cfg.md#package-specs) as other parts of cargo-deny's configuration.

### `allow-workspace`

```toml
allow-workspace = false
```

If `true`, automatically allows all workspace members even when using a deny-by-default policy (i.e., when `deny = [{ name = "*" }]` is specified). This is useful for organizations that want to implement strict dependency allowlists for external crates while automatically allowing their own workspace crates without having to explicitly list them in the `allow` configuration.

When `allow-workspace = true`:

- All workspace members are automatically treated as if they were in the `allow` list
- Workspace members take precedence over explicit `deny` entries
- External dependencies still require explicit allowlisting
- Works for both single-crate and multi-crate workspaces

**Default**: `false`

#### `allow.reason`

```toml
allow = [{ crate = "package-spec", reason = "the reason this crate is allowed"}]
```

This field provides the reason the crate is allowed as a string (eg. a simple message or even a url) that is surfaced in diagnostic output so that the user does not have to waste time digging through history or asking maintainers why this is the case.

### `external-default-features`

Determines the lint level used for when the `default` feature is enabled on a crate not in the workspace. This lint level will can then be overridden on a per-crate basis if desired.

For example, if `an-external-crate` had the `default` feature enabled it could be explicitly allowed.

```toml
[bans]
external-default-features = "deny"

[[bans.features]]
crate = "an-external-crate"
allow = ["default"]
```

### `workspace-default-features`

The workspace version of `external-default-features`.

```toml
[bans]
external-default-features = "allow"

[[bans.features]]
crate = "a-workspace-crate"
deny = ["default"]
```

### `features`

```toml
[[bans.features]]
crate = "featured-krate:1.0"
deny = ["bad-feature"]
allow = ["good-feature"]
exact = true
```

Allows specification of crate specific allow/deny lists of features. Each entry uses the same [PackageSpec](../cfg.md#package-specs) as other parts of cargo-deny's configuration.

#### `features.deny`

Denies specific features for the crate.

#### `features.allow`

Allows specific features for the crate, enabled features not in this list are denied.

#### `features.exact`

If specified, requires that the features in `allow` exactly match the features enabled on the crate, and will fail if features are allowed that are not enabled.

### `skip`

```toml
skip = [
    "package-spec",
    { crate = "package-spec", reason = "an old version is used by crate-x, see <PR link> for updating it" },
]
```

When denying duplicate versions, it's often the case that there is a window of time where you must wait for, for example, PRs to be accepted and new version published, before 1 or more duplicates are gone. The `skip` field allows you to temporarily ignore a crate during duplicate detection so that no errors are emitted, until it is no longer need.

It is recommended to use specific version constraints for crates in the `skip` list, as cargo-deny will emit warnings when any entry in the `skip` list no longer matches a crate in your graph so that you can cleanup your configuration.

Each entry uses the same [PackageSpec](../cfg.md#package-specs) as other parts of cargo-deny's configuration.

### `skip-tree`

```toml
skip-tree = [
    "windows-sys<=0.52", # will skip this crate and _all_ direct and transitive dependencies
    { crate = "windows-sys<=0.52", reason = "several crates use the outdated 0.42 and 0.45 versions" },
    { crate = "windows-sys<=0.52", depth = 3, reason = "several crates use the outdated 0.42 and 0.45 versions" },
]
```

When dealing with duplicate versions, it's often the case that a particular crate acts as a nexus point for a cascade effect, by either using bleeding edge versions of certain crates while in alpha or beta, or on the opposite end of the spectrum, a crate is using severely outdated dependencies while much of the rest of the ecosystem has moved to more recent versions. In both cases, it can be quite tedious to explicitly `skip` each transitive dependency pulled in by that crate that clashes with your other dependencies, which is where `skip-tree` comes in.

`skip-tree` entries are similar to `skip` in that they are used to specify a crate name and version range that will be skipped, but they also have an additional `depth` field used to specify how many levels from the crate will also be skipped. A depth of `0` would be the same as specifying the crate in the `skip` field.

Note that by default, the `depth` is infinite.

Each entry uses the same [PackageSpec](../cfg.md#package-specs) as other parts of cargo-deny's configuration.

**NOTE:** `skip-tree` is a very big hammer, and should be used with care.

### `std-replacements`

The `std-replacements` field configures if and how crates.io-sourced crates are checked against [`std-replacement-data`] which contains information on crates that have been either partially or fully implemented in `std` or `core`.

By default if this field is not present, the check is completely skipped.

#### `std-replacements.scope`

The scope for what crates are considered. The scope filters the crates which depend upon a crate listed in the [`std-replacement-data`], not the crate itself.

- `workspace` (default) - Only crates depended upon by 1 or more crates in your workspace are considered.
- `all` - All crates in the data are considered if present in your graph.
- `transitive` - Only crates depended upon by crates outside your workspace are considered.
- `none` - No crates are considered, this is another way to disable the check.

#### `std-replacements.ignore-rust-version`

The scope for when the `rust-version` for a crate is ignored. By default this is `none`, and the `rust-version` is respected, meaning crates that depend on a crate in [`std-replacement-data`] only trigger the lint if at least one of them declares a `rust-version` that is >= to at least one version that the std replacement API was stabilized.

- `none` (default) - The `rust-version` is always taken into account
- `workspace` - The `rust-version` is ignored for crates that are depended upon by a workspace member
- `all` - The `rust-version` is never taken into account
- `transitive` - The `rust-version` is ignored for crates that are depended upon by crates not in the workspace

#### `std-replacements.rust-version`

The `rust-version` to use for crate's which do not specify their own. If not specified the version(s) in the [`std-replacement-data`] are not considered. This does not have to conform to semver and can be a simple `<major>.<minor>`. Note that Rust rarely/never adds functionality in patch releases, and there is only 1 major version, so only the minor version is considered during matching.

#### `std-replacements.ignore`

Ignores crates that would otherwise cause the lint to trigger, via a [PackageSpec](../cfg.md#package-specs).

#### `std-replacements.level`

The lint level for the diagnostic emitted when a crate is in the [`std-replacement-data`] and satisfies all the required conditions.

- `deny` (default)
- `warn`
- `allow`

### `build`

The `build` field contains configuration for raising diagnostics for crates that execute at compile time, either because they have a [build script](https://doc.rust-lang.org/cargo/reference/build-scripts.html), or they are a [procedural macro](https://doc.rust-lang.org/reference/procedural-macros.html). The configuration is (currently) focused on diagnostics around specific file types, as configured via extension glob patterns, as well as executables, either native or in the form of [interpreted shebang scripts](<https://en.wikipedia.org/wiki/Shebang_(Unix)>).

While the intention of this configuration is to raise awareness of crates that have or use precompiled binaries or scripts, or otherwise contain file types that you want to be aware of, the compile time crate linting supplied by cargo-deny does **NOT** protect you from actively malicious code.

A quick run down of things that cargo-deny **WILL NOT DETECT**.

- The crate just straight up does bad things like uploading your SSH keys to a remote server using vanilla rust code
- The crate contains compressed, or otherwise obfuscated executable binaries
- The build script uses `include!()` for code that is benign in one version, then replaces it with something malicious without triggering a checksum mismatch on the build script contents itself.
- A build time dependency of a non-malicious crate does any of the above.
- Tons of other stuff I haven't thought of because I am not a security person

So all this is to say, `cargo-deny` (currently) is only really useful for analyzing when crates have native executables, and/or the crate maintainers have either forgotten or purposefully left helper scripts for their CI/release management/etc in the crate source that are not actually ever executed automatically.

#### `allow-build-scripts`

Specifies all the crates that are allowed to have a build script. If this option is omitted, all crates are allowed to have a build script, and if this option is set to an empty list, no crate is allowed to have a build script.

#### `executables`

This controls how native executables are handled. Note this check is done by actually reading the file headers from disk so that this check works on Windows as well, ie the executable bit is irrelevant.

- `deny` (default) - Emits an error when native executables are detected.
- `warn` - Prints a warning when native executables are detected, but does not fail the check.
- `allow` - Prints a note when native executables are detected, but does not fail the check.

This check currently only handles the major executable formats.

- [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [PE](https://en.wikipedia.org/wiki/Portable_Executable)
- [Mach-O](https://en.wikipedia.org/wiki/Mach-O)

#### `interpreted`

This controls how interpreted scripts are handled. Note this check is done by actually reading the file header from disk so that this check works on Windows as well, ie the executable bit is irrelevant.

- `deny` - Emits an error when interpreted scripts are detected.
- `warn` - Prints a warning when interpreted scripts are detected, but does not fail the check.
- `allow` (default) - Prints a note when interpreted scripts are detected, but does not fail the check.

#### `script-extensions`

If supplied scans crates that execute at compile time for any files with the specified extension(s), emitting an error for every one that matches.

#### `enable-builtin-globs`

If `true`, enables the builtin glob patterns for common languages that tend to be installed on most developer machines, such as python.

```toml
{{#include ../../../../src/bans/builtin_globs.toml}}
```

#### `include-dependencies`

By default, only the crate that executes at compile time is scanned, but if set to `true`, this field will check this crate as well as all of its dependencies. This option is disabled by default, as this will tend to only find CI scripts that people leave in their published crates.

#### `include-workspace`

If `true`, workspace crates will also be scanned. This defaults to false as you presumably have some degree of trust for your own code.

#### `include-archives`

If `true`, archive files (eg. Windows .lib, Unix .a, C++ .o object files etc) are also counted as native code. This defaults to false, as these tend to need to be linked before they can be executed.

#### `bypass`

While all the previous configuration is about configuration the global checks that run on compile time crates, the `allow` field is how one can suppress those lints on a crate-by-crate basis.

Each entry uses the same [PackageSpec](../cfg.md#package-specs) as other parts of cargo-deny's configuration.

```toml
[build.bypass]
crate = "crate-name"
```

##### `build-script` and `required-features`

If set to a valid, 64-character hexadecimal [SHA-256](https://en.wikipedia.org/wiki/SHA-2), the `build-script` field will cause the rest of the scanning to be bypassed _if_ the crate's build script's checksum matches the user specified checksum **AND** none of the features specified in the `required-features` field are enabled. If the checksum does not match, the calculated checksum will be emitted as a warning, and the crate will be scanned as if a checksum was not supplied.

**NOTE:** These options only applies to crates with build scripts, not proc macros, as proc macros do not have a single entry point that can be easily checksummed.

```toml
[[build.bypass]]
name = "crate-name"
build-script = "5392f0e58ad06e089462d93304dfe82337acbbefb87a0749a7dc2ed32af04af7"
```

##### `allow-globs`

Bypasses scanning of files that match one or more of the glob patterns specified. Note that unlike the [`script-extensions`](#the-script-extensions-field-optional) field that applies to all crates, these globs can match anything, not just extensions.

```toml
[build]
script-extensions = ["cs"]

[[build.bypass]]
crate = "crate-name"
allow-globs = [
    "scripts/*.cs",
]
```

##### `bypass.allow`

Bypasses scanning a single file.

```toml
[build]
executables = "deny"

[[build.bypass]]
crate = "crate-name"
allow = [
    { path = "bin/x86_64-linux", checksum = "5392f0e58ad06e089462d93304dfe82337acbbefb87a0749a7dc2ed32af04af7" }
]
```

###### `path`

The path, relative to the crate root, of the file to bypass scanning.

###### `checksum`

The 64-character hexadecimal [SHA-256](https://en.wikipedia.org/wiki/SHA-2) checksum of the file. If the checksum does not match, an error is emitted.

[`std-replacement-data`]: https://github.com/rust-lang/std-replacement-data
