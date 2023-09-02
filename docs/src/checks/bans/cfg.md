# The `[bans]` section

Contains all of the configuration for `cargo deny check bans`

## Example Config

```ini
{{#include ../../../../tests/cfg/bans.toml}}
```

### The `multiple-versions` field (optional)

Determines what happens when multiple versions of the same crate are encountered.

* `deny` - Will emit an error for each crate with duplicates and fail the check.
* `warn` (default) - Prints a warning for each crate with duplicates, but does not fail the check.
* `allow` - Ignores duplicate versions of the same crate.

### The `wildcards` field (optional)

Determines what happens when a dependency is specified with the `*` (wildcard) version.

* `deny` - Will emit an error for each crate specified with a wildcard version.
* `warn` (default) - Prints a warning for each crate with a wildcard version, but does not fail the check.
* `allow` - Ignores all wildcard version specifications.

### The `allow-wildcard-paths` field (optional)

If specified, alters how the `wildcard` field behaves:

* [path](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies) `dependencies` in **private** crates will no longer emit a warning or error.
* path `dev-dependencies` in both public and private crates will no longer emit a warning or error.
* path `dependencies` and `build-dependencies` in **public** crates will continue to produce warnings and errors.

Being limited to private crates is due to crates.io not allowing packages to be published with `path` dependencies except for `dev-dependencies`.

### The `highlight` field (optional)

When multiple versions of the same crate are encountered and `multiple-versions` is set to `warn` or `deny`, using the `-g <dir>` option will print out a [dotgraph](https://www.graphviz.org/) of each of the versions and how they were included into the graph. This field determines how the graph is colored to help you quickly spot good candidates for removal or updating.

* `lowest-version` - Highlights the path to the lowest duplicate version. Highlighted in ![red](https://placehold.it/15/ff0000/000000?text=+)
* `simplest-path` - Highlights the path to the duplicate version with the fewest number of total edges to the root of the graph, which will often be the best candidate for removal and/or upgrading. Highlighted in ![blue](https://placehold.it/15/0000FF/000000?text=+).
* `all` - Highlights both the `lowest-version` and `simplest-path`. If they are the same, they are only highlighted in ![red](https://placehold.it/15/ff0000/000000?text=+).

![Imgur](https://i.imgur.com/xtarzeU.png)

### Crate specifier

The `allow`, `deny`, `features`, `skip`, `skip-tree`, and `build.allow` fields all use a crate identifier to specify what crate(s) they want to match against.

```ini
{ name = "some-crate-name-here", version = "<= 0.7.0" }
```

#### The `name` field

The name of the crate.

#### The `version` field (optional)

An optional version constraint specifying the range of crate versions that will match. Defaults to any version.

### The `deny` field (optional)

```ini
deny = [{ name = "crate-you-don't-want", version = "<= 0.7.0" }]
```

Determines specific crates that are denied.

#### The `wrappers` field (optional)

```ini
deny = [{ name = "crate-you-don't-want", version = "<= 0.7.0", wrappers = ["this-can-use-it"] }]
```

This field allows specific crates to have a direct dependency on the banned crate but denies all transitive dependencies on it.

#### The `deny-multiple-versions` field (optional)

```ini
multiple-versions = 'allow'
deny = [{ name = "crate-you-want-only-one-version-of", deny-multiple-versions = true }]
```

This field allows specific crates to deny multiple versions of themselves, but allowing or warning on multiple versions for all other crates. This field cannot be set simultaneously with `wrappers`.

### The `allow` field (optional)

Determines specific crates that are allowed. If the `allow` list has one or more entries, then any crate not in that list will be denied, so use with care.

### The `external-default-features` field (optional)

Determines the lint level used for when the `default` feature is enabled on a crate not in the workspace. This lint level will can then be overridden on a per-crate basis if desired.

For example, if `an-external-crate` had the `default` feature enabled it could be explicitly allowed.

```ini
[bans]
external-default-features = "deny"

[[bans.features]]
name = "an-external-crate"
allow = ["default"]
```

### The `workspace-default-features` field (optional)

The workspace version of `external-default-features`.

```ini
[bans]
external-default-features = "allow"

[[bans.features]]
name = "a-workspace-crate"
deny = ["default"]
```

### The `features` field (optional)

```ini
[[bans.features]]
name = "featured-krate"
version = "1.0"
deny = ["bad-feature"]
allow = ["good-feature"]
exact = true
```

Allows specification of crate specific allow/deny lists of features.

#### The `features.deny` field (optional)

Denies specific features for the crate.

#### The `features.allow` field (optional)

Allows specific features for the crate, enabled features not in this list are denied.

#### The `features.exact` field (optional)

If specified, requires that the features in `allow` exactly match the features enabled on the crate, and will fail if features are allowed that are not enabled.

### The `skip` field (optional)

When denying duplicate versions, it's often the case that there is a window of time where you must wait for, for example, PRs to be accepted and new version published, before 1 or more duplicates are gone. The `skip` field allows you to temporarily ignore a crate during duplicate detection so that no errors are emitted, until it is no longer need.

It is recommended to use specific version constraints for crates in the `skip` list, as cargo-deny will emit warnings when any entry in the `skip` list no longer matches a crate in your graph so that you can cleanup your configuration.

### The `skip-tree` field (optional)

When dealing with duplicate versions, it's often the case that a particular crate acts as a nexus point for a cascade effect, by either using bleeding edge versions of certain crates while in alpha or beta, or on the opposite end of the spectrum, a crate is using severely outdated dependencies while much of the rest of the ecosystem has moved to more recent versions. In both cases, it can be quite tedious to explicitly `skip` each transitive dependency pulled in by that crate that clashes with your other dependencies, which is where `skip-tree` comes in.

`skip-tree` entries are similar to `skip` in that they are used to specify a crate name and version range that will be skipped, but they also have an additional `depth` field used to specify how many levels from the crate will also be skipped. A depth of `0` would be the same as specifying the crate in the `skip` field.

Note that by default, the `depth` is infinite.

**NOTE:** `skip-tree` is a very big hammer at the moment, and should be used with care.

### The `build` field (optional)

The `build` field contains configuration for raising diagnostics for crates that execute at compile time, either because they have a [build script](https://doc.rust-lang.org/cargo/reference/build-scripts.html), or they are a [procedural macro](https://doc.rust-lang.org/reference/procedural-macros.html). The configuration is (currently) focused on diagnostics around specific file types, as configured via extension glob patterns, as well as executables, either native or in the form of [interpreted shebang scripts](https://en.wikipedia.org/wiki/Shebang_(Unix)).

While the intention of this configuration is to raise awareness of crates that have or use precompiled binaries or scripts, or otherwise contain file types that you want to be aware of, the compile time crate linting supplied by cargo-deny does **NOT** protect you from actively malicious code.

A quick run down of things that cargo-deny **WILL NOT DETECT**.

* The crate just straight up does bad things like uploading your SSH keys to a remote server using vanilla rust code
* The crate contains compressed, or otherwise obfuscated executable binaries
* The build script uses `include!()` for code that is benign in one version, then replaces it with something malicious without triggering a checksum mismatch on the build script contents itself.
* A build time dependency of a non-malicious crate does any of the above.
* Tons of other stuff I haven't thought of because I am not a security person

So all this is to say, `cargo-deny` (currently) is only really useful for analyzing when crates have native executables, and/or the crate maintainers have either forgotten or purposefully left helper scripts for their CI/release management/etc in the crate source that are not actually ever executed automatically.

#### The `allow-build-scripts` field (optional)

Specifies all the crates that are allowed to have a build script. If this option is omitted, all crates are allowed to have a build script, and if this option is set to an empty list, no crate is allowed to have a build script.

#### The `executables` field (optional)

This controls how native executables are handled. Note this check is done by actually reading the file headers from disk so that this check works on Windows as well, ie the executable bit is irrelevant.

* `deny` (default) - Emits an error when native executables are detected.
* `warn` - Prints a warning when native executables are detected, but does not fail the check.
* `allow` - Prints a note when native executables are detected, but does not fail the check.

This check currently only handles the major executable formats.

* [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
* [PE](https://en.wikipedia.org/wiki/Portable_Executable)
* [Mach-O](https://en.wikipedia.org/wiki/Mach-O)

#### The `interpreted` field (optional)

This controls how interpreted scripts are handled. Note this check is done by actually reading the file header from disk so that this check works on Windows as well, ie the executable bit is irrelevant.

* `deny` - Emits an error when interpreted scripts are detected.
* `warn` - Prints a warning when interpreted scripts are detected, but does not fail the check.
* `allow` (default) - Prints a note when interpreted scripts are detected, but does not fail the check.

#### The `script-extensions` field (optional)

If supplied scans crates that execute at compile time for any files with the specified extension(s), emitting an error for every one that matches.

#### The `enable-builtin-globs` field (optional)

If `true`, enables the builtin glob patterns for common languages that tend to by installed on most developer machines, such as python.

```ini
{{#include ../../../../src/bans/builtin_globs.toml}}
```

#### The `include-dependencies` field (optional)

By default, only the crate that executes at compile time is scanned, but if set to `true`, this field will check this crate as well as all of its dependencies. This option is disabled by default, as this will tend to only find CI scripts that people leave in their published crates.

#### The `include-workspace` field (optional)

If `true`, workspace crates will also be scanned. This defaults to false as you presumably have some degree of trust for your own code.

#### The `include-archives` field (optional)

If `true`, archive files (eg. Windows .lib, Unix .a, C++ .o object files etc) are also counted as native code. This defaults to false, as these tend to need to be linked before they can be executed.

#### The `bypass` field (optional)

While all the previous configuration is about configuration the global checks that run on compile time crates, the `allow` field is how one can suppress those lints on a crate-by-crate basis.

Each entry uses the same [Crate specifier](#crate-specifier) as other parts of cargo-deny's configuration.

```ini
[build.bypass]
name = "crate-name"
```

##### The `build-script` and `required-features` field (optional)

If set to a valid, 64-character hexadecimal [SHA-256](https://en.wikipedia.org/wiki/SHA-2), the `build-script` field will cause the rest of the scanning to be bypassed _if_ the crate's build script's checksum matches the user specified checksum **AND** none of the features specified in the `required-features` field are enabled. If the checksum does not match, the calculated checksum will be emitted as a warning, and the crate will be scanned as if a checksum was not supplied.

**NOTE:** These options only applies to crate with build scripts, not proc macros, as proc macros do not have a single entry point that can be easily checksummed.

```ini
[[build.bypass]]
name = "crate-name"
build-script = "5392f0e58ad06e089462d93304dfe82337acbbefb87a0749a7dc2ed32af04af7"
```

##### The `allow-globs` field (optional)

Bypasses scanning of files that match one or more of the glob patterns specified. Note that unlike the [`script-extensions`](#the-script-extensions-field-optional) field that applies to all crates, these globs can match anything, not just extensions.

```ini
[build]
script-extensions = ["cs"]

[[build.bypass]]
name = "crate-name"
allow-globs = [
    "scripts/*.cs",
]
```

##### The `bypass.allow` field (optional)

Bypasses scanning a single file.

```ini
[build]
executables = "deny"

[[build.bypass]]
name = "crate-name"
allow = [
    { path = "bin/x86_64-linux", checksum = "5392f0e58ad06e089462d93304dfe82337acbbefb87a0749a7dc2ed32af04af7" }
]
```

###### The `path` field

The path, relative to the crate root, of the file to bypass scanning.

###### The `checksum` field (optional)

The 64-character hexadecimal [SHA-256](https://en.wikipedia.org/wiki/SHA-2) checksum of the file. If the checksum does not match, an error is emitted.

[](
