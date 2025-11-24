# The `[licenses]` section

Contains all of the configuration for `cargo deny check license`.

## Example

```ini
{{#include ../../../../tests/cfg/licenses.toml}}
```

## SPDX Identifiers

All identifiers used in the license configuration section are expected to be valid SPDX v2.1 short identifiers, either from version 3.11 of the [SPDX License List](https://spdx.org/licenses/), or use a [custom identifier](https://spdx.github.io/spdx-spec/appendix-V-using-SPDX-short-identifiers-in-source-files/#format-for-spdx-license-identifier) by prefixing it with `LicenseRef-`.

```ini
allow = [
    # The Apache license identifier
    "Apache-2.0",
    # A custom license identifier
    "LicenseRef-Embark-Custom",
]

# Custom license refs can be specified for crates which don't use a license
# in the SPDX list
[[licenses.clarify]]
crate = "a-crate"
expression = "LicenseRef-Embark-Custom"
license-files = [
    { path = "LICENSE", hash = 0x001c7e6c },
]
```

License identifiers can also be coupled with an optional [exception](https://spdx.org/licenses/exceptions-index.html) by appending `WITH <exception-id>` to the license identifier. Licenses coupled with exceptions are considered distinct from the same license without the exception.

```ini
allow = [
    # The Apache license identifier
    "Apache-2.0",
    # The Apache license + LLVM-exception
    "Apache-2.0 WITH LLVM-exception",
]
```

### The `include-dev` field (optional)

If `true`, licenses are checked even for `dev-dependencies`. By default this is false as `dev-dependencies` are not used by downstream crates, nor part of binary artifacts.

### The `version` field (optional)

```ini
version = 2
```

The version field is (at the time of this writing) no longer used, the following fields have been removed and will now emit errors.

- `unlicensed` - Removed, if a crate is unlicensed you should open an issue/PR to fix it, and in the meantime, you may add a [clarification](#the-clarify-field-optional).
- `deny` - Removed, all licenses are denied unless explicitly allowed
- `copyleft` - Removed, all licenses are denied unless explicitly allowed
- `allow-osi-fsf-free` - Removed, all licenses are denied unless explicitly allowed
- `default` - Removed, all licenses are denied unless explicitly allowed

### The `allow` field (optional)

The licenses that are explicitly allowed. Licenses not in this list are denied by default, so if none of the licenses listed here can satisfy the license expression used by the project, the license check will fail.

#### Note on GNU licenses

- GPL
- AGPL
- LGPL
- GFDL

The GNU licenses are, of course, different from all the other licenses in the SPDX list which makes them annoying to deal with. In versions of cargo-deny <= 0.18.3 it would try to treat GNU licenses similarly to other licenses, attempting to follow the same rules as other licenses.

As of 0.18.4, GNU licenses are now treated pedantically. For example, if you want to allow `GPL-3.0` (deprecated), or `GPL-3.0-or-later` licenses, or `GPL-2.0-or-later`, but not `GPL-3.0-only`, you would need to do the following.

```ini
allow = ['GPL-2.0-or-later', 'GPL-3.0', 'GPL-3.0-or-later']
```

This also means that if a project declares their license as `GPL-2.0`, the deprecated form, you can't use `GPL-2.0-only`, it only matches `GPL-2.0`.

### The `exceptions` field (optional)

The license configuration generally applies to the entire crate graph, but this means that allowing any one license applies to all possible crates, even if only 1 crate actually uses that license. The `exceptions` field is meant to allow additional licenses only for particular crates, to make a clear distinction between licenses which you are fine with everywhere, versus ones which you want to be more selective about, and not have implicitly allowed in the future.

This field uses [PackageSpecs](../cfg.md#package-specs) to select the crate the exception applies to.

### Additional exceptions configuration file

In some cases it's useful to have global cargo-deny config and project-local exceptions. This can be accomplished with a project exceptions file in any of these locations relative to your top level `Cargo.toml` manifest file.

`cargo-deny` will look for the following files: `<cwd>/deny.exceptions.toml`, `<cwd>/.deny.exceptions.toml` and `<cwd>/.cargo/deny.exceptions.toml`

Only the exceptions field should be set:

```ini
exceptions = [
    # Each entry is the crate and version constraint, and its specific allow list.
    { allow = ["CDDL-1.0"], crate = "inferno" },
]
```

#### The `allow` field

This is the exact same as the general `allow` field.

```ini
[licenses]
allow = [
    "Apache-2.0",
    "MIT",
]
exceptions = [
    # This is the only crate that cannot be licensed with either Apache-2.0
    # or MIT, so we just add an exception for it, meaning we'll get a warning
    # if we add another crate that also requires this license
    { crate = "cloudabi", allow = ["BSD-2-Clause"] },
]
```

### The `confidence-threshold` field (optional)

`cargo-deny` uses [askalono](https://github.com/amzn/askalono) to determine the license of a LICENSE file. Due to variability in license texts because of things like authors, copyright year, and so forth, askalano assigns a confidence score to its determination, from `0.0` (no confidence) to `1.0` (perfect match). The confidence threshold value is used to reject the license determination if the score does not match or exceed the threshold.

`0.0` - `1.0` (default `0.8`)

### The `clarify` field (optional)

In some exceptional cases, a crate will not have easily machine readable license information, and would by default be considered "unlicensed" by cargo-deny. As a (hopefully) temporary patch for using the crate, you can specify a clarification for the crate by manually assigning its SPDX expression, based on one or more files in the crate's source. cargo-deny will use that expression for as long as the source files in the crate exactly match the clarification's hashes.

This field uses [PackageSpecs](../cfg.md#package-specs) to select the crate the clarification applies to.

```ini
[[licenses.clarify]]
crate = "webpki"
expression = "ISC"
license-files = [
    { path = "LICENSE", hash = 0x001c7e6c },
]
```

#### The `expression` field

The [SPDX license expression][SPDX-expr] you are specifying as the license requirements for the crate.

#### The `license-files` field

Contains one or more files that will be checked to ensure the license expression still applies to a version of the crate.

##### The `path` field

The crate relative path to a file to be used as a source of truth.

##### The `hash` field

An opaque hash calculated from the file contents. This hash can be obtained from the output of the license check when cargo-deny can't determine the license of the file in question.

### The `private` field (optional)

It's often not useful or wanted to check for licenses in your own private workspace crates. So the private field allows you to do so.

#### The `ignore` field

If `true`, workspace members will not have their license expression checked if they are not published.

```ini
# Cargo.toml
[package]
name = "sekret"
license = "¯\_(ツ)_/¯"
publish = false # "private"!
```

```ini
# deny.toml
[licenses]
# The sekret package would be ignored now
private = { ignore = true }
```

### The `registries` field

A list of private registries you may publish your workspace crates to. If a workspace member **only** publishes to private registries, it will also be ignored if `private.ignore = true`

```ini
# Cargo.toml
[package]
name = "sekret"
license = "¯\_(ツ)_/¯"
publish = ["sauce"]
```

```ini
# deny.toml
[licenses]
# Still ignored!
private = { ignore = true, registries = ["sauce"] }
```

### The `ignore-sources` field

A list of registries that crates can be sourced from that will not have their licenses checked.

```ini
# deny.toml
[licenses.private]
ignore = true
ignore-sources = ["https://sekretz.com/super/secret-index"]
```

[SPDX-expr]: https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/

### The `unused-allowed-license` field (optional)

Determines what happens when one of the licenses that appears in the [`allow`](#the-allow-field-optional) list is not encountered in the dependency graph.

- `warn` (default) - A warning is emitted for each license that appears in `license.allow` but which is not used in any crate.
- `allow` - Unused licenses in the `licenses.allow` list are ignored.
- `deny` - An unused license in the `licenses.allow` list triggers an error, and cause the license check to fail.

### The `unused-license-exception` field (optional)

Same as [`unused-allowed-license`](#the-unused-allowed-license-field-optional) but for [`exceptions`](#the-exceptions-field-optional).
