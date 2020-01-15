# ❌ cargo-deny

[![Build Status](https://github.com/EmbarkStudios/cargo-deny/workflows/CI/badge.svg)](https://github.com/EmbarkStudios/cargo-deny/actions?workflow=CI)
[![Latest version](https://img.shields.io/crates/v/cargo-deny.svg)](https://crates.io/crates/cargo-deny)
[![Docs](https://docs.rs/cargo-deny/badge.svg)](https://docs.rs/cargo-deny)
[![SPDX Version](https://img.shields.io/badge/SPDX%20Version-3.7-blue.svg)](https://shields.io/)
[![Contributor Covenant](https://img.shields.io/badge/contributor%20covenant-v1.4%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)
[![Embark](https://img.shields.io/badge/embark-open%20source-blueviolet.svg)](http://embark.dev)

`cargo-deny` is a cargo plugin for linting your dependencies


* [Licenses](#licenses---cargo-deny-check-licenses) - Configure which license terms you accept
* [Bans](#crate-bans---cargo-deny-check-bans) - Configure whether particular crates are allowed in your dependency graph
* [Advisories](#crate-advisories---cargo-deny-check-advisories) - Configure how security vulnerabilities and unmaintained crates are handled
* [Sources](#crate-sources---cargo-deny-check-sources) - Configure which crate registries and Git repositories are sources you trust

## Install

`cargo install cargo-deny`

## tl;dr

* `cargo deny check <licenses|all>` - check licenses for every crate
* `cargo deny check <bans|all>` - check crate graph for certain crates, and multiple version of the same crate
* `cargo deny check <advisories|all>` - check crate graph for security vulnerabilities and unmaintained crates
* `cargo deny check <sources|all>` - check that all crates are from allowed sources
* `cargo deny list` - list all of the licenses for all crates in a project

## Licenses - `cargo deny check licenses`

One important aspect that one must always keep in mind when using code from other people is what the licensing of that code is and whether it fits the requirements of your project. Luckily, most of the crates in the Rust ecosystem tend to follow the example set forth by Rust itself, namely dual-license `MIT OR Apache-2.0`, but of course, that is not always the case.

So `cargo-deny` allows you to ensure that all of your dependencies have license requirements that align with your configuration.

### Precedence

Currently, the precedence for determining whether a particular license is accepted or rejected is as follows:

1. A license specified in the `deny` list is **always rejected**.
1. A license specified in the `allow` list is **always accepted**.
1. If the license is considered [copyleft](https://en.wikipedia.org/wiki/Copyleft), the [`[license.copyleft]`](#the-copyleft-field) configuration determines its status
1. If the license is [OSI Approved](https://opensource.org/licenses) or [FSF Free/Libre](https://www.gnu.org/licenses/license-list.en.html), the [`[license.allow-osi-fsf-free]`](#the-allow-osi-fsf-free-field) configuration determines its status
1. If the license does not match any of the above criteria, it is implicitly **rejected**.

### The `[licenses]` section

Contains all of the configuration for `cargo deny check license`.

#### The `unlicensed` field (optional)

Determines what happens when a crate has not explicitly specified its license terms, and no license information could be easily detected via `LICENSE*` files in the crate's source.

* `deny` (default) - All unlicensed crates will emit an error and fail the license check
* `allow` - All unlicensed crates will show a note, but will not fail the license check
* `warn` - All unlicensed crates will show a warning, but will not fail the license check

#### The `allow` and `deny` fields (optional)

The licenses that should be allowed or denied. The license must be a valid SPDX v2.1 identifier, which must either be in version 3.7 of the [SPDX License List](https://spdx.org/licenses/), with an optional [exception](https://spdx.org/licenses/exceptions-index.html) specified by `WITH <exception-id>`, or else a user defined license reference denoted by `LicenseRef-<idstring>` for a license not on the SPDX License List.

**NOTE:** The same license cannot appear in both the `allow` and `deny` lists.

##### GNU licenses

* GPL
* AGPL
* LGPL
* GFDL

The GNU licenses are, of course, different from all the other licenses in the SPDX list which makes them annoying to deal with. When supplying one of the above licenses, to either `allow` or `deny`, you must not use the suffixes `-only` or `-or-later`, as they can only be used by the license holder themselves to decide under which terms to license their code.

So, for example, if you we wanted to disallow `GPL-2.0` licenses, but allow `GPL-3.0` licenses, we could use the following configuration.

```toml
[licenses]
allow = [ "GPL-3.0" ]
deny = [ "GPL-2.0" ]
```

#### The `exceptions` field (optional)

The license configuration generally applies the entire crate graph, but this means that, allowing a specific license applies to all possible crates, even if only 1 crate actually uses that license. The `exceptions` field is meant to allow licenses only for particular crates, so as to make a clear distinction between licenses are fine with everywhere, versus ones which you want to be more selective about, and not have implicitly allowed in the future.

##### The `name` field

The name of the crate that you are adding an exception for

##### The `version` field (optional)

An optional version constraint specifying the range of crate versions you are excepting. Defaults to all versions (`*`).

##### The `allow` field

This is the exact same as the general `allow` field.

```toml
[licenses]
allow = [
    "Apache-2.0",
    "MIT",
]
exceptions = [
    # This is the only crate that cannot be licensed with either Apache-2.0
    # or MIT, so we just add an exception for it, meaning we'll get a warning
    # if we add another crate that also requires this license
    { name = "cloudabi", allow = ["BSD-2-Clause"] },
]
```

#### The `copyleft` field (optional)

Determines what happens when a license that is considered [copyleft](https://en.wikipedia.org/wiki/Copyleft) is encountered.

* `warn` (default) - Will emit a warning that a copyleft license was detected, but will not fail the license check
* `deny` - The license is not accepted if it is copyleft, but might not fail the license check if part of an expression that containe
* `allow` - The license is accepted if it is copyleft

#### The `allow-osi-fsf-free` field (optional)

Determines what happens when licenses aren't explicitly allowed or denied, but are marked as [OSI Approved](https://opensource.org/licenses) or [FSF Free/Libre](https://www.gnu.org/licenses/license-list.en.html) in version 3.6 of the [SPDX License List](https://spdx.org/licenses/).

* `both` - The license is accepted if it is both OSI approved and FSF Free
* `either` - The license is accepted if it is either OSI approved or FSF Free
* `osi-only` - The license is accepted if it is OSI approved and not FSF Free
* `fsf-only` - The license is accepted if it is FSF Free and not OSI approved
* `neither` (default) - No special consideration is given the license

#### The `confidence-threshold` field (optional)

`cargo-deny` uses [askalono](https://github.com/amzn/askalono) to determine the license of a license file, the confidence threshold value determines if askalono's determination meets your minimum requirements. The higher the value, the more closely the license text must be to the canonical license text of a valid SPDX license file.

`0.0` - `1.0` (default `0.8`)

#### The `clarify` field (optional)

In some exceptional cases, the crate does not have easily machine readable license information, and would by default be considered "unlicensed" by `cargo-deny`. As a (hopefully) temporary patch for using the crate, you can specify a clarification for a crate where you can specify the license expression based on your understanding of the requirements as described by the license holder.

##### The `name` field

The name of the crate that you are clarifying

##### The `version` field (optional)

An optional version constraint specifying the range of crate versions you are clarifying. Defaults to all versions (`*`).

##### The `expression` field

The [SPDX license expression](https://spdx.org/spdx-specification-21-web-version#h.jxpfx0ykyb60) you are specifying as the license requirements for the crate in question.

##### The `license-files` field

Contains one or more files that will be checked to ensure the license expression still applies to a version of the crate. Each file is a `path` to the file relative to the crate route, and a `hash` of the contents to detect changes between versions. This hash is printed out when license files cannot have their license determined with high confidence.

### Example config

```toml
[licenses]
unlicensed = "deny"
allow-osi-fsf-free = "either"
copyleft = "ignore"
confidence-threshold = 0.92
deny = [
    "GPL-3.0-or-later",
]
allow = [
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-3-Clause",
    "MIT",
    "Zlib",
]

# ring has a rather complicated license file, and unfortunately does not
# provide an SPDX expression in the `license` toml
[[licenses.clarify]]
name = "ring"
# SPDX considers OpenSSL to encompass both the OpenSSL and SSLeay licenses
# https://spdx.org/licenses/OpenSSL.html
# ISC - Both BoringSSL and ring use this for their new files
# MIT - "Files in third_party/ have their own licenses, as described therein. The MIT
# license, for third_party/fiat, which, unlike other third_party directories, is
# compiled into non-test libraries, is included below."
# OpenSSL - Obviously
expression = "ISC AND MIT AND OpenSSL"
license-files = [
    { path = "LICENSE", hash = 0xbd0eed23 },
]
```

## Crate bans - `cargo deny check bans`

### Use Case - Keeping certain crates out of your dependency graph

Sometimes, certain crates just don't fit in your project, so you have to remove them. However, nothing really stops them from sneaking back in due to small changes, like updating a crate to a new version that happens to add it as a dependency, or an existing dependency just changing what crates are included in the default feature set.

For example, we previously depended on OpenSSL as it is the "default" for many crates that deal with HTTP traffic. This was extremely annoying as it required us to have OpenSSL development libraries installed on Windows, for both individuals and CI. We moved all of our dependencies to use the much more streamlined `native-tls` and `ring` crates instead, and now we can make sure that OpenSSL doesn't return from the grave by being pulled in as a default feature of some future HTTP crate we might use.

### Use Case - Get a handle on duplicate versions

One thing that is part of the tradeoff of being able to use so many crates, is that they all won't necessarily agree on what versions of a dependency they want to use, and cargo and rust will happily chug along compiling all of them.  This is great when just trying out a new dependency as quickly as possible, but it does come with some long term costs. Crate fetch times (and disk space) are increased, but in particular, **compile times**, and ultimately your binary sizes, also increase. If you are made aware that you depend on multiple versions of the same crate, you at least have an opportunity to decide how you want to handle them.

### The `[bans]` section

Contains all of the configuration for `cargo deny check ban`

#### The `multiple-versions` field (optional)

Determines what happens when multiple versions of the same crate are encountered.

* `deny` - Will emit an error for each crate with duplicates and fail the check.
* `warn` (default) - Prints a warning for each crate with duplicates, but does not fail the check.
* `allow` - Ignores duplicate versions of the same crate.

#### The `highlight` field (optional)

When multiple versions of the same crate are encountered and the `multiple-versions` is set to `warn` or `deny`, using the `-g <dir>` option will print out a [dotgraph](https://www.graphviz.org/) of each of the versions and how they were included into the graph. This field determines how the graph is colored to help you quickly spot good candidates for removal or updating.

* `lowest-version` - Highlights the path to the lowest duplicate version. Highlighted in ![red](https://placehold.it/15/ff0000/000000?text=+)
* `simplest-path` - Highlights the path to the duplicate version with the fewest number of total edges to the root of the graph, which will often be the best candidate for removal and/or upgrading. Highlighted in ![blue](https://placehold.it/15/0000FF/000000?text=+).
* `all` - Highlights both the `lowest-version` and `simplest-path`. If they are the same, they are only highlighted in ![red](https://placehold.it/15/ff0000/000000?text=+).

![Imgur](https://i.imgur.com/xtarzeU.png)

#### Crate specifier

The `allow`, `deny`, `skip`, and `skip-tree` fields all use a crate identifier to specify what crate(s) they want to match against.

`{ name = "some-crate-name-here", version = "<= 0.7.0" }`

##### The `name` field

The name of the crate.

##### The `version` field (optional)

An optional version constraint specifying the range of crate versions that will match. Defaults to all versions (`*`).

#### The `allow` and `deny` fields (optional)

As with `licenses`, these determine which specificy crates and version ranges are actually allowed or denied.

#### The `skip` field (optional)

When denying duplicate versions, it sometimes takes time to update versions in transitive dependencies, or big changes in core often used crates such as `winapi` and others to ripple through the rest of the ecosystem. In such cases, it can be ok to remove certain versions from consideration so that they won't trigger failures due to multiple versions, and can eventually be removed once all crates have update to the later version(s).

Note entries in the `skip` field that never match a crate in your graph will have a warning printed that they never matched, allowing you to clean up your configuration as your crate graph changes over time.

#### The `skip-tree` field (optional)

When dealing with duplicate versions, it's often the case that a particular crate acts as a nexus point for a cascade effect, by either using bleeding edge versions of certain crates while in alpha or beta, or on the opposite end, a crate is using severely outdated dependencies while much of the rest of the ecosystem has moved to more recent versions. In both cases, it can be quite tedious to explicitly `skip` each transitive dependency pulled in by that crate that clashes with your other dependencies, which is where `skip-tree` comes in.

`skip-tree` entries are similar to `skip` in that they are used to specify a crate name and version range that will be skipped, but they also have an additional `depth` field that can be used to specify the depth from that root crate that will also be ignored when checking for duplicates. In that sense, a `depth` of `0` would be functionally the same as specifying the same crate name and version constraint in the `skip` list instead.

Note that by default, the `depth` is infinite.

### Example Config

```toml
[bans]
multiple-versions = "deny"
deny = [
    # You can never be too sure
    { name = "openssl-sys" },
]
skip = [
    # askalono 0.3.0 uses an ancient regex version which pulls
    # in other duplicates
    { name = "regex", version = "=0.2.11" },
    { name = "regex-syntax", version = "=0.5.6" },
    { name = "aho-corasick", version = "=0.6.10" },

    # some macro crates use the pre 1.0 syn dependencies
    { name = "syn", version = "<=0.15" },
    { name = "proc-macro2", version = "<=0.4" },
    { name = "quote", version = "<=0.6" },
    { name = "unicode-xid", version = "=0.1" },
]
skip-tree = [
    # tonic is in alpha right now, and pulls in many alpha versions of tokio/tower
    # crates, so ignore all of them for now until things stabilize
    { name = "tonic", version = "0.1.0-alpha.4" },
    # ignore older rand as many crates still use it instead of the newer 0.7+ version
    { name = "rand", version = "=0.6.5" },
]
```

## Crate advisories - `cargo deny check advisories`

### Use Case - Detecting security vulnerabilities

Security vulnerabilities are generally considered "not great" by most people, luckily rust has a great [advisory database](https://github.com/RustSec/advisory-db) which cargo-deny can use to check that you don't have any crates with (known) security vulnerabilities.

### Use Case - Detecting unmaintained crates

The [advisory database](https://github.com/RustSec/advisory-db) also contains advisories for unmaintained crates which in most cases users will want to avoid in favor of more active crates.

### The `[advisories]` section

Contains all of the configuration for `cargo deny check advisories`

#### The `db-url` field (optional)

URL to the advisory database's git repo

Default: https://github.com/RustSec/advisory-db

#### The `db-path` field (optional)

Path to the local copy of advisory database's git repo

Default: ~/.cargo/advisory-db

#### The `vulnerability` field (optional)

Determines what happens when a crate with a security vulnerability is encountered.

* `deny` (default) - Will emit an error with details about each vulnerability, and fail the check.
* `warn` - Prints a warning for each vulnerability, but does not fail the check.
* `allow` - Prints a note about the security vulnerability, but does not fail the check.

#### The `unmaintained` field (optional)

Determines what happens when a crate with an `unmaintained` advisory is encountered.

* `deny` - Will emit an error with details about the unmaintained advisory, and fail the check.
* `warn` (default) - Prints a warning for each unmaintained advisory, but does not fail the check.
* `allow` - Prints a note about the unmaintained advisory, but does not fail the check.

#### The `notice` field (optional)

Determines what happens when a crate with a `notice` advisory is encountered.

**NOTE**: As of 2019-12-17 there are no `notice` advisories in https://github.com/RustSec/advisory-db

* `deny` - Will emit an error with details about the notice advisory, and fail the check.
* `warn` (default) - Prints a warning for each notice advisory, but does not fail the check.
* `allow` - Prints a note about the notice advisory, but does not fail the check.

#### The `ignore` field (optional)

Every advisory in the advisory database contains a unique identifier, eg. `RUSTSEC-2019-0001`, putting an identifier in this array will cause the advisory to be treated as a note, rather than a warning or error.

#### The `severity-threshold` field (optional)

The threshold for security vulnerabilities to be turned into notes instead of of warnings or errors, depending upon its [CVSS](https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System) score. So having a high threshold means some vulnerabilities might not fail the check, but having a log level `>= info` will mean that a note will be printed instead of a warning or error depending on `[advisories.vulnerability]`.

* `None` (default) - CVSS Score 0.0
* `Low` - CVSS Score 0.1 - 3.9
* `Medium` - CVSS Score 4.0 - 6.9
* `High` - CVSS Score 7.0 - 8.9
* `Critical` - CVSS Score 9.0 - 10.0


## Crate sources - `cargo deny check sources`

### Use Case - Only allowing known/trusted sources

Cargo is very flexible in where it can retrieve crates from, multiple registries, git repositories, file paths. This is great in general and very flexible for development. But esp. re-routing dependencies to git repositories increases the amount of sources that one would have to trust and may be something a repository want explicitly opt-in to. 

Related: [Why npm lockfiles can be a security blindspot for injecting malicious modules](https://snyk.io/blog/why-npm-lockfiles-can-be-a-security-blindspot-for-injecting-malicious-modules/)

### Use Case - Only using vendored file dependencies

A crate repository may want to only support local file dependencies, such as having all dependencies vendored into the repository for full control and offline building. That is easy to enforce with this check.

### The `[sources]` section

Contains all of the configuration for `cargo deny check sources`

#### The `unknown-registry` field (optional)

Determines what happens when a crate from a crate registry that is not in the allow list is encountered.

* `deny` - Will emit an error with the URL of the source, and fail the check.
* `warn` (default) - Prints a warning for each crate, but does not fail the check.
* `allow` - Prints a note for each crate, but does not fail the check.

#### The `unknown-git` field (optional)

Determines what happens when a crate from a git repository not in the allow list is encountered.

* `deny` - Will emit an error with the URL of the repository, and fail the check.
* `warn` (default) - Prints a warning for each crate, but does not fail the check.
* `allow` - Prints a note for each crate, but does not fail the check.

#### The `allow-registry` field (optional)

Configure which crate registries that are known and allowed.

If a crate is not found in the list. Then `unknown-registry` setting will determine how it is handled.

If not specified this list will by default contain the [crates.io](http://crates.io) registry, equivalent to this:

```toml
[sources]
allow-registry = [
    "https://github.com/rust-lang/crates.io-index"
]
```

To not allow any crates registries, set to empty:

```toml
[sources]
unknown-registry = "deny"
allow-registry = []
```


#### The `allow-git` field

Configure which crate registries that are known and allowed.

```toml
[sources]
unknown-git = "deny"
allow-git = [
    "https://github.com/rust-lang/crates.io-index"
]
```


## CI Usage

We now have a Github Action for running `cargo-deny` on your Github repositories, check it out [here](https://github.com/EmbarkStudios/cargo-deny-action).

If you don't want to, or can't, use the action, you can look at the [self check](https://github.com/EmbarkStudios/cargo-deny/blob/a3c1ef8d29d5132e477e06a51bb3c17c4c604375/.github/workflows/ci.yaml#L60-L101) job for this repository, which just checks `cargo-deny` itself using the [deny.toml](deny.toml) config for how you run it in on your own code.

Also note, that while you can install cargo-deny via the normal `cargo install` process, we prebuild binaries for Linux, MacOS, and Windows for every release which you can use something like this.

```sh
#!/bin/bash
set -eu

mkdir /tmp/cargo-deny

curl -L -o /tmp/cargo-deny/archive.tar.gz https://github.com/EmbarkStudios/cargo-deny/releases/download/0.5.1/cargo-deny-0.5.1-x86_64-unknown-linux-musl.tar.gz

tar -xzvf /tmp/cargo-deny/archive.tar.gz --strip-components=1 -C /tmp/cargo-deny

/tmp/cargo-deny/cargo-deny --context . -L debug check bans licenses advisories
```

## List - `cargo deny list`

Similarly to [cargo-license](https://github.com/onur/cargo-license), print out the licenses and crates that use them.

* `layout = license, format = human` (default)

![Imgur](https://i.imgur.com/Iejfc7h.png)

* `layout = crate, format = human`

![Imgur](https://i.imgur.com/zZdcFXI.png)

* `layout = license, format = json`

![Imgur](https://i.imgur.com/wC2R0ym.png)

* `layout = license, format = tsv`

![Imgur](https://i.imgur.com/14l8a5K.png)

## Contributing

We welcome community contributions to this project.

Please read our [Contributor Guide](CONTRIBUTING.md) for more information on how to get started.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
