# ❌ cargo-deny

[![Build Status](https://github.com/EmbarkStudios/cargo-deny/workflows/CI/badge.svg)](https://github.com/EmbarkStudios/cargo-deny/actions?workflow=CI)
[![Latest version](https://img.shields.io/crates/v/cargo-deny.svg)](https://crates.io/crates/cargo-deny)
[![Docs](https://docs.rs/cargo-deny/badge.svg)](https://docs.rs/cargo-deny)
[![Contributor Covenant](https://img.shields.io/badge/contributor%20covenant-v1.4%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)
[![Embark](https://img.shields.io/badge/embark-open%20source-blueviolet.svg)](http://embark.games)

One of the key selling points of Rust is the ever growing and improving ecosystem of crates
available that can be easily added to your project incredibly easily via `cargo`. This is great!
However, the larger the project is and the more dependencies you have, the harder it is to keep
track of certain things, especially as a project evolves over time, which is what `cargo-deny` tries to help you with.

* [Licenses](#licenses---cargo-deny-check-license) - Configure which license terms you accept
* [Bans](#crate-bans---cargo-deny-check-ban) - Configure whether particular crates are allowed in your dependency graph

## tl;dr

* `cargo deny check <license|all>` - verify crate graph only contains acceptable license requirements
* `cargo deny check <ban|all>` - verify crate graph doesn't contain certain crates
* `cargo deny list` - list all of the licenses for all crates in a project

## Licenses - `cargo deny check license`

One important aspect that one must always keep in mind when using code from other people is what the licensing of that code is and whether it fits the requirements of your project. Luckily, most of the crates in the Rust ecosystem tend to follow the example set forth by Rust itself, namely dual-license `MIT OR Apache-2.0`, but of course, that is not always the case.

So `cargo-deny` allows you to ensure that all of your dependencies have license requirements that align with your configuration.

### The `[licenses]` section

Contains all of the configuration for `cargo deny check license`

#### The `unlicensed` field

Determines what happens when a crate has not explicitly specified its license terms, and no license
information could be easily detected via `LICENSE*` files in the crate's source.

* `deny` (default) - All unlicensed crates will emit an error and fail the license check
* `allow` - All unlicensed crates will be allowed with no feedback
* `warn` - All unlicensed crates will show a warning, but will not fail the license check

#### The `allow` and `deny` fields

The licenses that should be allowed or denied. The license must be a valid SPDX v2.1 identifier, which must either be in version 3.6 of the [SPDX License List](https://spdx.org/licenses/), with an optional [exception](https://spdx.org/licenses/exceptions-index.html) specified by `WITH <exception-id>`, or else a user defined license reference denoted by `LicenseRef-<idstring>` for a license not on the SPDX License List.

The same license cannot appear in both the `allow` and `deny` lists.

#### The `allow-osi-fsf-free` field

Determines what happens when licenses aren't explicitly allowed or denied, but are marked as [OSI Approved](https://opensource.org/licenses) or [FSF Free/Libre](https://www.gnu.org/licenses/license-list.en.html) in version 3.6 of the [SPDX License List](https://spdx.org/licenses/).

* `both` - The license is accepted if it is both OSI approved and FSF Free
* `either` - The license is accepted if it is either OSI approved or FSF Free
* `osi-only` - The license is accepted if it is OSI approved and not FSF Free
* `fsf-only` - The license is accepted if it is FSF Free and not OSI approved
* `neither` (default) - No special consideration is given the license

#### The `confidence-threshold` field

`cargo-deny` uses [askalono](https://github.com/amzn/askalono) to determine the license of a license file, the confidence threshold value determines if askalono's determination meets your
minimum requirements. The higher the value, the more closely the license text must be to the canonical license text of a valid SPDX license file.

`0.0` - `1.0` (default `0.8`)

#### The `clarify` field

In some exceptional cases, the crate does not have easily machine readable license information, and would by default be considered "unlicensed" by `cargo-deny`. As a (hopefully) temporary patch for using the crate, you can specify a clarification for a crate where you can specify the license expression based on your understanding of the requirements as described by the license holder.

##### The `name` field

The name of the crate that you are clarifying

##### The `version` field

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

## Crate bans - `cargo deny check ban`

### Use Case - Keeping certain crates out of your dependency graph

Sometimes, certain crates just don't fit in your project, so you have to remove them. However,
nothing really stops them from sneaking back in due to small changes, like updating a crate to
a new version that happens to add it as a dependency, or an existing dependency just changing
what crates are included in the default feature set.

For example, we previously depended on OpenSSL as it is the "default" for many crates that deal
with HTTP traffic. This was extremely annoying as it required us to have OpenSSL development libraries installed on Windows, for both individuals and CI. We moved all of our dependencies to use the much more streamlined `native-tls` and `ring` crates instead, and now we can make sure that OpenSSL doesn't return from the grave by being pulled in as a default feature of some future HTTP crate we might use.

### Use Case - Get a handle on duplicate versions

One thing that is part of the tradeoff of being able to use so many crates, is that they all won't
necessarily agree on what versions of a dependency they want to use, and cargo and rust will happily chug along compiling all of them.  This is great when just trying out a new dependency as quickly as possible, but it does come with some long term costs. Crate fetch times (and disk space) are increased, but in particular, **compile times**, and ultimately your binary sizes, also increase. If you are made aware that you depend on multiple versions of the same crate, you at least have an opportunity to decide how you want to handle them.

1. What happens when multiple versions of a crate are used? `allow` / `deny` / `warn`
1. Skip certain versions of crates, sometimes you just need to wait for a crate
to get a new release, or sometimes a little duplication is ok and not worth the effort
to "fix", but you are at least aware of it and explicitly allowing it, rather than suffering in
ignorance.
1. The `-g <path>` cmd line option on the `check` subcommand instructs `cargo-deny` to create
a [dotgraph](https://www.graphviz.org/) if multiple versions of a crate are detected and that
isn't allowed. A single graph will be created for each crate, with each version as a terminating
node in the graph with the full graph of crates that reference each version to more easily
show you why a particular version is included. It also highlights the lowest version's path
in ![red](https://placehold.it/15/ff0000/000000?text=+), and, if it differs from the lowest version,
the "simplest" path is highlighted in ![blue](https://placehold.it/15/0000FF/000000?text=+).

![Imgur](https://i.imgur.com/xtarzeU.png)

### The `[bans]` section

Contains all of the configuration for `cargo deny check ban`

#### The `multiple-versions` field

Determines what happens when multiple versions of the same crate are encountered.

* `deny` - Will emit an error for each crate with duplicates and fail the check.
* `warn` (default) - Prints a warning for each crate with duplicates, but does not fail the check.
* `allow` - Ignores duplicate versions of the same crate.

#### The `highlight` field

When multiple versions of the same crate are encountered and the `multiple-versions` is set to `warn` or `deny`, using the `-g <dir>` option will print out a dotgraph of each of the versions and how they were included into the graph. This field determines how the graph is colored to help you quickly spot good candidates for removal or updating.

* `simplest-path` - Highlights the path to the duplicate version with the fewest number of total
edges to the root of the graph, which will often be the best candidate for removal and/or upgrading.
* `lowest-version` - Highlights the path to the lowest duplicate version
* `all` - Highlights both the `lowest-version` and `simplest-path`, if they are different

#### The `allow` and `deny` fields

As with `licenses`, these determine which specificy crates and version ranges are actually allowed or denied.

#### The `skip` field

When denying duplicate versions, it sometimes takes time to update versions in transitive dependencies, or big changes in core often used crates such as winapi and others to ripple through the rest of the ecosystem. In such cases, it can be ok to remove certain versions from consideration so that they won't trigger failures due to multiple versions, and can eventually be removed once all crates have update to the later version(s).

Note entries in the `skip` field that never match a crate in your graph will have a warning printed that they never matched, allowing you to clean up your configuration as your crate graph changes over time.

#### Crate specifier

The `allow`, `deny`, and `skip` fields all use a crate identifier to specify what crate(s) they want to match against.

##### The `name` field

The name of the crate.

##### The `version` field

An optional version constraint specifying the range of crate versions that will match. Defaults to all versions (`*`).

### Example Config

```toml
[bans]
multiple-versions = "deny"
deny = [
    # You can never be too sure
    { name = "openssl" },
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
```

## CI Usage

`cargo-deny` is primarily meant to be used in your CI so it can do automatic verification for all
your changes, for an example of this, you can look at the [self check](https://github.com/EmbarkStudios/cargo-deny/blob/master/.travis.yml#L77-L87) job for this repository, which just checks `cargo-deny` itself using the [deny.toml](deny.toml) config.

## List - `cargo deny list`

Similarly to [cargo-license](https://github.com/onur/cargo-license), print out the licenses and crates
that use them.

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

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
