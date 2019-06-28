[![Build Status](https://travis-ci.com/EmbarkStudios/cargo-deny.svg?branch=master)](https://travis-ci.com/EmbarkStudios/cargo-deny)
[![Docs](https://docs.rs/cargo-deny/badge.svg)](https://docs.rs/cargo-deny)

# ❌ cargo-deny

One of the key selling points of Rust is the ever growing and improving ecosystem of crates
available that can be easily added to your project incredibly easily via `cargo`. This is great!
However, the larger the project is and the more dependencies you have, the harder it is to keep
track of certain things, especially as a project evolves over time, which is what `cargo-deny` tries to help
you with.

* [Licenses](#licenses) - Configure which licenses are allowed
* [Bans](#crate-bans) - Configure whether certain crates are allowed to be in your dependency graph

## tl;dr

* `cargo-deny check <license|all>` - verify licenses for a crate graph
* `cargo-deny check <ban|all>` - verify crate graph doesn't contain certain crates
* `cargo-deny list` - list all of the licenses in a crate graph

## Licenses - `cargo-deny check license`

One important aspect that one must always keep in mind when using code from other people is what the licensing
of that code is and whether it fits the requirements of your project. Luckily, most of the crates in the Rust
ecosystem tend to follow the example set forth by Rust itself, namely dual-license MIT and Apache 2.0, but of
course, that is not always the case. 

So `cargo-deny` allows you to ensure that all of your dependencies meet the requirements you want.

1. What happens when a crate is unlicensed? `allow` / `deny` / `warn`
1. What happens when a crate's license can't be determined? `allow` / `deny` / `warn`
1. Explicitly allow or deny 1 or more licenses.
1. Skip checking certain crates as long as they still have the same license information.
1. Ignore specific `LICENSE*` files. `cargo-deny` uses the [askalono](https://github.com/amzn/askalono) crate
to parse and score license text as being a certain license, but some license text can be modified to such
an extent that it makes it difficult to automatically determine it.

### Example config

```toml
[licenses]
unlicensed = "deny"
unknown = "deny"
# We want really high confidence when inferring licenses from text
confidence_threshold = 0.92
allow = [
    "Embark-Proprietary",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-2-Clause-FreeBSD",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "FTL",
    "ISC",
    "LLVM-exception",
    "MIT",
    "MPL-2.0",
    "Unicode-DFS-2016",
    "Unlicense",
    "Zlib",
]
skip = [
    # ring has a rather complicated LICENSE file due to reasons spelled out
    # in said LICENSE file, but is basically OpenSSL for older parts, and ISC
    # for newer parts
    { name = "ring", licenses = [] },
    # webpki uses an ISC license but it only has a 0.83 confidence level
    { name = "webpki", licenses = [] },
]

[[licenses.ignore]]
name = "rustls"
license_files = [
    # This is a top-level LICENSE that just spells out the *actual* 3
    # licenses that can be used with the crate, which askalono is unable
    # to score
    { path = "LICENSE", hash = 0xe567c411 },
]
```

## Crate bans - `cargo-deny check ban`

Sometimes, certain crates just don't fit in your project, so you have to remove them. However,
nothing really stops them from sneaking back in due to small changes, like updating a crate to
a new version that happens to add it as a dependency, or just changing what crates are included
in the default feature set.

One thing that is part of the tradeoff of being able to use so many crates, is that they all won't
necessarily agree on what versions of a dependency they want to use, and cargo and rust will happily
chug along compiling all of them.  This is great when just trying out a new dependency as quickly as
possible, but it does come with some long term costs. Crate fetch times (and disk space) are increased,
but in particular, **compile times** and ultimately your binary sizes to increase. If you are made aware 
that you depend on multiple versions of the same crate, you have an opportunity to 

1. Dis/allow certain crates in your dependency graph.
1. What happens when multiple versions of a crate are used? `allow` / `deny` / `warn`
1. Skip certain versions of crates, sometimes you just need to wait for a crate
to get a new release, or sometimes a little duplication is ok and not worth the effort
to "fix", but you are at least aware of it and allowing it, versus suffering from
unnecessarily longer compile times.
1. The `-g <path>` cmd line option on the `check` subcommand instructs `cargo-deny` to create
a [dotgraph](https://www.graphviz.org/) if multiple versions of a crate are detected and that
isn't allowed. A single graph will be created for each crate, with each version as a terminating
node in the graph with the full graph of crates that reference each version to more easily
show you why a particular version is included. It also highlights the lowest version's path
in ![red](https://placehold.it/15/ff0000/000000?text=+), and if it different from the lowest version,
the "simplest" path is highlighted in ![blue](https://placehold.it/15/0000FF/000000?text=+).

![Imgur](https://i.imgur.com/xtarzeU.png)

```toml
[bans]
multiple_versions = "deny"
deny = [
    # OpenSSL = Just Say No.
    { name = "openssl" },
]
skip = [
    # The issue where mime_guess is using a really old version of
    # unicase has been fixed, it just needs to be released
    # https://github.com/sfackler/rust-phf/issues/143
    { name = "unicase", version = "=1.4.2" },
    # rayon/rayon-core use very old versions of crossbeam crates,
    # so skip them for now until rayon updates them
    { name = "crossbeam-deque", version = "=0.2.0" },
    { name = "crossbeam-epoch", version = "=0.3.1" },
    { name = "crossbeam-utils", version = "=0.2.2" },
    # tokio-reactor, wasmer, and winit all use an older version
    # of parking_lot
    { name = "parking_lot", version = "=0.7.1" },
    { name = "parking_lot_core", version = "=0.4.0" },
    { name = "lock_api", version = "=0.1.5" },
    # rand_core depends on a newever version of itself...
    { name = "rand_core", version = "=0.3.1" },
    # lots of transitive dependencies use the pre-1.0 version
    # of scopeguard
    { name = "scopeguard", version = "=0.3.3" },
    # tons of transitive dependencies use this older winapi version
    { name = "winapi", version = "=0.2.8" },
]
```

## CI Usage

`cargo-deny` is primarily meant to be used in your CI so it can do automatic verification for all
your changes, for an example of this, you can look at the [self check](https://github.com/EmbarkStudios/cargo-deny/blob/master/.travis.yml#L77-L87) job for this repository, which just checks `cargo-deny` itself using
the [deny.toml](deny.toml) config.

## List - `cargo-deny list`

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
