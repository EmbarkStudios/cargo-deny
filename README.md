[![Build Status](https://travis-ci.com/EmbarkStudios/cargo-deny.svg?branch=master)](https://travis-ci.com/EmbarkStudios/cargo-deny)
[![Docs](https://docs.rs/cargo-deny/badge.svg)](https://docs.rs/cargo-deny)

# cargo-deny

One of the key selling points of Rust is the ever growing and improving ecosystem of crates
available that can be easily added to your project incredibly easily via `cargo`. This is great!
However, the larger the project is and the more dependencies you have, the harder it is to keep
track of certain things, especially as a project evolves over time, which `cargo-deny` tries to help
you with.

## Licenses

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
an extent as it makes it difficult to automatically determinte it.

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

## Crate bans

Sometimes, certain crates just don't fit in your project, so you have to remove them, but in
some cases, they can sneak back in if you aren't careful, usually through accidentally using
them via the default features of another crate. Another thing that is part of the tradeoff of
being able to use so many crates is that they all don't necessarily agree on what versions of a
dependency they want to use, and cargo and rust will happily chug along compiling all of them
this is great for adding a new dependency that you just want to try at first without having
to heavily modify your own crates, but it does come at a long term cost of increased crate fetch
times and particularly compile times as you are essentially compiling the "same" thing multiple
times

1. Dis/allow certain crates in your dependency graph.
1. What happens when multiple versions of a crate are used? `allow` / `deny` / `warn`
1. Skip certain verions of crates, sometimes you just need to wait for a crate
to get a new release, or sometimes a little duplication is ok and not worth the effort
to "fix", but you are at least aware of it and allowing it, versus suffering from
unnecessarily longer compile times.

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
