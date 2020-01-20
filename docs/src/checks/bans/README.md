# bans

The bans check is used to deny (or allow) specific crates, as well as detect
and handle multiple versions of the same crate.

```bash
cargo deny check bans
```

<img src="https://imgur.com/K3UeXcR.png"/>

## Use Case - Denying specific crates

Sometimes, certain crates just don't fit in your project, so you have to remove 
them. However, nothing really stops them from sneaking back in due to innocuous
changes like doing a `cargo update` and getting it transitively, or even
forgetting to set 
`default-features = false, features = ["feature-without-the-thing"]` when the 
crate is pulled in via the default features of a crate you already depend on, 
in your entire workspace.

For example, we previously depended on OpenSSL as it is the "default" for many 
crates that provide TLS. This was extremely annoying as it required us to have 
OpenSSL development libraries installed on Windows, for both individuals and CI. 
We moved all of our dependencies to use the much more streamlined `native-tls` 
or `ring` crates instead, and now we can make sure that OpenSSL doesn't return 
from the grave by accident.

## Use Case - Duplicate version detection

The larger your project and number of external dependencies, the likelihood that
you will have multiple versions of the same crate rises. This is due to two
fundamental aspects of the Rust ecosystem.

1. Cargo's dependency resolution, tries to solve all  the version constraints 
to a crate to the same version, but is totally ok with using [multiple 
versions](https://stephencoakley.com/2019/04/24/how-rust-solved-dependency-hell)
if it is unable to.
1. Rust has a huge (ever growing) number of crates. Every maintainer has
different amounts of time and energy they can spend on their crate, not to
mention different philosophies on dependecies and how often (or not) they should
be updated, so it is inevitable that crates will not always agree on which
version of another crate they want to use.

This tradeoff of allowing multiple version so of the same crate is one of the
reasons that cargo is such a pleasant experience for many people new to Rust,
but as with all tradeoffs, it does come with costs.

1. More packages must be fetched, which tends to impact CI more than devs.
1. Compile times increase, which impacts CI and devs.
1. Target directory size increases, which can impact devs.
1. Final binary size will also tend to increase, which can impact users.

Normally, you will not really notice that you have multiple versions of the
same crate unless you constantly watch your build log, but as mentioned above,
it **does** introduce papercuts into your workflows.

The intention of duplicate detection in cargo-deny is not to "correct" cargo's
behavior, but rather to draw your attention to duplicates so that you can make
and informed decision about how to handle the situation.

* Maybe you want to open up a PR on a crate to use a version of the duplicate
that is aligned with the rest of the ecosystem.
* Maybe the crate has actually already been updated, but the maintainer hasn't
published a new version yet and you can ask them to publish a new one.
* Maybe even though the versions are supposedly incompatible according to
semver, they actually aren't, and you temporarily introduce a `[patch]` to
force the crate to use a particular version.
* Sometimes having the "latest and greatest" is not really that imporant for
every version, and you can just downgrade to a version that matches one of
the duplicates instead.

