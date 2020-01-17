# The `[bans]` section

Contains all of the configuration for `cargo deny check bans`

## Example Config

```ini
[bans]
multiple-versions = "deny"
deny = [
    # "Problematic"
    # we use rustls instead
    { name = "openssl" },
    { name = "openssl-sys" },
    # we don't want to use any XML and some of these are 4 year old dependencies
    { name = "RustyXml" },
    { name = "serde-xml-rs" },
    # sha2 crate has surprising amount of dependencies, 
    # and we use ring instead in this project
    { name = "sha2" },

    # Library choices
    # we use glam as math library, not nalgebra
    { name = "nalgebra" },
    { name = "nalgebra-glm" },

    # deprecated/abandoned
    # term is not fully maintained, and termcolor is replacing it
    { name = "term" },
    # explicitly deprecated
    { name = "quickersort" },
]
skip = [
    # multiple crates use old percent-encoding
    { name = "percent-encoding", version = "<=1.0" },

    # ignore, texture-synthesis use this older version
    { name = "crossbeam-utils", version = "=0.6" },

    # rustls uses old base64 (have been upgraded on master)
    { name = "base64", version = "=0.10" },

    # bindgen (via coreaudio-sys) uses an old version
    { name = "version_check", version = "=0.1" },

    # sentry uses old url 1.7.
    # https://github.com/getsentry/rust-sentry-types/issues/39
    { name = "url", version = "=1.7" },
    { name = "idna", version = "=0.1" },
]
skip-tree = [
    # several crates use older versions of parking_lot
    { name = "parking_lot", version = "=0.9" },
    # ignore older rand and its "fun" crate structure
    { name = "rand", version = "=0.6.5" },
    # tonic is in alpha right now, and pulls in many alpha versions of 
    # tokio/tower crates, so ignore all of them for now until things stabilize
    { name = "tonic", version = "0.1.0-alpha.4" },
    # ignore winit 0.19 for now as it pulls in older crates, 
    # wayland stuff in particular
    { name = "winit", version = "= 0.19" },
]
```

### The `multiple-versions` field (optional)

Determines what happens when multiple versions of the same crate are
encountered.

* `deny` - Will emit an error for each crate with duplicates and fail the check.
* `warn` (default) - Prints a warning for each crate with duplicates, but does 
not fail the check.
* `allow` - Ignores duplicate versions of the same crate.

### The `highlight` field (optional)

When multiple versions of the same crate are encountered and `multiple-versions`
is set to `warn` or `deny`, using the `-g <dir>` option will print out a 
[dotgraph](https://www.graphviz.org/) of each of the versions and how they were 
included into the graph. This field determines how the graph is colored to help 
you quickly spot good candidates for removal or updating.

* `lowest-version` - Highlights the path to the lowest duplicate version. 
Highlighted in ![red](https://placehold.it/15/ff0000/000000?text=+)
* `simplest-path` - Highlights the path to the duplicate version with the 
fewest number of total edges to the root of the graph, which will often be the 
best candidate for removal and/or upgrading. Highlighted in 
![blue](https://placehold.it/15/0000FF/000000?text=+).
* `all` - Highlights both the `lowest-version` and `simplest-path`. If they are 
the same, they are only highlighted in 
![red](https://placehold.it/15/ff0000/000000?text=+).

![Imgur](https://i.imgur.com/xtarzeU.png)

### Crate specifier

The `allow`, `deny`, `skip`, and `skip-tree` fields all use a crate identifier 
to specify what crate(s) they want to match against.

`{ name = "some-crate-name-here", version = "<= 0.7.0" }`

#### The `name` field

The name of the crate.

#### The `version` field (optional)

An optional version constraint specifying the range of crate versions that will 
match. Defaults to all versions (`*`).

### The `allow` and `deny` fields (optional)

Determines specific crates that are allowed or denied. If the `allow` list has 
one or more entries, then any crate not in that list will be denied, so use with
care.

### The `skip` field (optional)

When denying duplicate versions, it's often the case that there is a window of
time where you must wait for eg. PRs to be accepted and new version published,
before 1 or more duplicates are gone. The `skip` field allows you to temporarily
ignore a crate during duplicate detection so that no errors are emitted, until
it is no longer need.

It is recommended to use specific version constraints for crates in the `skip`
list, as cargo-deny will emit warnings when any entry in the `skip` list no
longer matches a crate in your graph so that you can cleanup your configuration.

### The `skip-tree` field (optional)

When dealing with duplicate versions, it's often the case that a particular 
crate acts as a nexus point for a cascade effect, by either using bleeding edge 
versions of certain crates while in alpha or beta, or on the opposite end of
the specturm, a crate is using severely outdated dependencies while much of the 
rest of the ecosystem has moved to more recent versions. In both cases, it can 
be quite tedious to explicitly `skip` each transitive dependency pulled in by 
that crate that clashes with your other dependencies, which is where `skip-tree` 
comes in.

`skip-tree` entries are similar to `skip` in that they are used to specify a 
crate name and version range that will be skipped, but they also have an 
additional `depth` field used to specify how many levels from the crate will
also be skipped. A depth of `0` would be the same as specifying the crate in
the `skip` field.

Note that by default, the `depth` is infinite.

`skip-tree` is a very big hammer at the moment, and should be used with care.
