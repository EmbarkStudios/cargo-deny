# Changing the official [RustSec](https://rustsec.org/) frontend

## What is RustSec?

The [Advisory Database] is a repository of security advisories filed against Rust crates published via https://crates.io maintained by the [Rust Secure Code Working Group].

The [Advisory Database] contains advisories for security vulnerabilities, in additional to informational advisories for things such as `unmaintained` crates and `unsound` code that doesn't necessarily represent a security vulnerability.

## Frontends

### [cargo-audit]

Currently, the [cargo-audit] tool maintained by the [Rust Secure Code Working Group] is the official frontend for checking crates against an advisory database.

### [cargo-deny]

For those who aren't aware, [cargo-deny] is a tool made by [Embark Studios] which can basically be thought of as a linter for your workspace's dependency graph, checking it against the constraints you've placed on it via a configuration file.

Almost a year ago, [cargo-deny] gained the ability to [check](https://github.com/EmbarkStudios/cargo-deny/blob/main/CHANGELOG.md#050---2019-12-18) the crate graph for advisories, making it (mostly) equivalent to [cargo-audit].

## Changing the official frontend

An [issue](https://github.com/EmbarkStudios/cargo-deny/issues/194) was opened on [cargo-deny] by the [primary maintainer](https://github.com/tarcieri) of RustSec asking if it could replace [cargo-audit] as the official frontend for several reasons...

* One fewer projects to maintain for them to maintain (always a good thing!)
* [cargo-deny]'s error reporting is generally better to [cargo-audit]'s
* [cargo-deny] is a superset of [cargo-audit], there is no reason to run them both
* The core functionality for interacting with advisory databases is already in a separate [client library](https://github.com/RustSec/rustsec-crate) that [cargo-deny] already uses

Once the missing features of [JSON output](https://github.com/EmbarkStudios/cargo-deny/blob/main/CHANGELOG.md#070---2020-06-25) and a [`fix` subcommand](https://github.com/EmbarkStudios/cargo-deny/blob/main/CHANGELOG.md#080---2020-10-20) were added, [cargo-deny] can now be considered at feature parity with [cargo-audit] and we can pull the trigger in switching over, at least officially.

### What does this mean for [cargo-audit] users?

Nothing, at least for now. You can continue to use [cargo-audit] to check your workspaces for advisories and everything will continue to work.

However, it's unlikely [cargo-audit] will get significant further development in the long term future, so it might be good to start thinking about switching (of course I might be biased).

In addition to checking for [advisories](https://embarkstudios.github.io/cargo-deny/checks/advisories/index.html), [cargo-deny] also supports checking for other things.

* [bans](https://embarkstudios.github.io/cargo-deny/checks/bans/index.html) - Ban specific crates and/or crate versions, as well as checking for duplicate versions of the same crate.
* [licenses](https://embarkstudios.github.io/cargo-deny/checks/licenses/index.html) - Validate that all crate license expressions match your requirements.
* [sources](https://embarkstudios.github.io/cargo-deny/checks/sources/index.html) - Validate all crates come from sources you trust.

## Migrating from [cargo-audit] to [cargo-deny]

### Minimal Example

First, [install](https://embarkstudios.github.io/cargo-deny/cli/index.html) [cargo-deny].

* Navigate to a workspace
* Run `cargo deny init` to create the default configuration file
* Run `cargo audit`
* Run `cargo deny check advisories` for the equivalent of `cargo audit`

### Ignoring additional checks

If you don't care about the other checks provided by [cargo-deny] you can always just use `cargo deny check advisories` and only the advisories check will ever be run.

### Running in CI

#### Github

If you want to check a repository hosted in Github, you can use the [cargo-deny-action](https://github.com/EmbarkStudios/cargo-deny-action) to run [cargo-deny] on it.

#### Other

We provide [binary releases](https://github.com/EmbarkStudios/cargo-deny/releases) for Windows, Linux (musl), and MacOS, so generally it is easiest to download and unpack it in a Linux environment, for example.

```bash
deny_version="0.8.1"
curl --silent -L https://github.com/EmbarkStudios/cargo-deny/releases/download/$deny_version/cargo-deny-$deny_version-x86_64-unknown-linux-musl.tar.gz | tar -xzv -C /usr/bin --strip-components=1
```

## Differences

While [cargo-deny] is functionally equivalent there are some important differences that might affect you depending on your scenario. Keep in mind the following should be fairly comprehensive, but it's not exhaustive.

### Output

[cargo-deny] varies quite a bit from [cargo-audit] in how it outputs diagnostics for advisories. If you are using just the regular output, well, that's (hopefully) one of the improvements that [cargo-deny] is providing for you.

However, if you happen to be using the `--json` option with [cargo-audit] you will need to use `--format json check --audit-compatible-output` to get the same exact output as [cargo-audit] to stdout.

### Runtime requirements

[cargo-audit] only needs to read the `Cargo.lock` file to find the crates to check against the advisory database, meaning that the environment in which you are running it doesn't need to have `cargo` installed.

However, [cargo-deny] uses `cargo metadata`, or, with the `standalone` feature, `cargo` itself, to gather entire crate graph for your workspace, which lets it do more advanced [filtering](https://embarkstudios.github.io/cargo-deny/cli/common.html) of which crates it considers during [check](https://embarkstudios.github.io/cargo-deny/cli/check.html)ing, and even when the `standalone` feature is used, you still need to have [`rustc`](https://github.com/EmbarkStudios/cargo-deny/issues/295) itself installed.

### Configuration

[cargo-audit] supports various command line options such as `--ignore <advisory_id>` to configure its behavior, that are either not supported by [cargo-deny] or are done slightly differently due to [cargo-deny]'s use of a [configuration file](https://embarkstudios.github.io/cargo-deny/checks/cfg.html).

| config | [cargo-audit] | [cargo-deny] |
| --- | --- | --- |
| enable all-features | ❌ | [--all-features](https://embarkstudios.github.io/cargo-deny/cli/common.html#--all-features-single-crate-or-workspace) |
| no default features | ❌ | [--no-default-features](https://embarkstudios.github.io/cargo-deny/cli/common.html#--no-default-features-single-crate-only) |
| specific features | ❌ | [--features](https://embarkstudios.github.io/cargo-deny/cli/common.html#--features-single-crate-only)
| toggle output coloring | -c, --color | [-c, --color](https://embarkstudios.github.io/cargo-deny/cli/common.html#--color) |
| local path for advisory database | -d, --db | [deny.toml](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html#the-db-path-field-optional) |
| deny warnings | -D, --deny-warnings | ❌ |
| specify workspace | -f _Cargo.lock_ | [--manifest-path _Cargo.toml_](https://embarkstudios.github.io/cargo-deny/cli/common.html#--manifest-path) |
| ignore advisory | --ignore _id_ | [deny.toml](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html#the-ignore-field-optional) |
| disable db fetching | -n, --no-fetch | [-d, --disable-fetch](https://embarkstudios.github.io/cargo-deny/cli/check.html#-d---disable-fetch) |
| specify advisory db source | -u, --url | [deny.toml](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html#the-db-urls-field-optional)
| JSON output | --json | [--format json](https://embarkstudios.github.io/cargo-deny/cli/common.html#--format) |

## Conclusion

If you have any questions or issues you can ping us in [Discord](https://discord.gg/Fg4u4VX) or open an issue in [Github](https://github.com/EmbarkStudios/cargo-deny/issues/new/choose).

[Rust Secure Code Working Group]: https://www.rust-lang.org/governance/wgs/wg-secure-code
[Advisory Database]: https://github.com/RustSec/advisory-db
[cargo-audit]: https://github.com/RustSec/cargo-audit
[cargo-deny]: https://github.com/EmbarkStudios/cargo-deny
[Embark Studios]: https://github.com/EmbarkStudios