<!-- markdownlint-disable no-inline-html first-line-heading no-emphasis-as-heading -->

<div align="center">

# `❌ cargo-deny`

**Cargo plugin for linting your dependencies**

[![Embark Opensource](https://img.shields.io/badge/embark-open%20source-blueviolet.svg)](https://embark.dev)
[![Embark Discord](https://img.shields.io/badge/discord-ark-%237289da.svg?logo=discord)](https://discord.gg/Fg4u4VX)
[![Crates.io](https://img.shields.io/crates/v/cargo-deny.svg)](https://crates.io/crates/cargo-deny)
[![API Docs](https://docs.rs/cargo-deny/badge.svg)](https://docs.rs/cargo-deny)
[![Docs](https://img.shields.io/badge/The%20Book-📕-brightgreen.svg)](https://embarkstudios.github.io/cargo-deny/)
[![Minimum Stable Rust Version](https://img.shields.io/badge/Rust-1.70.0-blue?color=fc8d62&logo=rust)](https://blog.rust-lang.org/2023/06/01/Rust-1.70.0.html)
[![SPDX Version](https://img.shields.io/badge/SPDX%20Version-3.25.0-blue.svg)](https://spdx.org/licenses/)
[![dependency status](https://deps.rs/repo/github/EmbarkStudios/cargo-deny/status.svg)](https://deps.rs/repo/github/EmbarkStudios/cargo-deny)
[![Build Status](https://github.com/EmbarkStudios/cargo-deny/workflows/CI/badge.svg)](https://github.com/EmbarkStudios/cargo-deny/actions?workflow=CI)

</div>

See the [book 📕](https://embarkstudios.github.io/cargo-deny/) for in-depth documentation.

To run on CI as a GitHub Action, see [`cargo-deny-action`](https://github.com/EmbarkStudios/cargo-deny-action).

_Please Note: This is a tool that we use (and like!) and it makes sense to us to release it as open source. However, we can’t take any responsibility for your use of the tool, if it will function correctly or fulfil your needs. No functionality in - or information provided by - cargo-deny constitutes legal advice._

## [Quickstart](https://embarkstudios.github.io/cargo-deny/)

```bash
cargo install --locked cargo-deny && cargo deny init && cargo deny check
```

## Usage

<a href="https://repology.org/project/cargo-deny/versions"><img align="right" src="https://repology.org/badge/vertical-allrepos/cargo-deny.svg" alt="Packaging status"></a>

### [Install](https://embarkstudios.github.io/cargo-deny/cli/index.html) cargo-deny

If you want to use `cargo-deny` without having `cargo` installed, build `cargo-deny` with the `standalone` feature. This can be useful in Docker Images.

```bash
cargo install --locked cargo-deny

# Or, if you're an Arch user
pacman -S cargo-deny
```

### [Initialize](https://embarkstudios.github.io/cargo-deny/cli/init.html) your project

```bash
cargo deny init
```

### [Check](https://embarkstudios.github.io/cargo-deny/cli/check.html) your crates

```bash
cargo deny check
```

#### [Licenses](https://embarkstudios.github.io/cargo-deny/checks/licenses/index.html)

The licenses check is used to verify that every crate you use has license terms you find acceptable.

```bash
cargo deny check licenses
```

![licenses output](docs/src/output/licenses.svg)

#### [Bans](https://embarkstudios.github.io/cargo-deny/checks/bans/index.html)

The bans check is used to deny (or allow) specific crates, as well as detect and handle multiple versions of the same crate.

```bash
cargo deny check bans
```

![bans output](docs/src/output/bans.svg)

#### [Advisories](https://embarkstudios.github.io/cargo-deny/checks/advisories/index.html)

The advisories check is used to detect issues for crates by looking in an advisory database.

```bash
cargo deny check advisories
```

![advisories output](docs/src/output/advisories.svg)

#### [Sources](https://embarkstudios.github.io/cargo-deny/checks/sources/index.html)

The sources check ensures crates only come from sources you trust.

```bash
cargo deny check sources
```

![sources output](docs/src/output/sources.svg)

### Pre-commit hook

You can use `cargo-deny` with [pre-commit](https://pre-commit.com). Add it to your local `.pre-commit-config.yaml` as follows:

```yaml
- repo: https://github.com/EmbarkStudios/cargo-deny
  rev: 0.14.16 # choose your preferred tag
  hooks:
    - id: cargo-deny
      args: ["--all-features", "check"] # optionally modify the arguments for cargo-deny (default arguments shown here)
```

## Contributing

[![Contributor Covenant](https://img.shields.io/badge/contributor%20covenant-v1.4-ff69b4.svg)](CODE_OF_CONDUCT.md)

We welcome community contributions to this project.

Please read our [Contributor Guide](CONTRIBUTING.md) for more information on how to get started.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
