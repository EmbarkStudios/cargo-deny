<div align="center">

# `❌ cargo-deny`

**Cargo plugin for linting your dependencies**

[![Embark Opensource](https://img.shields.io/badge/embark-open%20source-blueviolet.svg)](https://embark.dev)
[![Embark Discord](https://img.shields.io/badge/discord-ark-%237289da.svg?logo=discord)](https://discord.gg/Fg4u4VX)
[![Crates.io](https://img.shields.io/crates/v/cargo-deny.svg)](https://crates.io/crates/cargo-deny)
[![API Docs](https://docs.rs/cargo-deny/badge.svg)](https://docs.rs/cargo-deny)
[![Docs](https://img.shields.io/badge/The%20Book-📕-brightgreen.svg)](https://embarkstudios.github.io/cargo-deny/)
[![Minimum Stable Rust Version](https://img.shields.io/badge/Rust-1.53.0-blue?color=fc8d62&logo=rust)](https://blog.rust-lang.org/2021/06/17/Rust-1.53.0.html)
[![SPDX Version](https://img.shields.io/badge/SPDX%20Version-3.14-blue.svg)](https://spdx.org/licenses/)
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

### [Install](https://embarkstudios.github.io/cargo-deny/cli/index.html) cargo-deny

If you want to use `cargo-deny` without having `cargo` installed,
build `cargo-deny` with the `standalone` feature.
This can be useful in Docker Images.

```bash
cargo install --locked cargo-deny

# Or, if you're an Arch user
yay -S cargo-deny
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

<img src="https://imgur.com/XMmvx9L.png"/>

#### [Bans](https://embarkstudios.github.io/cargo-deny/checks/bans/index.html)

The bans check is used to deny (or allow) specific crates, as well as detect and handle multiple versions of the same crate.

```bash
cargo deny check bans
```

<img src="https://imgur.com/K3UeXcR.png"/>

#### [Advisories](https://embarkstudios.github.io/cargo-deny/checks/advisories/index.html)

The advisories check is used to detect issues for crates by looking in an advisory database.

```bash
cargo deny check advisories
```

<img src="https://imgur.com/FK50XLb.png"/>

#### [Sources](https://embarkstudios.github.io/cargo-deny/checks/sources/index.html)

The sources check ensures crates only come from sources you trust.

```bash
cargo deny check sources
```

<img src="https://imgur.com/xdHFDWS.png"/>

## Contributing

[![Contributor Covenant](https://img.shields.io/badge/contributor%20covenant-v1.4-ff69b4.svg)](CODE_OF_CONDUCT.md)

We welcome community contributions to this project.

Please read our [Contributor Guide](CONTRIBUTING.md) for more information on how to get started.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
