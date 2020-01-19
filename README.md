# ❌ cargo-deny

[![Build Status](https://github.com/EmbarkStudios/cargo-deny/workflows/CI/badge.svg)](https://github.com/EmbarkStudios/cargo-deny/actions?workflow=CI)
[![Latest version](https://img.shields.io/crates/v/cargo-deny.svg)](https://crates.io/crates/cargo-deny)
[![Docs](https://img.shields.io/badge/docs-The%20Book-green.svg)](https://embarkstudios.github.io/cargo-deny/)
[![API Docs](https://docs.rs/cargo-deny/badge.svg)](https://docs.rs/cargo-deny)
[![SPDX Version](https://img.shields.io/badge/SPDX%20Version-3.7-blue.svg)](https://spdx.org/licenses/)
[![Contributor Covenant](https://img.shields.io/badge/contributor%20covenant-v1.4%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)
[![Embark](https://img.shields.io/badge/embark-open%20source-blueviolet.svg)](http://embark.dev)

`cargo-deny` is a cargo plugin for linting your dependencies. See the [book 📖](https://embarkstudios.github.io/cargo-deny/) for in-depth documentation.

To run on CI as a GitHub Action, see [`cargo-deny-action`](https://github.com/EmbarkStudios/cargo-deny-action).

## [Quickstart](https://embarkstudios.github.io/cargo-deny/)

```bash
cargo install cargo-deny && cargo deny init && cargo deny check
```

## Usage

### [Install](https://embarkstudios.github.io/cargo-deny/cli/index.html) cargo-deny

```bash
cargo install cargo-deny
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

#### [Bans](https://embarkstudios.github.io/cargo-deny/checks/bans/index.html)

The bans check is used to deny (or allow) specific crates, as well as detect and handle multiple versions of the same crate.

```bash
cargo deny check bans
```

#### [Advisories](https://embarkstudios.github.io/cargo-deny/checks/advisories/index.html)

The advisories check is used to detect issues for crates by looking in an advisory database.

```bash
cargo deny check advisories
```

#### [Sources](https://embarkstudios.github.io/cargo-deny/checks/sources/index.html)

The sources check ensures crates only come from sources you trust.

```bash
cargo deny check sources
```

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
