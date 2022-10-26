# licenses

The licenses check is used to verify that every crate you use has license terms you find acceptable. cargo-deny does this by evaluating the license requirements specified by each crate against the [configuration](cfg.md) you've specified, to determine if your project meets that crate's license requirements.

```bash
cargo deny check licenses
```

## SPDX

cargo-deny uses [SPDX license expressions][SPDX] as the source of truth for the license requirements of a crate. Note however, that cargo-deny does **not** (currently)exhaustively search the entirety of the source code of every crate to find every possible license that could be attributed to the crate, as there are a ton of edge cases to that approach.

cargo-deny rather assumes that each crate correctly defines its license requirements, but it provides a mechanism for manually specifying the license requirements for crates in the, from our experience, rare circumstance that they cannot be gathered automatically.

### Expression Source Precedence

The source of the SPDX expression used to evaluate the crate by is obtained in the following order.

1. If the crate in question has a [Clarification](cfg.md#the-clarify-field-optional) applied to it, and the source file(s) in the crate's source still match, the expression from the clarification will be used.
1. The [`license`][cargo-md] field from the crate's Cargo.toml manifest will be used if it exists.
1. The [`license-file`][cargo-md] field, as well as **all** other `LICENSE(-*)?` files will be parsed to determine the SPDX license identifier, and then all of those identifiers will be joined with the `AND` operator, meaning that you must accept **all** of the licenses detected.

### Evaluation Precedence

Currently, the precedence for determining whether a particular license is accepted or rejected is as follows:

1. A license specified in the `deny` list is **always rejected**.
1. A license specified in the `allow` list is **always accepted**.
1. If the license is considered [copyleft](https://en.wikipedia.org/wiki/Copyleft), the
[`[licenses.copyleft]`](cfg.md#the-copyleft-field-optional) configuration determines its status
1. If the license is [OSI Approved](https://opensource.org/licenses) or [FSF Free/Libre](https://www.gnu.org/licenses/license-list.en.html), the [`[licenses.allow-osi-fsf-free]`](cfg.md#the-allow-osi-fsf-free-field-optional) configuration determines its status, if it is `neither` the check continues
1. If the license does not match any of the above criteria, the [`[licenses.default]`](cfg.md#the-default-field-optional) configuration determines its status

## Example output

![licenses output](../../output/licenses.svg)

[SPDX]: https://spdx.github.io/spdx-spec/appendix-IV-SPDX-license-expressions/
[cargo-md]: https://doc.rust-lang.org/cargo/reference/manifest.html#package-metadata
