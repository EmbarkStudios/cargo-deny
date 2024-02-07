# licenses

The licenses check is used to verify that every crate you use has license terms you find acceptable. cargo-deny does this by evaluating the license requirements specified by each crate against the [configuration](cfg.md) you've specified, to determine if your project meets that crate's license requirements.

```bash
cargo deny check licenses
```

## SPDX

cargo-deny uses [SPDX license expressions][SPDX] to interpret the license requirements of a crate. In the event that it cannot obtain an SPDX license expression directly from metadata, it tries to
derive such within the confidence threshold you specify. Note that cargo-deny currently does **not** exhaustively search the entirety of the source code of every crate to find every possible license that could be attributed to the crate. There are many edge cases to that approach, and human ingenuity, or even human error, can always outwit a statically-compiled program.

cargo-deny makes a good-faith assumption each crate correctly defines its license requirements. In the (in our experience, rare) circumstance such data cannot be gathered automatically, it provides a mechanism for manually specifying the license requirements for crates.

### Expression Source Precedence

The source of the SPDX expression used to evaluate the crate's licensing requirement is obtained in the following order:

1. If the crate in question has a [Clarification](cfg.md#the-clarify-field-optional) applied to it, and the source file(s) in the crate's source still match, the expression from the clarification will be used.
1. The [`license`][cargo-md] field from the crate's Cargo.toml manifest will be used if it exists.
1. The [`license-file`][cargo-md] field, as well as **all** other `LICENSE(-*)?` files will be parsed to determine the SPDX license identifier, and then all of those identifiers will be joined with the `AND` operator, meaning that you must accept **all** of the licenses detected.

*Importantly*, this precedence, combined with the trust that licensing data is handled correctly, means the following edge cases are **not** handled. This is not an exhaustive list, but are rather a sample of the kinds of things a program is not able to completely prevent, even if more checks are added:

1. **Absences**: If the package contains inadequate licensing data, in e.g. the event of a crate not reflecting the license of code it is linked with.
1. **Mismatches:** If the Cargo.toml documents a given SPDX expression that does not match the actual license files in the package, this is not checked.
1. **Inventiveness**: It is possible to place licensing data somewhere that is not in these locations, or have names that start with things other than `LICENSE`. There is no guarantee such placements inside a package would lose their legal force, even if there is other licensing data that cargo-deny may detect first and assume is comprehensive.

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
