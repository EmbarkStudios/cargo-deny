# `TargetAdvanced`

**Type:** `object`

Advanced configurations to apply for the target triple

## Examples

- ```toml
  triple = "aarch64-apple-darwin"
  ```
- ```toml
  triple = "x86_64-pc-windows-msvc"
  features = ["some-feature"]
  ```

## `triple`

**Type:** [`TargetString`](/checks2/schema/type-index/TargetString.md) `string`<br>
**Key:** `required`

## `features`

**Type:** `string`<br>
**Key:** `optional`

Rust `cfg()` expressions support the [`target_feature = "feature-name"`](https://doc.rust-lang.org/reference/attributes/codegen.html#the-target_feature-attribute)
predicate, but at the moment, the only way to actually pass them when compiling is to use
the `RUSTFLAGS` environment variable. The `features` field allows you to specify 1 or more
`target_feature`s you plan to build with, for a particular target triple. At the time of
this writing, cargo-deny does not attempt to validate that the features you specify are
actually valid for the target triple, but this is [planned](https://github.com/EmbarkStudios/cfg-expr/issues/1).
