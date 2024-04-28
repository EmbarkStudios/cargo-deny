# `TargetString`

**Type:** `string`

The [target triple](https://forge.rust-lang.org/release/platform-support.html) for the target
you wish to filter target specific dependencies with. If the target triple specified is **not**
one of the targets builtin to `rustc`, the configuration check for that target will be limited
to only the raw `[target.<target-triple>.dependencies]` style of target configuration, as `cfg()`
expressions require us to know the details about the target.


## Examples

- ```toml
  value = "x86_64-unknown-linux-gnu"
  ```
- ```toml
  value = "x86_64-pc-windows-msvc"
  ```
- ```toml
  value = "aarch64-apple-darwin"
  ```