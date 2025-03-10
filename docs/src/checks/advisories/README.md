# advisories

The advisories check is used to detect issues for crates by looking in an advisory database.

```bash
cargo deny check advisories
```

## Use Case - Detecting security vulnerabilities

Security vulnerabilities are generally considered "not great" by most people, luckily, Rust has a great [advisory database](https://github.com/RustSec/advisory-db) which cargo-deny can use to check that you don't have any crates with (known) security vulnerabilities.

You can also use your own advisory databases instead of, or in addition to, the above default, as long as it follows the same format.

## Use Case - Detecting unmaintained crates

The [advisory database](https://github.com/RustSec/advisory-db) also contains advisories for unmaintained crates, which in most cases users will want to avoid in favor of more actively maintained crates. By default, all `unmaintained` advisories will result in an error, but by using the following config you can error only if you directly depend on an unmaintained crate from your workspace.

```ini
[advisories]
unmaintained = 'workspace'
```

## Example output

![advisories output](../../output/advisories.svg)
