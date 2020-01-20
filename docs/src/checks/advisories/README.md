# advisories

The advisories check is used to detect issues for crates by looking in an
advisory database.

```bash
cargo deny check advisories
```

<img src="https://imgur.com/FK50XLb.png"/>

## Use Case - Detecting security vulnerabilities

Security vulnerabilities are generally considered "not great" by most people, 
luckily rust has a great
[advisory database](https://github.com/RustSec/advisory-db) which cargo-deny 
can use to check that you don't have any crates with (known) security 
vulnerabilities.

The database can be changed to use your own as well, as long as it follows the
same format.

## Use Case - Detecting unmaintained crates

The [advisory database](https://github.com/RustSec/advisory-db) also contains 
advisories for unmaintained crates, which in most cases users will want to 
avoid in favor of more actively maintained crates.
