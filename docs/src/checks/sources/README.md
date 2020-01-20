# sources

The sources check ensures crates only come from sources you trust.

```bash
cargo deny check sources
```

<img src="https://imgur.com/xdHFDWS.png"/>

## Use Case - Only allowing known/trusted sources

Cargo can retrieve crates from a variety of sources, namely registries, 
git repositories, or local file paths. This is great in general and very 
flexible for development. But esp. re-routing dependencies to git repositories 
increases the amount of sources that one would have to trust and may be 
something a repository want explicitly opt-in to. 

See [Why npm lockfiles can be a security blindspot for injecting malicious modules](https://snyk.io/blog/why-npm-lockfiles-can-be-a-security-blindspot-for-injecting-malicious-modules/)
for the motivating reason for why this check was added.

## Use Case - Only using vendored file dependencies

A crate repository may want to only support local file dependencies, such as 
having all dependencies vendored into the repository for full control and 
offline building.
