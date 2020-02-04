# sources

The sources check ensures crates only come from sources you trust.

```bash
cargo deny check sources
```

<img src="https://imgur.com/xdHFDWS.png"/>

## Use Case - Only allowing known/trusted sources

Cargo can retrieve crates from a variety of sources, namely registries, git 
repositories, or local file paths. This is great in general and very flexible 
for development. But, especially when re-routing dependencies to git 
repositories, increasing the amount of sources that a project has to trust may
be something a repository wants to explicitly opt-in to.

See [Why npm lockfiles can be a security blindspot for injecting malicious 
modules](https://snyk.io/blog/why-npm-lockfiles-can-be-a-security-blindspot-for-injecting-malicious-modules/)
for the motivating reason for why this check was added.

## Use Case - Only using vendored file dependencies

A project may want to only support local file dependencies, such as having all 
dependencies vendored into the repository for full control and offline building.
This can be achieved by disallowing all git and registry sources to ensure that
every dependency is added into your source control rather than via an external
source.
