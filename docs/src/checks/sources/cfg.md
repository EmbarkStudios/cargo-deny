# The `[sources]` section

Contains all of the configuration for `cargo deny check sources`

## Example Config

```ini
{{#include ../../../../tests/cfg/sources.toml}}
```

### The `unknown-registry` field (optional)

Determines what happens when a crate from a crate registry that is not in the `allow-registry` list is encountered.

* `deny` - Will emit an error with the URL of the source, and fail the check.
* `warn` (default) - Prints a warning for each crate, but does not fail the check.
* `allow` - Prints a note for each crate, but does not fail the check.

### The `unknown-git` field (optional)

Determines what happens when a crate from a git repository not in the `allow-git` list is encountered.

* `deny` - Will emit an error with the URL of the repository, and fail the check.
* `warn` (default) - Prints a warning for each crate, but does not fail the check.
* `allow` - Prints a note for each crate, but does not fail the check.

### The `required-git-spec` (optional)

Determines which [specifiers](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories) are required for git sources. Git sources are a convient way to use patched code temporarily, but they have downsides for long term maintenance, as the specifier you use for the source determines what happens when you do a `cargo update`, and in the default case, this means you essentially have a wildcard dependency on the repository.

This configuration value allows you to control what specifiers you want to allow for your git sources to reduce surprises. The following values are listed in order from least to most specific, and using a less specific specifier will also allow all of the more specific ones.

* `any` (default) - Allows all git specs, including the default of not having
any specifier, which tracks the latest commit on the `master` branch of the repo
* `branch` - Allows the `branch = "<branch_name>"` specifier.
* `tag` - Allows the `tag = "<tag_name>"` specifier.
* `rev` - Allows the `rev = "<commit_sha>"` specifier.

### The `allow-git` field (optional)

Configure which git urls are allowed for crate sources. If a crate's source is not in one of the listed urls, then the `unknown-git` setting will determine how it is handled.

### The `allow-registry` field (optional)

The list of registries that are allowed. If a crate is not found in one of the listed registries, then the `unknown-registry` setting will determine how it is handled.

If not specified, this list will by default contain the [crates.io](http://crates.io) registry, equivalent to this:

```ini
[sources]
allow-registry = [
    "https://github.com/rust-lang/crates.io-index"
]
```

To not allow any crates registries, set it to empty:

```ini
[sources]
unknown-registry = "deny"
allow-registry = []
```

### The `allow-org` field (optional)

Generally, I think most projects in the Rust space probably follow a similar procedure as we do when they want to fix a bug or add a feature to one of their dependencies, which is basically.

1. Fork the crate to make your changes
1. Hack away locally, probably just patching your project(s) to use a `path` dependency to the cloned fork
1. Push changes to your fork, and once you're happy, change the `path` dependency to a `git` dependency and point it to your fork for others/CI to be able to use the same changes easily
1. Eventually (hopefully!) make a PR to the original repo with your changes
1. Hopefully get your changes merged to the original repo
1. Wait until a release is made that incorporates your changes, possibly changing the `git` source to point to the original repo
1. Remove the `git` source and instead point at the new version of the crate with your changes
1. Profit!

When working in a company or organization, it is often the case that all crates will be forked to a shared organization account rather than a personal Github account. However, if you lint your git sources, every new and deleted fork needs to keep that list updated, which is tedious, even if all the forks fall under the same organization (in Github terminology), even though presumably only people you trust have permission to create forks there, and you would like to just blanket trust any repo under that org.

The `allow-org` object allows you to specify 1 or more orgs in several VCS providers to more easily configure git sources for your projects.

#### The `github` field (optional)

Allows you to specify one or more `github.com` organizations to allow as git sources.

```ini
[sources.allow-org]
github = ["YourCoolOrgGoesHere"]
```

#### The `gitlab` field (optional)

Allows you to specify one or more `gitlab.com` organizations to allow as git sources.

```ini
[sources.allow-org]
gitlab = ["YourCoolOrgGoesHere"]
```

#### The `bitbucket` field (optional)

Allows you to specify one or more `bitbucket.org` organizations to allow as git sources.

```ini
[sources.allow-org]
bitbucket = ["YourCoolOrgGoesHere"]
```
