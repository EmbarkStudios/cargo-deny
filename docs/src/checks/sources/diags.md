# Sources diagnostics

### `git-source-underspecified`

A `git` source uses a specification that doesn't meet the minimum specifier required by [`sources.required-git-spec`](cfg.md#the-required-git-spec-optional).

### `allowed-source`

A crate source is explicitly allowed by [`sources.allow-git`](cfg.md#the-allow-git-field-optional) or [`sources.allow-registry`](cfg.md#the-allow-registry-field-optional).

### `allowed-by-organization`

A crate source was explicitly allowed by an entry in [`sources.allow-org`](cfg.md#the-allow-org-field-optional).

### `source-not-allowed`

A crate's source was not explicitly allowed.

### `unmatched-source`

An allowed source in [`sources.allow-git`](cfg.md#the-allow-git-field-optional) or [`sources.allow-registry`](cfg.md#the-allow-registry-field-optional) was not encountered.

### `unmatched-organization`

An allowed source in [`sources.allow-org`](cfg.md#the-allow-org-field-optional) was not encountered.
