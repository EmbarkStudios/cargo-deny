# Sources diagnostics

### `S001` - 'git' source is underspecified

A `git` source uses a specification that doesn't meet the minimum specifier
required by [`sources.required-git-spec`](cfg.md#the-required-git-spec-optional).

### `S002` - source explicitly allowed

A crate source is explicitly allowed by [`sources.allow-git`](cfg.md#the-allow-git-field-optional) or [`sources.allow-registry`](cfg.md#the-allow-registry-field-optional).

### `S003` - source allowed by organization allowance

A crate source was explicitly allowed by an entry in [`sources.allow-org`](cfg.md#the-allow-org-field-optional).

### `S004` - detected source not explicitly allowed

A crate source was not explicitly allowed.

### `S005` - allowed source was not encountered

An allowed source in [`sources.allow-git`](cfg.md#the-allow-git-field-optional)
or [`sources.allow-registry`](cfg.md#the-allow-registry-field-optional) was not
encountered.

### `S006` - allowed organization  was not encountered

An allowed source in [`sources.allow-org`](cfg.md#the-allow-org-field-optional)
was not encountered.
