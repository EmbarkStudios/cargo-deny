# Sources diagnostics

<!-- markdownlint-disable-next-line heading-increment -->

### `git-source-underspecified`

A `git` source uses a specification that doesn't meet the minimum specifier required by [`sources.required-git-spec`](cfg.md#required-git-spec).

### `allowed-source`

A crate source is explicitly allowed by [`sources.allow-git`](cfg.md#allow-git) or [`sources.allow-registry`](cfg.md#allow-registry).

### `allowed-by-organization`

A crate source was explicitly allowed by an entry in [`sources.allow-org`](cfg.md#allow-org).

### `source-not-allowed`

A crate's source was not explicitly allowed.

### `unmatched-source`

An allowed source in [`sources.allow-git`](cfg.md#allow-git) or [`sources.allow-registry`](cfg.md#allow-registry) was not encountered.

This diagnostic can be silenced by configuring the [`sources.unused-allowed-source`](cfg.md#unused-allowed-source) field to "allow".

### `unmatched-organization`

An allowed source in [`sources.allow-org`](cfg.md#allow-org) was not encountered.
