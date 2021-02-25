# The `fix` command

The fix command attempts to address advisories detected from one or more advisory databases by recursively applying patched versions of crates until it reaches your workspace members and edits one or more of them to reference the fixed version(s) so the advisories no longer apply.

Note that the larger the workspace and the more dependencies that are used within it, the higher the likelihood that the fix command will not be able to update completely to the fixed version of the crate, as every crate that transitively depends on the crate the advisory applies to needs to have a published version that depends on one more of the fixed versions, when the crate in question even has fixed versions at all.

## Flags

### `--allow-incompatible`

Allows crates to be patched with versions which are incompatible with the current version requirements. So, for example, if you have

```ini
[dependencies]
vulnerable-crate = "0.5"
```

and the vulnerability is fixed in version "1.0", the fix subcommand will be able to edit your manifest to be this

```diff
[dependencies]
- vulnerable-crate = "0.5"
+ vulnerable-crate = "1.0"
```

even though they are semver incompatible.

### `--dry-run`

Prints the diff for the manifest changes, but does not actually modify any files on disk

### `-d, --disable-fetch`

Disable fetching of the advisory database and crates.io index

By default the advisory database and crates.io index are updated before checking the advisories, if disabled via this flag, an error occurs if the advisory database or crates.io index are not available locally already.

## Options

### `-c, --config`

The path to the config file used to determine which crates are allowed or denied. Will default to `<context>/deny.toml` if not specified.
