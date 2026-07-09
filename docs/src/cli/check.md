# The `check` command

The check command is the primary subcommand of cargo-deny as it is what actually runs through all of the crates in your project and checks them against your configuration.

## Args

### `<WHICH>`

The check(s) to perform. By default, **all** checks will be performed, unless one or more checks are specified here.

See [checks](../checks/index.html) for the list of available checks.

## Options

### `-A, --allow <ALLOW>`

Set lint allowed.

```shell
$ cargo run -- --manifest-path tests/test_data/duplicates/Cargo.toml check bans
error[duplicate]: found 2 duplicate entries for crate 'webpki-roots'
    ┌─ /home/jake/code/cargo-deny/tests/test_data/duplicates/Cargo.lock:138:1
    │
138 │ ╭ webpki-roots 0.25.4 registry+https://github.com/rust-lang/crates.io-index
139 │ │ webpki-roots 0.26.11 registry+https://github.com/rust-lang/crates.io-index
    │ ╰──────────────────────────────────────────────────────────────────────────┘ lock entries
    │
    ├ webpki-roots v0.25.4
      └── minreq v2.13.4
          └── duplicates v0.1.0
    ├ webpki-roots v0.26.11
      └── duplicates v0.1.0

bans FAILED
$ cargo run -- --manifest-path tests/test_data/duplicates/Cargo.toml check -A duplicate bans
bans ok
```

### `--audit-compatible-output`

To ease transition from cargo-audit to cargo-deny, this flag will tell cargo-deny to output the exact same output as cargo-audit would, to `stdout` instead of `stderr`, just as with cargo-audit.

Note that this flag only applies when the output format is JSON, and note that since cargo-deny supports multiple advisory databases, instead of a single JSON object, there will be 1 for each unique advisory database.

### `-D, --deny <DENY>`

Set lint denied.

```shell
$ cargo run -- --manifest-path tests/test_data/duplicates/Cargo.toml check -A duplicate bans
warning[unmatched-skip-root]: skip tree root was not found in the dependency graph
   ┌─ deny.toml:35:16
   │
35 │     { crate = "windows-sys", reason = "a foundational crate for many that bumps far too frequently to ever have a shared version" },
   │                ━━━━━━━━━━━ no crate matched these criteria

warning[unmatched-skip]: skipped crate 'getrandom = =0.2.17' was not encountered
   ┌─ deny.toml:31:16
   │
31 │     { crate = "getrandom@0.2.17", reason = "ring uses this old version" },
   │                ━━━━━━━━━━━━━━━━             ────────────────────────── reason
   │                │
   │                unmatched skip configuration

warning[unmatched-skip]: skipped crate 'hashbrown = =0.15.5' was not encountered
   ┌─ deny.toml:32:16
   │
32 │     { crate = "hashbrown@0.15.5", reason = "petgraph uses this old version" },
   │                ━━━━━━━━━━━━━━━━             ────────────────────────────── reason
   │                │
   │                unmatched skip configuration

bans ok
$ cargo run -- --manifest-path tests/test_data/duplicates/Cargo.toml check -A duplicate -D unmatched-skip bans
warning[unmatched-skip-root]: skip tree root was not found in the dependency graph
   ┌─ deny.toml:35:16
   │
35 │     { crate = "windows-sys", reason = "a foundational crate for many that bumps far too frequently to ever have a shared version" },
   │                ━━━━━━━━━━━ no crate matched these criteria

error[unmatched-skip]: skipped crate 'getrandom = =0.2.17' was not encountered
   ┌─ deny.toml:31:16
   │
31 │     { crate = "getrandom@0.2.17", reason = "ring uses this old version" },
   │                ━━━━━━━━━━━━━━━━             ────────────────────────── reason
   │                │
   │                unmatched skip configuration

error[unmatched-skip]: skipped crate 'hashbrown = =0.15.5' was not encountered
   ┌─ deny.toml:32:16
   │
32 │     { crate = "hashbrown@0.15.5", reason = "petgraph uses this old version" },
   │                ━━━━━━━━━━━━━━━━             ────────────────────────────── reason
   │                │
   │                unmatched skip configuration

bans FAILED
```

### `--feature-depth <FEATURE_DEPTH>`

Specifies the depth at which feature edges are added in inclusion graphs

### `-g, --graph <GRAPH>`

Path to graph_output root directory

If set, a dotviz graph will be created for whenever multiple versions of the same crate are detected.

Each file will be created at `<dir>/graph_output/<crate_name>.dot`. `<dir>/graph_output/*` is deleted and recreated each run.

### `--hide-inclusion-graph`

Hides the inclusion graph when printing out info for a crate

By default, if a diagnostic message pertains to a specific crate, cargo-deny will append an inverse dependency graph to the diagnostic to show you how that crate was pulled into your project.

```text
some diagnostic message

the-crate
├── a-crate
└── b-crate
    └── c-crate
```

### `-s, --show-stats`

Show stats for all the checks, regardless of the log-level

### `-W, --warn <WARN>`

Set lint warned.

```shell
$ cargo run -- --manifest-path tests/test_data/duplicates/Cargo.toml check bans
error[duplicate]: found 2 duplicate entries for crate 'webpki-roots'
    ┌─ /home/jake/code/cargo-deny/tests/test_data/duplicates/Cargo.lock:138:1
    │
138 │ ╭ webpki-roots 0.25.4 registry+https://github.com/rust-lang/crates.io-index
139 │ │ webpki-roots 0.26.11 registry+https://github.com/rust-lang/crates.io-index
    │ ╰──────────────────────────────────────────────────────────────────────────┘ lock entries
    │
    ├ webpki-roots v0.25.4
      └── minreq v2.13.4
          └── duplicates v0.1.0
    ├ webpki-roots v0.26.11
      └── duplicates v0.1.0

bans FAILED
$ cargo run -- --manifest-path tests/test_data/duplicates/Cargo.toml check -W duplicate bans
warning[duplicate]: found 2 duplicate entries for crate 'webpki-roots'
    ┌─ /home/jake/code/cargo-deny/tests/test_data/duplicates/Cargo.lock:138:1
    │
138 │ ╭ webpki-roots 0.25.4 registry+https://github.com/rust-lang/crates.io-index
139 │ │ webpki-roots 0.26.11 registry+https://github.com/rust-lang/crates.io-index
    │ ╰──────────────────────────────────────────────────────────────────────────┘ lock entries
    │
    ├ webpki-roots v0.25.4
      └── minreq v2.13.4
          └── duplicates v0.1.0
    ├ webpki-roots v0.26.11
      └── duplicates v0.1.0

bans ok
```

## Exit Codes

As of [0.14.1](https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.14.1), the exit code for the check command is a bitset of the checks that were executed that had 1 or more errors.

A script or program can use the following values to determine exactly which check(s) failed.

- `advisories` - `0x1`
- `bans` - `0x2`
- `licenses` - `0x4`
- `sources` - `0x8`
