# `PackageSpec`

**Type:** `string`

Many configuration options require a package specifier at a minimum, which we'll describe here.
The options that use package specifiers will be called out in their individual documentation.
We'll use the [`bans.deny`](bans/cfg.md#the-deny-field-optional) option in the following examples.

### String format

If the particular only requires a package spec at a minimum, then the string format can be used,
which comes in three forms.

#### Simple

```toml
# Will match any version of the simple crate
deny = ["simple"]
```

The simplest string is one which is just the crate name. In this case, the version requirement
used when checking will be `*` meaning it will match against all versions of that crate in the graph.

#### With Version Requirements

```toml
# Will match only these versions of the simple crate that match the predicate(s)
deny = ["simple:<=0.1,>0.2"]
```

If you want to apply version requirements (predicates) to the crate, simply append them following
a `:` separator.

#### Exact

```toml
# Will match only this exact version of the simple crate
deny = [
    "simple@0.1.0",
    # This is semantically equivalent to the above
    "simple:=0.1.0",
]
```

The exact form is a specialization of the version requirements, where the semver after the `@`
is transformed to be [= (Exact)](https://docs.rs/semver/latest/semver/enum.Op.html#opexact).

### Table format

#### Crate format

```toml
deny = [
    { crate = "simple@0.1.0" }, # equivalent to "simple@0.1.0"
    { crate = "simple", wrappers = ["example"] },
]
```

The crate format is a replacement for the old `name` and/or `version` table format. It uses
the string format described above in a single `crate` key.

#### Old format

```toml
deny = [
    { name = "simple" },
    { name = "simple", version = "*" },
    { name = "simple", wrappers = ["example"] }
]
```

The old format uses a required `name` key and an optional `version` key. This format is deprecated
and should not be used.
