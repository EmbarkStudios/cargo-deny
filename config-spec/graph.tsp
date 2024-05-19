import "@schemd/tsp";
using Schemd;

model Graph {
    /**
     * By default, cargo-deny will consider every single crate that is resolved by cargo, including
     * target specific dependencies e.g.
     *
     * ```toml
     * [target.x86_64-pc-windows-msvc.dependencies]
     * winapi = "0.3.8"
     *
     * [target.'cfg(target_os = "fuchsia")'.dependencies]
     * fuchsia-cprng = "0.1.1"
     * ```
     *
     * But unless you are actually targeting `x86_64-fuchsia` or `aarch64-fuchsia`, the `fuchsia-cprng` is
     * never actually going to be compiled or linked into your project, so checking it is pointless for you.
     *
     * The `targets` field allows you to specify one or more targets which you **actually** build for.
     * Every dependency link to a crate is checked against this list, and if none of the listed targets
     * satisfy the target constraint, the dependency link is ignored. If a crate has no dependency links
     * to it, it is not included into the crate graph that the checks are
     * executed against.
     */
    targets?: Target[];

    /**
     * Just as with the [`--exclude`](https://embarkstudios.github.io/cargo-deny/cli/common.html#--exclude-dev)
     * command line option, this field allows you to specify one or more [Package ID specifications](https://doc.rust-lang.org/cargo/commands/cargo-pkgid.html)
     * that will cause the crate(s) in question to be excluded from the crate graph that is used
     * for the operation you are performing.
     *
     * Note that excluding a crate is recursive, if any of its transitive dependencies are only referenced
     * via the excluded crate, they will also be excluded from the crate graph.
     */
    @examples(["some-crate@0.1.0"])
    exclude?: string[] = [];

    /**
     * If set to `true`, `--all-features` will be used when collecting metadata
     */
    `all-features`?: boolean = false;

    /**
     * If set to `true`, `--no-default-features` will be used when collecting metadata.
     */
    `no-default-features`?: boolean = false;

    /**
     * If set, and `--features` is not specified on the cmd line, these features
     * will be used when collecting metadata.
     */
    @examples(["some-feature"])
    features?: string[] = [];

    /**
     * If set to `true`, all `dev-dependencies`, even one for workspace crates, are not included
     * in the crate graph used for any of the checks. This option can also be enabled on cmd line
     * with `--exclude-dev` either [before](https://embarkstudios.github.io/cargo-deny/cli/common.html#--exclude-dev)
     * or [after](https://embarkstudios.github.io/cargo-deny/cli/check.html#--exclude-dev)
     * the `check` subcommand.
     */
    `exclude-dev`?: boolean = false;
}

union Target {
    String: TargetString,
    Advanced: TargetAdvanced,
}

/**
 * Advanced configurations to apply for the target triple
 */
@examples(
    [
        {
            triple: "aarch64-apple-darwin",
        },
        {
            triple: "x86_64-pc-windows-msvc",
            features: ["some-feature"],
        }
    ]
)
model TargetAdvanced {
    triple: TargetString;

    /**
     * Rust `cfg()` expressions support the [`target_feature = "feature-name"`](https://doc.rust-lang.org/reference/attributes/codegen.html#the-target_feature-attribute)
     * predicate, but at the moment, the only way to actually pass them when compiling is to use
     * the `RUSTFLAGS` environment variable. The `features` field allows you to specify 1 or more
     * `target_feature`s you plan to build with, for a particular target triple. At the time of
     * this writing, cargo-deny does not attempt to validate that the features you specify are
     * actually valid for the target triple, but this is [planned](https://github.com/EmbarkStudios/cfg-expr/issues/1).
     */
    features?: string[] = [];
}

/**
 * The [target triple](https://forge.rust-lang.org/release/platform-support.html) for the target
 * you wish to filter target specific dependencies with. If the target triple specified is **not**
 * one of the targets builtin to `rustc`, the configuration check for that target will be limited
 * to only the raw `[target.<target-triple>.dependencies]` style of target configuration, as `cfg()`
 * expressions require us to know the details about the target.
 */
@examples(
    [
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
        "aarch64-apple-darwin"
    ]
)
scalar TargetString extends string;
