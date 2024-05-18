import "@typespec/json-schema";
import "./schemd.tsp";
import "./package-spec.tsp";

using JsonSchema;
using Schemd;

@examples(
    [
        {
            `db-path`: "~/.cargo/advisory-dbs",
            `db-urls`: ["https://github.com/RustSec/advisory-db"],
            vulnerability: "deny",
            unmaintained: "warn",
            unsound: "warn",
            yanked: "warn",
            notice: "warn",
            ignore: [
                "RUSTSEC-0000-0000",
                "crate@0.1",
                {
                    crate: "yanked",
                    reason: "a new version has not been released",
                }
            ],
            `severity-threshold`: "medium",
        }
    ]
)
model Advisories {
    /**
     * URLs to one or more advisory databases.
     */
    `db-urls`?: url[] = ["https://github.com/RustSec/advisory-db"];

    /**
     * Path to the root directory into which one or more advisory databases are cloned into.
     *
     * This value supports basic shell expansion:
     *
     * - `~` - Expands to [`home::home_dir`](https://docs.rs/home/latest/home/fn.home_dir.html)
     * - `$VARNAME` - Expands to [`std::env::var("VARNAME")`](https://doc.rust-lang.org/std/env/fn.var.html)
     * - `${VARNAME}` - Expands to [`std::env::var("VARNAME")`](https://doc.rust-lang.org/std/env/fn.var.html)
     * - `${VARNAME:-fallback}` - Expands to [`std::env::var("VARNAME")`](https://doc.rust-lang.org/std/env/fn.var.html)
     *   or the fallback value if it doesn't exist (everything between the `:-` and `}`)
     * - `$CARGO_HOME` - Expands to [`std::env::var("CARGO_HOME")`](https://doc.rust-lang.org/std/env/fn.var.html)
     *   if it exists, otherwise expands to `$(home::home_dir())/.cargo`
     *
     * Note that the path must be valid utf-8, after expansion.
     */
    `db-path`?: string = "$CARGO_HOME/advisory-dbs";

    /**
     * The advisories section has an upcoming breaking change, with deprecation warnings for several
     * fields that will be removed. Setting `version = 2` will opt-in to the future default behavior.
     *
     * The breaking change is as follows:
     *
     * - `vulnerability` - Removed, all vulnerability advisories now emit errors.
     * - `unmaintained` - Removed, all unmaintained advisories now emit errors.
     * - `unsound` - Removed, all unsound advisories now emit errors.
     * - `notice` - Removed, all notice advisories now emit errors.
     * - `severity-threshold` - Removed, all vulnerability advisories now emit errors.
     *
     * As before, if you want to ignore a specific advisory, add it to the `ignore` field.
     */
    version?: 2;

    /**
     * Determines what happens when a crate with a security vulnerability is encountered.
     */
    #deprecated "see `version` field"
    vulnerability?: LintLevel = LintLevel.deny;

    /**
     * Determines what happens when a crate with an `unmaintained` advisory is encountered.
     */
    #deprecated "see `version` field"
    unmaintained?: LintLevel = LintLevel.warn;

    /**
     * Determines what happens when a crate with an `unsound` advisory is encountered.
     */
    #deprecated "see `version` field"
    unsound?: LintLevel = LintLevel.warn;

    /**
     * Determines what happens when a crate with a `notice` advisory is encountered.
     *
     * **NOTE**: As of 2019-12-17 there are no `notice` advisories in the
     * [RustSec Advisory DB](https://github.com/RustSec/advisory-db)
     */
    #deprecated "see `version` field"
    notice?: LintLevel = LintLevel.warn;

    /**
     * Determines what happens when a crate with a version that has been yanked from its source
     * registry is encountered.
     */
    yanked?: LintLevel = LintLevel.warn;

    /**
     * Every advisory in the advisory database contains a unique identifier, eg. `RUSTSEC-2019-0001`.
     * Putting an identifier in this array will cause the advisory to be treated as a note, rather
     * than a warning or error.
     *
     * In addition, yanked crate versions can be ignored by specifying a
     * [PackageSpec](https://embarkstudios.github.io/cargo-deny/checks/cfg.html#package-spec)
     * with an optional `reason`.
     */
    @examples(
        [
            [
                "RUSTSEC-0000-0000",
                {
                    id: "RUSTSEC-0000-0000",
                    reason: "this vulnerability does not affect us as we don't use the particular code path",
                },
                "yanked@0.1.1",
                {
                    crate: "yanked-crate@0.1.1",
                },
                {
                    reason: "a semver compatible version hasn't been published yet",
                }
            ]
        ]
    )
    ignore?: AdvisoriesIgnoreItem[] = [];
}

union AdvisoriesIgnoreItem {
    /**
     * Either an advisory ID (e.g. `RUSTSEC-2019-0001`) or a package spec (e.g. `yanked@0.1.1`)
     */
    @doc("goo")
    @summary("bruh")
    String: string,

    @docHeader("Ignore an advisory")
    Advisory: AdvisoriesIgnoreAdvisory,

    @docHeader("Ignore a yanked crate version")
    @extension("foo", Json<"bruh">)
    Yanked: AdvisoriesIgnoreYanked,
}

model AdvisoriesIgnoreAdvisory {
    /**
     * The unique identifier of the advisory to ignore
     */
    @examples(["RUSTSEC-2019-0001"])
    id: string;

    @docInline
    reason?: IgnoreReason;
}

model AdvisoriesIgnoreYanked {
    /**
     * The yanked crate version to ignore.
     */
    crate: PackageSpec;
    reason?: IgnoreReason;
}

/**
 * Free-form string that can be used to describe the reason why the advisory is ignored.
 */
scalar IgnoreReason extends string;

enum LintLevel {
    /**
     * Emit an error with details about the problem, and fail the check.
     */
    deny,

    /**
     * Print a warning for each propblem, but don't fail the check.
     */
    warn,

    /**
     * Print a note about the problem, but don't fail the check.
     */
    allow,
}
