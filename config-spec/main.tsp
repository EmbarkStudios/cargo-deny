import "@typespec/json-schema";
import "@schemd/tsp";

import "./advisories.tsp";
import "./bans.tsp";
import "./graph.tsp";
import "./output.tsp";

using TypeSpec.JsonSchema;
using Schemd;

/**
 * Full documentation is at https://embarkstudios.github.io/cargo-deny/checks/cfg.html
 */
@summary("Configuration file for cargo-deny, by default called `deny.toml`")
@jsonSchema("https://github.com/EmbarkStudios/cargo-deny/config-spec")
@schemdSchema
model CargoDenyConfig {
    /**
     * Checks advisory databases for crates with security vulnerabilities,
     * or that have been marked as unmaintained, or which have been yanked from
     * their source registry.
     *
     * This section is considered when running `cargo deny check advisories`.
     */
    advisories?: Advisories;

    /**
     * Checks for specific crates in your graph, as well as duplicates.
     *
     * This section is considered when running `cargo deny check bans`.
     */
    bans?: Bans;

    /**
     * The graph table configures how the dependency graph is constructed and thus which crates the
     * checks are performed against
     */
    graph?: Graph;

    /**
     * The output table provides options for how/if diagnostics are outputted
     */
    output?: Output;
}
