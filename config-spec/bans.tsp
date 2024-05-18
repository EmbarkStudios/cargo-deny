import "./schemd.tsp";
import "./package-spec.tsp";

model Bans {
  /**
   * Determines specific crates that are allowed. If the `allow` list has one or more entries, then
   * any crate not in that list will be denied, so use with care. Each entry uses the same
   * [PackageSpec](https://embarkstudios.github.io/cargo-deny/checks/cfg.html#package-spec)
   * as other parts of cargo-deny's configuration.
   */
  allow?: PackageSpec[] = [];
}
