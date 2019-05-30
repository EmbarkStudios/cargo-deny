use semver::VersionReq;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CrateId {
    // The name of the crate
    pub name: String,
    /// The version constraints of the crate
    pub version: Option<VersionReq>,
}

#[derive(Deserialize)]
pub struct Config {
    /// The crates that will cause us to emit failures
    #[serde(default)]
    pub deny: Vec<CrateId>,
    /// If specified, means only the listed crates are allowed
    #[serde(default)]
    pub allow: Vec<CrateId>,
}

impl Config {
    pub fn sort(&mut self) {
        self.deny.sort_by(|a, b| match a.name.cmp(&b.name) {
            std::cmp::Ordering::Equal => a.version.cmp(&b.version),
            o => o,
        });
        self.allow.sort_by(|a, b| match a.name.cmp(&b.name) {
            std::cmp::Ordering::Equal => a.version.cmp(&b.version),
            o => o,
        });
    }
}

// pub fn check_bans(log: slog::Logger, crates: &[crate::CrateDetails]) -> Result<(), Error> {
//     for crat in crates {
//         if binary_search(self.deny, )
//     }
// }
