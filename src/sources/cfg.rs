use crate::LintLevel;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(default = "crate::lint_warn")]
    pub unknown_registry: LintLevel,

    #[serde(default = "crate::lint_warn")]
    pub unknown_git: LintLevel,

    //    #[serde(default = "crate::lint_warn")]
    //    pub missing_git_revision: LintLevel,
    #[serde(default = "default_allow_registry")]
    pub allow_registry: Vec<String>,

    #[serde(default)]
    pub allow_git: Vec<String>,
}

fn default_allow_registry() -> Vec<String> {
    vec!["https://github.com/rust-lang/crates.io-index".to_owned()]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            unknown_registry: LintLevel::Warn,
            unknown_git: LintLevel::Warn,
            allow_registry: Vec::new(),
            allow_git: Vec::new(),
        }
    }
}

impl Config {
    pub fn validate(
        self,
        cfg_file: codespan::FileId,
    ) -> Result<ValidConfig, Vec<crate::diag::Diagnostic>> {
        Ok(ValidConfig {
            file_id: cfg_file,
            unknown_registry: self.unknown_registry,
            unknown_git: self.unknown_git,
            allow_registry: self.allow_registry,
            allow_git: self.allow_git,
        })
    }
}

pub struct ValidConfig {
    pub file_id: codespan::FileId,

    pub unknown_registry: LintLevel,
    pub unknown_git: LintLevel,
    pub allow_registry: Vec<String>,
    pub allow_git: Vec<String>,
}
