use crate::LintLevel;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(default = "crate::lint_allow")]
    pub custom_builds: LintLevel,

    #[serde(default = "crate::lint_allow")]
    pub proc_macros: LintLevel,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            custom_builds: LintLevel::Allow,
            proc_macros: LintLevel::Allow,
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
            custom_builds: self.custom_builds,
            proc_macros: self.proc_macros,
        })
    }
}

pub struct ValidConfig {
    pub file_id: codespan::FileId,

    pub custom_builds: LintLevel,
    pub proc_macros: LintLevel,
}
