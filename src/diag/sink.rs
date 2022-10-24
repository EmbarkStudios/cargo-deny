use super::Pack;

pub struct ErrorSink {
    pub overrides: Option<std::sync::Arc<DiagnosticOverrides>>,
    pub channel: super::PackChannel,
}

impl From<super::PackChannel> for ErrorSink {
    fn from(channel: super::PackChannel) -> Self {
        Self {
            overrides: None,
            channel,
        }
    }
}

impl ErrorSink {
    pub fn push(&mut self, pack: impl Into<Pack>) {
        let mut pack = pack.into();

        if let Some(overrides) = &self.overrides {
            for diag in &mut pack.diags {
                if let Some(new_severity) = diag
                    .diag
                    .code
                    .as_deref()
                    .map(|code| overrides.get(code, diag.diag.severity))
                {
                    diag.diag.severity = new_severity;
                }
            }
        }

        self.channel.send(pack).unwrap();
    }
}

use super::Severity;

/// Each diagnostic will have a default severity, but these can be overriden
/// by the user via the CLI so that eg. warnings can be made into errors on CI
pub struct DiagnosticOverrides {
    pub code_overrides: std::collections::BTreeMap<&'static str, Severity>,
    pub level_overrides: Vec<(Severity, Severity)>,
}

impl DiagnosticOverrides {
    #[inline]
    fn get(&self, name: &str, severity: Severity) -> Severity {
        let code_severity = self.code_overrides.get(name).copied();

        let severity = code_severity.unwrap_or(severity);

        self.level_overrides
            .iter()
            .find_map(|(input, output)| {
                if *input == severity {
                    Some(*output)
                } else {
                    None
                }
            })
            .unwrap_or(severity)
    }
}
