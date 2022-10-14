use super::Pack;

pub struct ErrorSink {
    pub overrides: Option<std::sync::Arc<super::DiagnosticOverrides>>,
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
