#[derive(Copy, Clone, Debug)]
pub enum MessageFormat {
    Human,
    Json,
}

impl std::str::FromStr for MessageFormat {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(MessageFormat::Json),
            "human" => Ok(MessageFormat::Human),
            s => failure::bail!("unknown message format {}", s),
        }
    }
}
