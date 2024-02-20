use crate::{
    advisories::cfg::Config as AdvisoriesConfig, bans::cfg::Config as BansConfig,
    licenses::cfg::Config as LicensesConfig, sources::cfg::Config as SourcesConfig, Spanned,
};
use toml_span::{
    de_helpers::TableHelper,
    value::{Value, ValueInner},
    DeserError, Deserialize,
};

pub struct Target {
    pub filter: Spanned<krates::Target>,
    pub features: Vec<String>,
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let (triple, features) = match value.take() {
            ValueInner::String(s) => (Spanned::with_span(s, value.span), Vec::new()),
            ValueInner::Table(tab) => {
                let mut th = TableHelper::from((tab, value.span));
                let triple = th.required("triple")?;
                let features = th.optional("features").unwrap_or_default();
                th.finalize(None)?;

                (triple, features)
            }
            other => {
                return Err(
                    toml_span::de_helpers::expected("a string or table", other, value.span).into(),
                )
            }
        };

        Ok(Self {
            filter: triple.map(),
            features,
        })
    }
}

#[derive(Default)]
pub struct GraphConfig {
    pub targets: Vec<Target>,
    pub exclude: Vec<String>,
    pub features: Vec<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    /// By default, dev dependencies for workspace crates are not ignored
    pub exclude_dev: bool,
}

impl<'de> Deserialize<'de> for GraphConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let targets = th.optional("targets").unwrap_or_default();
        let exclude = th.optional("exclude").unwrap_or_default();
        let features = th.optional("features").unwrap_or_default();
        let all_features = th.optional("all-features").unwrap_or_default();
        let no_default_features = th.optional("no-default-features").unwrap_or_default();
        let exclude_dev = th.optional("exclude-dev").unwrap_or_default();
        th.finalize(None)?;

        Ok(Self {
            targets,
            exclude,
            features,
            all_features,
            no_default_features,
            exclude_dev,
        })
    }
}

#[derive(Default)]
pub struct OutputConfig {
    pub feature_depth: Option<u32>,
}

impl<'de> Deserialize<'de> for OutputConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;
        let feature_depth = th.optional("feature-depth");
        th.finalize(None)?;
        Ok(Self { feature_depth })
    }
}

pub struct RootConfig {
    pub advisories: Option<AdvisoriesConfig>,
    pub bans: Option<BansConfig>,
    pub licenses: Option<LicensesConfig>,
    pub sources: Option<SourcesConfig>,
    pub graph: GraphConfig,
    pub output: OutputConfig,
    // Bit ugly but we keep track of usage of deprecated options until they
    // are removed
    pub graph_deprecated: Vec<crate::Span>,
    pub output_deprecated: Option<crate::Span>,
}

impl<'de> Deserialize<'de> for RootConfig {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let mut th = TableHelper::new(value)?;

        let advisories = th.optional("advisories");
        let bans = th.optional("bans");
        let licenses = th.optional("licenses");
        let sources = th.optional("sources");

        let mut graph: GraphConfig = th.optional("graph").unwrap_or_default();

        fn deser<'de, T>(v: &mut Value<'de>, errors: &mut Vec<toml_span::Error>) -> T
        where
            T: Deserialize<'de> + Default,
        {
            match T::deserialize(v) {
                Ok(v) => v,
                Err(mut err) => {
                    errors.append(&mut err.errors);
                    T::default()
                }
            }
        }

        let graph_deprecated = {
            let mut gd = Vec::new();

            macro_rules! dep {
                ($name:literal, $field:ident) => {
                    if let Some((k, mut v)) = th.take($name) {
                        gd.push(k.span);
                        graph.$field = deser(&mut v, &mut th.errors);
                    }
                };
            }

            dep!("targets", targets);
            dep!("exclude", exclude);
            dep!("features", features);
            dep!("all-features", all_features);
            dep!("no-default-features", no_default_features);
            dep!("exclude-dev", exclude_dev);

            gd
        };

        let mut output: OutputConfig = th.optional("output").unwrap_or_default();
        let output_deprecated = if let Some((key, mut v)) = th.take("feature-depth") {
            output.feature_depth = Some(deser(&mut v, &mut th.errors));
            Some(key.span)
        } else {
            None
        };

        th.finalize(None)?;

        Ok(Self {
            advisories,
            bans,
            licenses,
            sources,
            graph,
            graph_deprecated,
            output,
            output_deprecated,
        })
    }
}
