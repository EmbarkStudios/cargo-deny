mod package_spec;
pub mod toml;

pub use package_spec::{ConfigWithSpec, EmbeddedSpec, PackageSpec, PackageSpecOrExtended};

use crate::diag;
use serde::{de, ser};
use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    #[inline]
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start == 0 && self.end == 0
    }
}

impl From<Span> for (usize, usize) {
    fn from(Span { start, end }: Span) -> (usize, usize) {
        (start, end)
    }
}

impl From<std::ops::Range<usize>> for Span {
    fn from(s: std::ops::Range<usize>) -> Self {
        Self {
            start: s.start,
            end: s.end,
        }
    }
}

impl From<Span> for std::ops::Range<usize> {
    fn from(s: Span) -> Self {
        Self {
            start: s.start,
            end: s.end,
        }
    }
}

pub struct ValidationContext<'ctx> {
    pub cfg_id: diag::FileId,
    pub files: &'ctx mut diag::Files,
    pub diagnostics: &'ctx mut Vec<diag::Diagnostic>,
}

impl<'ctx> ValidationContext<'ctx> {
    // pub fn convert_embedded<T, V>(
    //     &mut self,
    //     input: PackageSpecOrExtended<T>,
    //     convert: impl Fn(T, package_spec::ConvertCtx<'_>) -> anyhow::Result<ConfigWithSpec<V>>,
    // ) -> Option<ConfigWithSpec<V>> {
    //     match input {
    //         PackageSpecOrExtended::Simple(spec) => Some(ConfigWithSpec { spec, inner: None }),
    //         PackageSpecOrExtended::Extended(ext) => {
    //             let doc = self.files.source(self.cfg_id);

    //             let ctx = package_spec::ConvertCtx {
    //                 doc: doc.as_str(),
    //                 span: ext.span,
    //             };

    //             let inner = ext.value;
    //             match convert(inner, ctx) {
    //                 Ok(cs) => Some(cs),
    //                 Err(err) => {
    //                     self.diagnostics.push(
    //                         diag::Diagnostic::error()
    //                             .with_message(err.to_string())
    //                             .with_labels(vec![diag::Label::secondary(self.cfg_id, ext.span)]),
    //                     );

    //                     None
    //                 }
    //             }
    //         }
    //     }
    // }

    // #[inline]
    // pub fn convert_spanned(&mut self, span: Span, spec: EmbeddedSpec) -> Option<PackageSpec> {
    //     let ctx = package_spec::ConvertCtx {
    //         doc: self.files.source(self.cfg_id).as_str(),
    //         span,
    //     };

    //     match PackageSpec::from_embedded(spec, ctx) {
    //         Ok(ps) => Some(ps),
    //         Err(err) => {
    //             self.diagnostics.push(
    //                 diag::Diagnostic::error()
    //                     .with_message(err.to_string())
    //                     .with_labels(vec![diag::Label::secondary(self.cfg_id, span)]),
    //             );

    //             None
    //         }
    //     }
    // }

    #[inline]
    pub fn push(&mut self, diag: diag::Diagnostic) {
        self.diagnostics.push(diag);
    }
}

pub trait UnvalidatedConfig {
    type ValidCfg;

    fn validate(self, ctx: ValidationContext<'_>) -> Self::ValidCfg;
}

#[derive(Default)]
pub struct Spanned<T> {
    pub(crate) value: T,
    pub(crate) span: Span,
}

impl<T> Spanned<T> {
    #[inline]
    pub(crate) const fn new(value: T, span: Span) -> Self {
        Self { value, span }
    }

    #[inline]
    pub fn span(&self) -> &Span {
        &self.span
    }

    #[inline]
    pub fn take(self) -> T {
        self.value
    }
}

#[cfg(test)]
pub(crate) trait Fake<T> {
    fn fake(self) -> Spanned<T>;
}

#[cfg(test)]
impl<T> Fake<T> for T
where
    T: Sized,
{
    fn fake(self) -> Spanned<T> {
        #[allow(clippy::reversed_empty_ranges)]
        Spanned {
            value: self,
            span: Default::default(),
        }
    }
}

impl<T> AsRef<T> for Spanned<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T> std::fmt::Debug for Spanned<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.value)
    }
}

impl<T> Clone for Spanned<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            span: self.span.clone(),
        }
    }
}

impl<T> PartialOrd for Spanned<T>
where
    T: PartialOrd,
{
    fn partial_cmp(&self, o: &Spanned<T>) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&o.value)
    }
}

impl<T> Ord for Spanned<T>
where
    T: Ord,
{
    fn cmp(&self, o: &Spanned<T>) -> std::cmp::Ordering {
        self.value.cmp(&o.value)
    }
}

impl<T> PartialEq for Spanned<T>
where
    T: PartialEq,
{
    fn eq(&self, o: &Spanned<T>) -> bool {
        self.value == o.value
    }
}

impl<T> Eq for Spanned<T> where T: Eq {}

impl<T> PartialEq<T> for Spanned<T>
where
    T: PartialEq,
{
    fn eq(&self, o: &T) -> bool {
        &self.value == o
    }
}

pub(crate) mod span_tags {
    pub const NAME: &str = "$__serde_spanned_private_Spanned";
    pub const START: &str = "$__serde_spanned_private_start";
    pub const END: &str = "$__serde_spanned_private_end";
    pub const VALUE: &str = "$__serde_spanned_private_value";
    pub const FIELDS: [&str; 3] = [START, END, VALUE];
}

impl<'de, T> de::Deserialize<'de> for Spanned<T>
where
    T: de::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct SpannedVisitor<T>(::std::marker::PhantomData<T>);

        impl<'de, T> de::Visitor<'de> for SpannedVisitor<T>
        where
            T: de::Deserialize<'de>,
        {
            type Value = Spanned<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a TOML spanned")
            }

            fn visit_map<V>(self, mut visitor: V) -> Result<Spanned<T>, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let start: usize = visitor
                    .next_entry()?
                    .and_then(|(k, v): (&str, _)| (k == span_tags::START).then_some(v))
                    .ok_or(de::Error::custom("spanned start key not found"))?;

                let end: usize = visitor
                    .next_entry()?
                    .and_then(|(k, v): (&str, _)| (k == span_tags::END).then_some(v))
                    .ok_or(de::Error::custom("spanned start key not found"))?;

                if visitor.next_key()? != Some(span_tags::VALUE) {
                    return Err(de::Error::custom("spanned value key not found"));
                }

                let value: T = visitor.next_value()?;

                Ok(Spanned {
                    span: (start..end).into(),
                    value,
                })
            }
        }

        let visitor = SpannedVisitor(::std::marker::PhantomData);
        deserializer.deserialize_struct(span_tags::NAME, &span_tags::FIELDS, visitor)
    }
}

impl<T: ser::Serialize> ser::Serialize for Spanned<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.value.serialize(serializer)
    }
}

pub(crate) fn parse_url(
    cfg_file: crate::diag::FileId,
    urls: Spanned<String>,
) -> Result<Spanned<url::Url>, crate::diag::Diagnostic> {
    url::Url::parse(urls.as_ref())
        .map(|url| Spanned {
            value: url,
            span: urls.span.clone(),
        })
        .map_err(|pe| {
            crate::diag::Diagnostic::error()
                .with_message("failed to parse url")
                .with_labels(vec![
                    crate::diag::Label::primary(cfg_file, urls.span).with_message(pe.to_string())
                ])
        })
}

pub type Reason = Option<Spanned<String>>;

#[cfg(test)]
pub(crate) mod test {
    use crate::{
        diag::{FileId, Files},
        PathBuf,
    };

    pub(crate) struct ConfigData<T> {
        pub(crate) config: T,
        pub(crate) files: Files,
        pub(crate) id: FileId,
    }

    pub(crate) fn load_str<T: serde::de::DeserializeOwned>(
        name: impl Into<std::ffi::OsString>,
        contents: impl Into<String>,
    ) -> ConfigData<T> {
        let contents = contents.into();
        let config = toml::from_str(&contents).unwrap();
        let mut files = Files::new();
        let id = files.add(name, contents);

        ConfigData { config, files, id }
    }

    pub(crate) fn load<T: serde::de::DeserializeOwned>(path: impl Into<PathBuf>) -> ConfigData<T> {
        let path = path.into();
        let contents = std::fs::read_to_string(&path).unwrap();

        load_str(path, contents)
    }
}
