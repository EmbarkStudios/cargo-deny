use serde::{de, ser};
use std::fmt;

pub trait UnvalidatedConfig {
    type ValidCfg;

    fn validate(
        self,
        id: crate::diag::FileId,
        files: &mut crate::diag::Files,
        diagnostics: &mut Vec<crate::diag::Diagnostic>,
    ) -> Self::ValidCfg;
}

#[derive(Default)]
pub struct Spanned<T> {
    pub(crate) value: T,
    pub(crate) span: std::ops::Range<usize>,
}

impl<T> Spanned<T> {
    #[inline]
    pub(crate) const fn new(value: T, span: std::ops::Range<usize>) -> Self {
        Self { value, span }
    }

    #[inline]
    pub fn span(&self) -> &std::ops::Range<usize> {
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
            span: 0..0,
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

impl<'de, T> de::Deserialize<'de> for Spanned<T>
where
    T: de::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        pub(crate) const NAME: &str = "$__serde_spanned_private_Spanned";
        pub(crate) const START: &str = "$__serde_spanned_private_start";
        pub(crate) const END: &str = "$__serde_spanned_private_end";
        pub(crate) const VALUE: &str = "$__serde_spanned_private_value";

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
                if visitor.next_key()? != Some(START) {
                    return Err(de::Error::custom("spanned start key not found"));
                }

                let start: usize = visitor.next_value()?;

                if visitor.next_key()? != Some(END) {
                    return Err(de::Error::custom("spanned end key not found"));
                }

                let end: usize = visitor.next_value()?;

                if visitor.next_key()? != Some(VALUE) {
                    return Err(de::Error::custom("spanned value key not found"));
                }

                let value: T = visitor.next_value()?;

                Ok(Spanned {
                    span: start..end,
                    value,
                })
            }
        }

        let visitor = SpannedVisitor(::std::marker::PhantomData);

        static FIELDS: [&str; 3] = [START, END, VALUE];
        deserializer.deserialize_struct(NAME, &FIELDS, visitor)
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

    pub(crate) fn load<T: serde::de::DeserializeOwned>(path: impl Into<PathBuf>) -> ConfigData<T> {
        let path = path.into();
        let contents = std::fs::read_to_string(&path).unwrap();

        let config = toml::from_str(&contents).unwrap();
        let mut files = Files::new();
        let id = files.add(&path, contents);

        ConfigData { config, files, id }
    }
}
