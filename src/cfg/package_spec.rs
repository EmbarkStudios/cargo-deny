use crate::{cfg::Span, Spanned};
use clap::builder::ValueParserFactory;
use semver::VersionReq;
use serde::Deserialize;
use std::fmt;

/// A package identifier, consisting of a package name and a version requirement
///
/// This is specified similarly to [Cargo Package Ids](https://doc.rust-lang.org/cargo/reference/pkgid-spec.html),
/// however we change semantics a bit to instead use a [`semver::VersionReq`] instead
/// of a [`semver::Version`] as Cargo's are meant for disambiguating graph operations
/// whereas ours may be targeting single or multiple packages. In practice this
/// is mainly just a superset of Cargo's version
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Spanned<String>")]
pub struct PackageSpec {
    pub name: String,
    pub version_req: Option<VersionReq>,
    pub span: Span,
}

pub struct ConvertCtx<'ctx> {
    pub span: Span,
    pub doc: &'ctx str,
}

impl PackageSpec {
    // / Recreate a PackageId from span information for a larger struct and the
    // / original string we are deserializing
    // /
    // / toml::Spanned has a problem when we are doing flattened or untagged enums
    // / as serde will first deserialize into a generic container, which is problematic
    // / since the toml::Spanned relies on the deserializer detecting special state
    // / which is lost in that transition. This is easy to fix for a the simple
    // / situation in [`PackageIdOrExtended`], but is problematic for having a
    // / split or contiguous id in the case of [`EmbeddedId`] since it's flattened
    // / into a larger struct. Rather than have special deserialization code for
    // / each struct that has this embedded id, we cheat by capturing the span
    // / information for the value as a whole, then do a simple string search
    // / for the expected ids to to get the real span information
    // pub fn from_embedded(embedded: EmbeddedSpec, ctx: ConvertCtx<'_>) -> anyhow::Result<Self> {
    //     let find = |key: &str| -> anyhow::Result<Span> {
    //         let vrange = &ctx.doc[std::ops::Range::from(ctx.span)];

    //         let key = vrange
    //             .find(key)
    //             .ok_or_else(|| anyhow::anyhow!("failed to locate '{key}' in '{vrange}'"))?;

    //         for delim in ['"', '\''] {
    //             let Some(start) = vrange[key..].find(delim) else {
    //                 continue;
    //             };

    //             // Note we don't handle multiline strings here, there should be
    //             // no reason to use them in this particular context
    //             let Some(end) = vrange[key + start..].find(delim) else {
    //                 continue;
    //             };

    //             let rstart = ctx.span.start + key;
    //             return Ok((rstart + start..rstart + end).into());
    //         }

    //         anyhow::bail!("unable to locate '{key}' value")
    //     };

    //     match embedded {
    //         EmbeddedSpec::Simple { spec } => {
    //             let crate_span = find("crate")?;
    //             Ok(Spanned::new(spec, crate_span).try_into()?)
    //         }
    //         EmbeddedSpec::Split { name, version } => {
    //             let name_span = find("name")?;
    //             Ok(Self {
    //                 name,
    //                 version_req: version,
    //                 span: name_span,
    //             })
    //         }
    //     }
    // }
}

impl fmt::Display for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;

        if let Some(vr) = &self.version_req {
            write!(f, " = {vr}")?;
        }

        Ok(())
    }
}

impl fmt::Debug for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {:?}", self.name, self.version_req)
    }
}

impl TryFrom<Spanned<String>> for PackageSpec {
    type Error = anyhow::Error;

    fn try_from(mut value: Spanned<String>) -> Result<Self, Self::Error> {
        let (vstr, make_exact) = if let Some((_n, v)) = value.value.split_once('@') {
            (Some(v), true)
        } else if let Some((_n, v)) = value.value.split_once(':') {
            (Some(v), false)
        } else {
            (None, false)
        };

        let version_req = if let Some(vstr) = vstr {
            let mut v: VersionReq = vstr.parse()?;
            if make_exact {
                if let Some(comp) = v.comparators.get_mut(0) {
                    comp.op = semver::Op::Exact;
                }
            }

            let len = vstr.len() + 1;
            value.value.truncate(value.value.len() - len);

            Some(v)
        } else {
            None
        };

        let span = value.span;
        let name = value.value;

        Ok(Self {
            name,
            version_req,
            span,
        })
    }
}

#[derive(Deserialize)]
pub enum PackageSpecOrExtended<T> {
    Simple(PackageSpec),
    Extended {
        #[serde(flatten)]
        spec: EmbeddedSpec,
        #[serde(flatten)]
        inner: Option<T>,
    },
}

// impl<'de, T> Deserialize<'de> for PackageSpecOrExtended<T>
// where
//     T: Deserialize<'de>,
// {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         let content = <Spanned<serde::__private::de::Content<'de>>>::deserialize(deserializer)?;
//         let deserializer =
//             serde::__private::de::ContentRefDeserializer::<D::Error>::new(&content.value);

//         if let Ok(simple) = String::deserialize(deserializer).and_then(|s| {
//             let pid = Spanned::new(s, content.span.clone())
//                 .try_into()
//                 .map_err(serde::de::Error::custom)?;
//             Ok(PackageSpecOrExtended::Simple(pid))
//         }) {
//             return Ok(simple);
//         }
//         if let Ok(ext) = T::deserialize(deserializer)
//             .map(|ext| PackageSpecOrExtended::Extended(Spanned::new(ext, content.span)))
//         {
//             return Ok(ext);
//         }

//         Err(serde::de::Error::custom(
//             "data did not match any variant of untagged enum PackageSpecOrExtended",
//         ))
//     }
// }

impl<T> fmt::Debug for PackageSpecOrExtended<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Simple(spec) => write!(f, "{spec:?}"),
            Self::Extended { spec, .. } => match spec {
                EmbeddedSpec::Simple { spec } => write!(f, "{spec:?}"),
                EmbeddedSpec::Split { name, version } => {
                    write!(f, "{name:?}")?;
                    if let Some(v) = version {
                        write!(f, ":{v}")?;
                    }

                    Ok(())
                }
            },
        }
    }
}

pub struct ConfigWithSpec<T> {
    pub spec: PackageSpec,
    pub inner: Option<T>,
}

impl<T, U> TryFrom<PackageSpecOrExtended<T>> for ConfigWithSpec<U>
where
    U: TryFrom<T>,
{
    type Error = <U as TryFrom<T>>::Error;

    fn try_from(value: PackageSpecOrExtended<T>) -> Result<Self, Self::Error> {
        match value {
            PackageSpecOrExtended::Simple(spec) => Ok(Self { spec, inner: None }),
            PackageSpecOrExtended::Extended { spec, inner } => {
                let spec = match spec {
                    EmbeddedSpec::Simple { spec } => spec,
                    EmbeddedSpec::Split { name, version } => PackageSpec {
                        name: name.value,
                        version_req: version,
                        span: name.span,
                    },
                };

                let inner = if let Some(inner) = inner {
                    Some(inner.try_into()?)
                } else {
                    None
                };

                Ok(Self { spec, inner })
            }
        }
    }
}

impl<T> fmt::Debug for ConfigWithSpec<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigWithSpec")
            .field("spec", &self.spec)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<T> Clone for ConfigWithSpec<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            spec: self.spec.clone(),
            inner: self.inner.clone(),
        }
    }
}

#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(untagged)]
pub enum EmbeddedSpec {
    Simple {
        #[serde(rename = "crate")]
        spec: PackageSpec,
    },
    Split {
        name: Spanned<String>,
        version: Option<VersionReq>,
    },
}

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn deserializes_package_id() {
//         #[derive(Deserialize)]
//         struct Boop {
//             data: Option<Spanned<u32>>,
//         }

//         #[derive(Debug)]
//         struct ValidBoop {
//             data: Option<Spanned<u32>>,
//         }

//         impl TryFrom<Boop> for ValidBoop {
//             type Error = anyhow::Error;

//             fn try_from(value: Boop) -> Result<Self, Self::Error> {
//                 Ok(Self { data: value.data })
//             }
//         }

//         #[derive(Deserialize)]
//         struct TestCfg {
//             bare: PackageSpecOrExtended<Boop>,
//             specific: PackageSpecOrExtended<Boop>,
//             range: PackageSpecOrExtended<Boop>,
//             mixed: Vec<PackageSpecOrExtended<Boop>>,
//         }

//         #[derive(Debug)]
//         struct ValidTestCfg {
//             bare: ConfigWithSpec<ValidBoop>,
//             specific: ConfigWithSpec<ValidBoop>,
//             range: ConfigWithSpec<ValidBoop>,
//             mixed: Vec<ConfigWithSpec<ValidBoop>>,
//         }

//         const TEST_DATA: &str = r#"
// bare = "bare-name"
// specific = { name = "specific", version = "=0.1.0" }
// range = { crate = "range:<=1.0" }
// mixed = [
//     "bare-name-1",
//     { name = "range-2", version = ">=1.0,<=2.0" },
//     "specific-3@0.2.1",
// ]
// "#;

//         let tc: TestCfg = crate::cfg::deserialize_spanned(TEST_DATA).unwrap();

//         let vtc = ValidTestCfg {
//             bare: tc.bare.try_into().unwrap(),
//             specific: tc.specific.try_into().unwrap(),
//             range: tc.range.try_into().unwrap(),
//             mixed: tc
//                 .mixed
//                 .into_iter()
//                 .map(|tc| tc.try_into().unwrap())
//                 .collect(),
//         };

//         insta::assert_debug_snapshot!(vtc);
//     }
// }
