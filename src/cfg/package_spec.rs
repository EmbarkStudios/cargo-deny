use crate::{cfg::Span, Spanned};
use semver::VersionReq;
use std::fmt;
use toml_file::{
    de_helpers::{expected, TableHelper},
    value::{Value, ValueInner},
    DeserError, Deserialize,
};

/// A package identifier, consisting of a package name and a version requirement
///
/// This is specified similarly to [Cargo Package Ids](https://doc.rust-lang.org/cargo/reference/pkgid-spec.html),
/// however we change semantics a bit to instead use a [`semver::VersionReq`] instead
/// of a [`semver::Version`] as Cargo's are meant for disambiguating graph operations
/// whereas ours may be targeting single or multiple packages. In practice this
/// is mainly just a superset of Cargo's version
#[derive(Clone, PartialEq, Eq)]
pub struct PackageSpec {
    pub name: Spanned<String>,
    pub version_req: Option<VersionReq>,
}

impl fmt::Display for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name.value)?;

        if let Some(vr) = &self.version_req {
            write!(f, " = {vr}")?;
        }

        Ok(())
    }
}

impl fmt::Debug for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {:?}", self.name.value, self.version_req)
    }
}

impl<'de> Deserialize<'de> for PackageSpec {
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        use std::borrow::Cow;

        struct Ctx<'de> {
            inner: Cow<'de, str>,
            split: Option<(usize, bool)>,
            span: Span,
        }

        impl<'de> Ctx<'de> {
            fn from_str(bs: Cow<'de, str>, span: Span) -> Self {
                let split = bs
                    .find('@')
                    .map(|i| (i, true))
                    .or_else(|| bs.find(':').map(|i| (i, false)));
                Self {
                    inner: bs,
                    split,
                    span,
                }
            }
        }

        let ctx = match value.take() {
            ValueInner::String(s) => Ctx::from_str(s, value.span),
            ValueInner::Table(tab) => {
                let mut th = TableHelper::from(tab);

                if let Some(mut val) = th.table.remove(&"crate".into()) {
                    let s = val.take_string(Some("a crate spec"))?;
                    th.finalize(Some(value))?;

                    Ctx::from_str(s, val.span)
                } else {
                    let name = th.required("name")?;
                    let version = th.optional::<Spanned<Cow<'_, str>>>("version");

                    th.finalize(Some(value))?;

                    let version_req = if let Some(vr) = version {
                        Some(vr.value.parse().map_err(|e: semver::Error| {
                            toml_file::Error::from((
                                toml_file::ErrorKind::Custom(e.to_string()),
                                vr.span,
                            ))
                        })?)
                    } else {
                        None
                    };

                    return Ok(Self { name, version_req });
                }
            }
            other => return Err(expected("a string or table", other, value.span).into()),
        };

        let (name, version_req) = if let Some((i, make_exact)) = ctx.split {
            let mut v: VersionReq = ctx.inner[i + 1..].parse().map_err(|e: semver::Error| {
                toml_file::Error::from((
                    toml_file::ErrorKind::Custom(e.to_string()),
                    Span::new(ctx.span.start + i + 1, ctx.span.end),
                ))
            })?;
            if make_exact {
                if let Some(comp) = v.comparators.get_mut(0) {
                    comp.op = semver::Op::Exact;
                }
            }

            (
                Spanned::with_span(
                    ctx.inner[..i].into(),
                    Span::new(ctx.span.start, ctx.span.start + i),
                ),
                Some(v),
            )
        } else {
            (Spanned::with_span(ctx.inner.into(), ctx.span), None)
        };

        Ok(Self { name, version_req })
    }
}

#[cfg(test)]
impl serde::Serialize for PackageSpec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("name", &self.name.value)?;
        map.serialize_entry("version-req", &self.version_req)?;
        map.end()
    }
}

#[cfg_attr(test, derive(serde::Serialize))]
pub struct PackageSpecOrExtended<T> {
    pub spec: PackageSpec,
    pub inner: Option<T>,
}

impl<T> PackageSpecOrExtended<T> {
    pub fn try_convert<V, E>(self) -> Result<PackageSpecOrExtended<V>, E>
    where
        V: TryFrom<T, Error = E>,
    {
        let inner = if let Some(i) = self.inner {
            Some(V::try_from(i)?)
        } else {
            None
        };

        Ok(PackageSpecOrExtended {
            spec: self.spec,
            inner,
        })
    }

    pub fn convert<V>(self) -> PackageSpecOrExtended<V>
    where
        V: From<T>,
    {
        PackageSpecOrExtended {
            spec: self.spec,
            inner: self.inner.map(V::from),
        }
    }
}

impl<'de, T> toml_file::Deserialize<'de> for PackageSpecOrExtended<T>
where
    T: toml_file::Deserialize<'de>,
{
    fn deserialize(value: &mut Value<'de>) -> Result<Self, DeserError> {
        let spec = PackageSpec::deserialize(value)?;

        // If more keys exist in the table (or string) then try to deserialize
        // the rest as the "extended" portion
        let inner = if value.has_keys() {
            Some(T::deserialize(value)?)
        } else {
            None
        };

        Ok(Self { spec, inner })
    }
}

impl<T> fmt::Debug for PackageSpecOrExtended<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackageSpecOrExtended")
            .field("spec", &self.spec)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<T> Clone for PackageSpecOrExtended<T>
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

#[cfg(test)]
#[allow(dead_code)]
mod test {
    use super::*;
    use crate::{cfg::ValidationContext, test_utils::ConfigData};

    #[test]
    fn deserializes_package_id() {
        struct Boop {
            data: Option<Spanned<u32>>,
        }

        impl<'de> Deserialize<'de> for Boop {
            fn deserialize(value: &mut toml_file::value::Value<'de>) -> Result<Self, DeserError> {
                let mut th = TableHelper::new(value)?;
                let data = th.optional_s("data");
                th.finalize(None)?;
                Ok(Self { data })
            }
        }

        #[derive(serde::Serialize)]
        struct ValidBoop {
            data: Option<Spanned<u32>>,
        }

        impl From<Boop> for ValidBoop {
            fn from(value: Boop) -> Self {
                Self { data: value.data }
            }
        }

        struct TestCfg {
            bare: PackageSpecOrExtended<Boop>,
            specific: PackageSpecOrExtended<Boop>,
            range: PackageSpecOrExtended<Boop>,
            mixed: Vec<PackageSpecOrExtended<Boop>>,
        }

        impl<'de> Deserialize<'de> for TestCfg {
            fn deserialize(value: &mut toml_file::value::Value<'de>) -> Result<Self, DeserError> {
                let mut th = TableHelper::new(value)?;
                let bare = th.required("bare")?;
                let specific = th.required("specific")?;
                let range = th.required("range")?;
                let mixed = th.required("mixed")?;
                th.finalize(None)?;

                Ok(Self {
                    bare,
                    specific,
                    range,
                    mixed,
                })
            }
        }

        #[derive(serde::Serialize)]
        struct ValidTestCfg {
            bare: PackageSpecOrExtended<ValidBoop>,
            specific: PackageSpecOrExtended<ValidBoop>,
            range: PackageSpecOrExtended<ValidBoop>,
            mixed: Vec<PackageSpecOrExtended<ValidBoop>>,
        }

        impl crate::cfg::UnvalidatedConfig for TestCfg {
            type ValidCfg = ValidTestCfg;

            fn validate(self, mut _ctx: ValidationContext<'_>) -> Self::ValidCfg {
                ValidTestCfg {
                    bare: self.bare.convert(),
                    specific: self.specific.convert(),
                    range: self.range.convert(),
                    mixed: self.mixed.into_iter().map(|m| m.convert()).collect(),
                }
            }
        }

        let cd = ConfigData::<TestCfg>::load("tests/cfg/package-specs.toml");
        let validated = cd.validate(|s| s);

        insta::assert_json_snapshot!(validated);
    }
}
