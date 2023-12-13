use crate::Spanned;
use semver::VersionReq;

/// A package identifier, consisting of a package name and a version requirement
///
/// This is specified similarly to [Cargo Package Ids](https://doc.rust-lang.org/cargo/reference/pkgid-spec.html),
/// however we change semantics a bit to instead use a [`semver::VersionReq`] instead
/// of a [`semver::Version`] as Cargo's are meant for disambiguating graph operations
/// whereas ours may be targeting single or multiple packages. In practice this
/// is mainly just a superset of Cargo's version
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct PackageId {
    pub name: Spanned<String>,
    pub version_req: Option<VersionReq>,
}

impl<'de> serde::de::Deserialize<'de> for PackageId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let mut name = Spanned::<String>::deserialize(deserializer)?;

        let (vstr, make_exact) = if let Some((_n, v)) = name.value.split_once('@') {
            (Some(v), true)
        } else if let Some((_n, v)) = name.value.split_once(':') {
            (Some(v), false)
        } else {
            (None, false)
        };

        let version_req = if let Some(vstr) = vstr {
            let mut v: VersionReq = vstr.parse().map_err(serde::de::Error::custom)?;
            if make_exact {
                if let Some(comp) = v.comparators.get_mut(0) {
                    comp.op = semver::Op::Exact;
                }
            }

            let len = vstr.len() + 1;
            name.span.end -= len;
            name.value.truncate(name.value.len() - len);

            Some(v)
        } else {
            None
        };

        Ok(Self { name, version_req })
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub enum PackageIdOrExtended<T> {
    Simple(PackageId),
    Extended(T),
}
