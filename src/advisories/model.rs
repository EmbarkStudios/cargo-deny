//! Data model for a `rustsec` compatible advisory database

use cfg_expr::targets;
use semver::VersionReq;
use smallvec::SmallVec;

pub struct Affected<'f> {
    pub arch: SmallVec<[targets::Arch; 2]>,
    pub os: SmallVec<[targets::Os; 1]>,
    pub functions: std::collections::BTreeMap<&'f str, Vec<VersionReq>>,
}

impl Affected<'_> {
    #[inline]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "arch": serde_json::Value::Array(self.arch.iter().map(|a| serde_json::Value::String(a.0.to_string())).collect()),
            "os": serde_json::Value::Array(self.os.iter().map(|o| serde_json::Value::String(o.0.to_string())).collect()),
            "functions": self.functions,
        })
    }
}

pub struct Versions {
    pub patched: Vec<VersionReq>,
    pub unaffected: Vec<VersionReq>,
}

impl Versions {
    #[inline]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "patched": self.patched,
            "unaffected": self.unaffected,
        })
    }
}

pub enum Informational<'f> {
    /// Security notices for a crate which are published on <https://rustsec.org>
    /// but don't represent a vulnerability in a crate itself.
    Notice,
    /// Crate is unmaintained / abandoned
    Unmaintained,
    /// Crate is not [sound], i.e., unsound.
    ///
    /// A crate is unsound if, using its public API from safe code, it is possible to cause [Undefined Behavior].
    ///
    /// [sound]: https://rust-lang.github.io/unsafe-code-guidelines/glossary.html#soundness-of-code--of-a-library
    /// [Undefined Behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
    Unsound,
    /// Other types of informational advisories: left open-ended to add
    /// more of them in the future.
    Other(&'f str),
}

pub struct AdvisoryLicense<'f>(pub &'f str);

impl Default for AdvisoryLicense<'_> {
    fn default() -> Self {
        Self("CC0-1.0")
    }
}

pub struct Metadata<'f> {
    pub id: &'f str,
    pub krate: &'f str,
    pub title: &'f str,
    pub description: &'f str,
    pub date: jiff::civil::Date,
    pub aliases: SmallVec<[&'f str; 2]>,
    pub related: SmallVec<[&'f str; 1]>,
    pub categories: SmallVec<[&'f str; 2]>,
    pub keywords: SmallVec<[&'f str; 4]>,
    pub cvss: Option<&'f str>,
    pub informational: Option<Informational<'f>>,
    pub references: SmallVec<[&'f str; 1]>,
    pub source: Option<crate::Source>,
    pub url: Option<&'f str>,
    pub withdrawn: Option<jiff::civil::Date>,
    pub license: AdvisoryLicense<'f>,
    pub expect_deleted: bool,
}

#[inline]
fn array(l: &[&str]) -> serde_json::Value {
    serde_json::Value::Array(
        l.iter()
            .map(|s| serde_json::Value::String((*s).to_string()))
            .collect(),
    )
}

impl Metadata<'_> {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "package": self.krate,
            "title": self.title,
            "description": self.description,
            "date": self.date.to_string(),
            "aliases": array(&self.aliases),
            "related": array(&self.related),
            // TODO: change this if we (or rustsec) ever supports checking the actual rust version
            "collection": "crates",
            "categories": array(&self.categories),
            "keywords": array(&self.keywords),
            "cvss": self.cvss,
            "informational": self.informational.as_ref().map(|i| {
                match i {
                    Informational::Unmaintained => "unmaintained",
                    Informational::Unsound => "unsound",
                    Informational::Notice => "notice",
                    Informational::Other(o) => o,
                }
            }),
            "references": array(&self.references),
            "source": self.source.as_ref().map(|s| s.to_string()),
            "url": self.url,
            "withdrawn": self.withdrawn.map(|d| d.to_string()),
            "license": self.license.0,
            "expect-deleted": self.expect_deleted,
        })
    }
}

pub struct Advisory<'f> {
    pub advisory: Metadata<'f>,
    pub affected: Option<Affected<'f>>,
    pub versions: Versions,
}

impl Advisory<'_> {
    pub fn to_sarif(&self) -> crate::diag::SerializedAdvisory {
        use std::fmt::Write as _;

        let mut md = String::with_capacity(128);

        let meta = &self.advisory;

        md.push_str("# ");

        if let Some(url) = &meta.url {
            md.push('[');
            md.push_str(meta.id);
            md.push_str("](");
            md.push_str(url);
            md.push(')');
        } else {
            md.push_str(meta.id);
        }

        md.push('\n');
        md.push_str(meta.title);
        md.push('\n');

        md.push_str("## Description\n");
        md.push_str(meta.description);
        md.push_str("\n\n");

        if !self.versions.unaffected.is_empty() {
            md.push_str("## Unaffected\n");
            for un in &self.versions.unaffected {
                writeln!(&mut md, "- `{un}`").unwrap();
            }
            md.push('\n');
        }

        if !self.versions.patched.is_empty() {
            md.push_str("## Patched\n");
            for un in &self.versions.patched {
                writeln!(&mut md, "- `{un}`").unwrap();
            }
            md.push('\n');
        }

        if let Some(affected) = &self.affected {
            md.push_str("## Affected\n");
            if !affected.functions.is_empty() {
                md.push_str("| Functions | Versions |\n|---|---|\n");
                for (path, reqs) in &affected.functions {
                    write!(&mut md, "|`{path}`|").unwrap();

                    for (i, req) in reqs.iter().enumerate() {
                        if i > 0 {
                            md.push_str(", ");
                        }

                        write!(&mut md, "`{req}`").unwrap();
                    }

                    md.push_str("|\n");
                }

                md.push('\n');
            }

            if !affected.arch.is_empty() {
                md.push_str("### Arches\n");
                for arch in &affected.arch {
                    md.push_str("- ");
                    md.push_str(arch.as_str());
                    md.push('\n');
                }
                md.push('\n');
            }

            if !affected.os.is_empty() {
                md.push_str("### Operating Systems\n");
                for os in &affected.os {
                    md.push_str("- ");
                    md.push_str(os.as_str());
                    md.push('\n');
                }
                md.push('\n');
            }
        }

        crate::diag::SerializedAdvisory::Sarif {
            id: meta.id.to_owned(),
            title: meta.title.to_owned(),
            markdown: md,
        }
    }

    pub fn to_json(&self) -> crate::diag::SerializedAdvisory {
        // let json = serde_json::json!({
        //     "advisory": self.advisory.to_json(),
        //     "affected": self.affected.as_ref().map(|aff| aff.to_json()),
        //     "versions": self.versions.to_json(),
        // });

        crate::diag::SerializedAdvisory::Json(self.advisory.to_json())
    }
}
