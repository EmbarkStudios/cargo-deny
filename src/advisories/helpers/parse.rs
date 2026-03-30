#![allow(clippy::question_mark)]

use crate::advisories::model;
use anyhow::Context as _;
use semver::VersionReq;

struct ArrayIter {
    arr: &'static str,
    inner: memchr::Memchr<'static>,
}

impl ArrayIter {
    /// An iterator over an array of string values that might span lines
    fn new(toml: &'static str, line: Line, liter: &mut std::iter::Peekable<LineIter>) -> Self {
        let start = memchr::memchr(b'[', line.s.as_bytes()).expect("no array opener");

        let arr = if let Some(end) = memchr::memchr(b']', line.s.as_bytes()) {
            &line.s[start + 1..end]
        } else {
            let arr_end = 'end: {
                for l in liter.by_ref() {
                    if let Some(end) = memchr::memchr(b']', l.s.as_bytes()) {
                        break 'end l.start + end;
                    }
                }

                panic!("unclosed '['");
            };

            &toml[line.start + start..arr_end]
        };

        Self {
            arr,
            inner: memchr::memchr_iter(b'"', arr.as_bytes()),
        }
    }
}

impl Iterator for ArrayIter {
    type Item = &'static str;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let Some(start) = self.inner.next() else {
            return None;
        };
        let Some(end) = self.inner.next() else {
            return None;
        };

        Some(&self.arr[start + 1..end])
    }
}

#[derive(Copy, Clone)]
struct Line {
    s: &'static str,
    start: usize,
}

impl Line {
    #[inline]
    fn skip(self) -> bool {
        self.s.trim().is_empty() || self.s.starts_with('#')
    }

    #[inline]
    fn pair(self) -> anyhow::Result<(&'static str, &'static str)> {
        let split = memchr::memchr(b'=', self.s.as_bytes())
            .with_context(|| format!("line `{}` did not follow expected format", self.s))?;

        Ok((self.s[..split].trim(), self.s[split + 1..].trim()))
    }
}

struct LineIter {
    start: usize,
    v: &'static str,
    inner: memchr::Memchr<'static>,
}

impl LineIter {
    #[inline]
    fn new(v: &'static str) -> Self {
        Self {
            start: 0,
            v,
            inner: memchr::memchr_iter(b'\n', v.as_bytes()),
        }
    }
}

impl Iterator for LineIter {
    type Item = Line;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let Some(end) = self.inner.next() else {
            return None;
        };

        let s = &self.v[self.start..end];
        let start = self.start;
        self.start = end + 1;

        Some(Line { s, start })
    }
}

struct StringIter {
    s: &'static str,
    inner: memchr::Memchr<'static>,
}

impl StringIter {
    #[inline]
    fn new(s: &'static str) -> Self {
        Self {
            s,
            inner: memchr::memchr_iter(b'"', s.as_bytes()),
        }
    }
}

impl Iterator for StringIter {
    type Item = &'static str;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let Some(start) = self.inner.next() else {
            return None;
        };
        let Some(end) = self.inner.next() else {
            return None;
        };

        Some(&self.s[start + 1..end])
    }
}

#[inline]
pub(super) fn parse(b: &'static [u8]) -> anyhow::Result<model::Advisory<'static>> {
    let whole = std::str::from_utf8(b)?;

    // This should be at the start, but just in case
    let tstart = whole
        .find("```toml\n")
        .context("failed to find toml block")?;
    let s = &whole[tstart + 8..];

    let tend = s
        .find("```\n")
        .context("failed to find end of toml block")?;

    let rest = &s[tend + 4..];
    let toml = &s[..tend];

    let mut adv = parse_toml(toml)?;

    let mut start = 0;
    for end in memchr::Memchr::new(b'\n', rest.as_bytes()) {
        let line = &rest[start..end];
        start = end + 1;

        if let Some(title) = line.strip_prefix("# ") {
            // rustsec trims whitespace in the title from the end but not the beginning
            // <https://github.com/rustsec/rustsec/blob/9909babfe97ac580d59bb48ff8f26308afcd486e/rustsec/src/advisory/parts.rs#L63>
            adv.advisory.title = title.trim_end();
            break;
        }
    }

    adv.advisory.description = rest[start..].trim();

    Ok(adv)
}

fn parse_toml(toml: &'static str) -> anyhow::Result<model::Advisory<'static>> {
    let mut liter = LineIter::new(toml).peekable();

    let mut md = model::Metadata {
        id: "",
        krate: "",
        title: "",
        description: "",
        date: jiff::civil::Date::constant(0, 1, 1),
        aliases: Default::default(),
        related: Default::default(),
        categories: Default::default(),
        keywords: Default::default(),
        cvss: None,
        informational: None,
        source: None,
        references: Default::default(),
        url: None,
        withdrawn: None,
        license: Default::default(),
        expect_deleted: false,
    };
    let mut versions = None;
    let mut affected = None;

    let parse_advisory = |liter: &mut std::iter::Peekable<LineIter>,
                          md: &mut model::Metadata<'static>|
     -> anyhow::Result<()> {
        while let Some(line) = liter.next_if(|l| !l.s.starts_with('[')) {
            if line.skip() {
                continue;
            }

            let (field, value) = line.pair().with_context(|| format!("TOML {toml}"))?;

            let string = || -> &'static str {
                let Some(start) = memchr::memchr(b'"', value.as_bytes()) else {
                    panic!("expected opening '\"' in `{value}`");
                };
                let Some(end) = memchr::memchr(b'"', &value.as_bytes()[start + 1..]) else {
                    panic!("expected closing '\"' in `{value}`");
                };

                &value[start + 1..start + 1 + end]
            };

            match field {
                "id" => md.id = string(),
                "package" => md.krate = string(),
                "aliases" => {
                    for alias in ArrayIter::new(toml, line, liter) {
                        md.aliases.push(alias);
                    }
                }
                "related" => {
                    for id in ArrayIter::new(toml, line, liter) {
                        md.related.push(id);
                    }
                }
                "cvss" => md.cvss = Some(string()),
                "date" => md.date = string().parse().context("failed to parse `date`")?,
                "url" => md.url = Some(string()),
                "informational" => {
                    md.informational = Some(match string() {
                        "unmaintained" => model::Informational::Unmaintained,
                        "unsound" => model::Informational::Unsound,
                        "notice" => model::Informational::Notice,
                        other => model::Informational::Other(other),
                    });
                }
                "categories" => {
                    for alias in ArrayIter::new(toml, line, liter) {
                        md.categories.push(alias);
                    }
                }
                "keywords" => {
                    for kw in ArrayIter::new(toml, line, liter) {
                        md.keywords.push(kw);
                    }
                }
                "references" => {
                    for r in ArrayIter::new(toml, line, liter) {
                        md.references.push(r);
                    }
                }
                "withdrawn" => {
                    md.withdrawn = Some(string().parse().context("failed to parse `withdrawn`")?);
                }
                "license" => {
                    md.license = model::AdvisoryLicense(string());
                }
                "source" => {
                    md.source = Some(
                        crate::Source::from_metadata(value.to_owned(), None)
                            .with_context(|| "failed to parse `source` field '{value}'")?,
                    );
                }
                "expect-deleted" => {
                    md.expect_deleted = value == "true";
                }
                unknown => {
                    log::warn!("unknown advisory field '{unknown}'");
                }
            }
        }

        Ok(())
    };

    let parse_versions =
        |liter: &mut std::iter::Peekable<LineIter>| -> anyhow::Result<model::Versions> {
            let mut v = model::Versions {
                patched: Default::default(),
                unaffected: Default::default(),
            };

            while let Some(line) = liter.next_if(|l| !l.s.starts_with('[')) {
                if line.skip() {
                    continue;
                }

                let (field, _value) = line.pair()?;

                match field {
                    "patched" => {
                        for vr in ArrayIter::new(toml, line, liter) {
                            v.patched.push(vr.parse().with_context(|| {
                                format!("failed to parse patched version '{vr}'")
                            })?);
                        }
                    }
                    "unaffected" => {
                        for vr in ArrayIter::new(toml, line, liter) {
                            v.unaffected.push(vr.parse().with_context(|| {
                                format!("failed to parse unaffected version '{vr}'")
                            })?);
                        }
                    }
                    unknown => anyhow::bail!("unknown versions field '{unknown}'"),
                }
            }

            Ok(v)
        };

    let parse_affected = |liter: &mut std::iter::Peekable<LineIter>,
                          first: &'static str|
     -> anyhow::Result<Option<model::Affected<'static>>> {
        let mut affected = model::Affected {
            functions: Default::default(),
            os: Default::default(),
            arch: Default::default(),
        };

        let parse_function_table = |liter: &mut std::iter::Peekable<LineIter>,
                                    funcs: &mut std::collections::BTreeMap<
            &'static str,
            Vec<VersionReq>,
        >| {
            while let Some(line) = liter.next_if(|l| !l.s.starts_with('[')) {
                if line.skip() {
                    continue;
                }

                let Some((field, _value)) = line.s.split_once(" = ") else {
                    continue;
                };

                let key = field.trim_matches('"');
                let mut val = Vec::new();

                for vr in ArrayIter::new(toml, line, liter) {
                    match vr.parse() {
                        Ok(vr) => val.push(vr),
                        Err(error) => {
                            log::error!(
                                "failed to parse version requirement for function '{key}': {error}"
                            );
                        }
                    }
                }

                funcs.insert(key, val);
            }
        };

        if first == "[affected]" {
            while let Some(line) = liter.peek() {
                if line.s.starts_with('[') {
                    if line.s == "[affected.functions]" {
                        liter.next();

                        parse_function_table(liter, &mut affected.functions);
                    }

                    break;
                }

                let line = liter.next().unwrap();
                if line.skip() {
                    continue;
                }

                let (field, value) = line.pair()?;

                match field {
                    "functions" => {
                        let Some(start) = memchr::memchr(b'{', value.as_bytes()) else {
                            continue;
                        };
                        let Some(end) = memchr::memrchr(b'}', value.as_bytes()) else {
                            continue;
                        };

                        let mut map = value[start + 1..end].trim();

                        while let Some((key, value)) = map.split_once(" = ") {
                            let key = key.trim_matches('"');
                            let mut val = Vec::new();

                            let vstart = memchr::memchr(b'[', value.as_bytes())
                                .expect("function did not have a valid version array start");
                            let vend = memchr::memchr(b']', value.as_bytes())
                                .expect("function did not have a valid version array end");

                            for vr in StringIter::new(&value[vstart..vend]) {
                                match vr.parse() {
                                    Ok(vr) => val.push(vr),
                                    Err(error) => {
                                        log::error!(
                                            "failed to parse version requirement for function '{key}': {error}"
                                        );
                                    }
                                }
                            }

                            affected.functions.insert(key, val);

                            let Some(start) = memchr::memchr(b'"', &value.as_bytes()[vend..])
                            else {
                                break;
                            };

                            map = &value[vend + start..];
                        }
                    }
                    "os" => {
                        for os in ArrayIter::new(toml, line, liter) {
                            affected
                                .os
                                .push(cfg_expr::targets::Os(std::borrow::Cow::Borrowed(os)));
                        }
                    }
                    "arch" => {
                        for arch in ArrayIter::new(toml, line, liter) {
                            affected
                                .arch
                                .push(cfg_expr::targets::Arch(std::borrow::Cow::Borrowed(arch)));
                        }
                    }
                    unknown => {
                        log::warn!("unknown `affected` field '{unknown}'");
                    }
                }
            }
        } else if first == "[affected.functions]" {
            parse_function_table(liter, &mut affected.functions);
        }

        if affected.functions.is_empty() && affected.os.is_empty() && affected.arch.is_empty() {
            Ok(None)
        } else {
            Ok(Some(affected))
        }
    };

    while let Some(line) = liter.next() {
        match line.s {
            "[advisory]" => {
                parse_advisory(&mut liter, &mut md)?;
            }
            "[versions]" => {
                versions = Some(parse_versions(&mut liter)?);
            }
            aff if line.s.starts_with("[affected") => {
                affected = parse_affected(&mut liter, aff)?;
            }
            "```" => {
                break;
            }
            "" => {}
            unknown => {
                log::warn!("unknown toml table '{unknown}'");
            }
        }
    }

    Ok(model::Advisory {
        advisory: md,
        affected,
        versions: versions.unwrap_or(model::Versions {
            patched: Vec::new(),
            unaffected: Vec::new(),
        }),
    })
}

#[cfg(test)]
mod test {
    #[test]
    fn split_arrays() {
        let toml = r#"[advisory]
id = "RUSTSEC-2020-0146"
package = "generic-array"
date = "2020-04-09"
url = "https://github.com/fizyk20/generic-array/issues/98"
categories = ["memory-corruption"]
keywords = ["soundness"]
aliases = ["CVE-2020-36465", "GHSA-3358-4f7f-p4j4"]
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"

[versions]
patched = [
    ">= 0.8.4, < 0.9.0",
    ">= 0.9.1, < 0.10.0",
    ">= 0.10.1, < 0.11.0",
    ">= 0.11.2, < 0.12.0",
    ">= 0.12.4, < 0.13.0",
    ">= 0.13.3",
]
unaffected = ["< 0.8.0"]"#;

        super::parse_toml(toml).unwrap();
    }
}
