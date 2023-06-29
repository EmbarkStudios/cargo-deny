use crate::{Krate, Krates, Source};
use anyhow::Context as _;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::{borrow::Cow, collections::BTreeMap};
use tame_index::index::{self, ComboIndexCache};

pub struct Indices<'k> {
    indices: Vec<(&'k Source, Option<ComboIndexCache>)>,
    cache: BTreeMap<&'k str, tame_index::IndexKrate>,
}

impl<'k> Indices<'k> {
    pub fn load(krates: &'k Krates, cargo_home: Option<crate::PathBuf>) -> anyhow::Result<Self> {
        let mut indices = Vec::<(&Source, Option<ComboIndexCache>)>::new();

        let cargo_home = if let Some(pb) = cargo_home {
            pb
        } else {
            tame_index::utils::cargo_home()?
        };

        // As of Rust 1.70, the sparse index is stable and the default, but can
        // be manually disabled by users via .config/cargo.toml or env. This
        // doesn't actually change the source for crates.io packages, so we detect
        // if it's being used by checking the manifest paths as a simpler check
        if let Some(ksrc) = krates.krates().find_map(|k| {
            k.source.as_ref().filter(|_s| {
                k.is_crates_io()
                    && k.manifest_path
                        .as_str()
                        .contains("index.crates.io-6f17d22bba15001f")
            })
        }) {
            indices.push((
                ksrc,
                Some(
                    index::SparseIndex::with_path(
                        cargo_home.clone(),
                        tame_index::CRATES_IO_HTTP_INDEX,
                    )?
                    .into(),
                ),
            ));
        }

        for (krate, source) in krates.krates().filter_map(|k| {
            k.source
                .as_ref()
                .filter(|s| s.is_registry())
                .map(|s| (k, s))
        }) {
            if indices.iter().any(|(src, _)| *src == source) {
                continue;
            }

            use crate::SourceKind;
            let index = match (source.kind, source.url()) {
                (SourceKind::CratesIo(true) | SourceKind::Sparse, url) => {
                    let surl = if let Some(url) = url {
                        Cow::Owned(format!("sparse+{url}"))
                    } else {
                        Cow::Borrowed(tame_index::CRATES_IO_HTTP_INDEX)
                    };

                    match index::SparseIndex::with_path(cargo_home.clone(), &surl) {
                        Ok(index) => Some(ComboIndexCache::Sparse(index)),
                        Err(err) => {
                            log::warn!("failed to load sparse index '{surl}' used by crate '{krate}': {err}");
                            None
                        }
                    }
                }
                (SourceKind::CratesIo(false) | SourceKind::Registry, url) => {
                    let url = url
                        .map(|u| u.as_str())
                        .unwrap_or(tame_index::CRATES_IO_INDEX);

                    match index::GitIndex::with_path(cargo_home.clone(), &url) {
                        Ok(i) => Some(ComboIndexCache::Git(i)),
                        Err(err) => {
                            log::warn!(
                                "failed to load git index '{url}' used by crate '{krate}': {err}"
                            );
                            None
                        }
                    }
                }
                _ => None,
            };

            indices.push((source, index));
        }

        // Load the current entries into an in-memory cache so we can hopefully
        // remove any I/O in the rest of the check
        let set: BTreeMap<_, _> = krates
            .krates()
            .filter_map(|k| {
                k.source
                    .as_ref()
                    .filter(|s| s.is_registry())
                    .map(|s| (k.name.as_str(), s))
            })
            .collect();

        let cache = set
            .into_par_iter()
            .filter_map(|(name, src)| {
                let index = indices
                    .iter()
                    .find_map(|(url, index)| index.as_ref().filter(|_i| src == *url))?;

                index
                    .cached_krate(name.try_into().ok()?)
                    .ok()?
                    .map(|ik| (name, ik))
            })
            .collect();

        Ok(Self { indices, cache })
    }

    #[inline]
    pub fn is_yanked(&self, krate: &'k Krate) -> anyhow::Result<bool> {
        // Ignore non-registry crates when checking, as a crate sourced
        // locally or via git can have the same name as a registry package
        let Some(src) = krate.source.as_ref().filter(|s| s.is_registry()) else { return Ok(false) };

        let index_krate = if let Some(ik) = self.cache.get(krate.name.as_str()) {
            Cow::Borrowed(ik)
        } else {
            let index = self
                .indices
                .iter()
                .find_map(|(url, index)| index.as_ref().filter(|_i| src == *url))
                .context("failed to load source index")?;

            let ik = index
                .cached_krate(krate.name.as_str().try_into()?)
                .context("failed to read crate from index cache")?
                .context("unable to find crate in cache")?;
            Cow::Owned(ik)
        };

        let is_yanked = index_krate
            .versions
            .iter()
            .find_map(|kv| (kv.version == krate.version).then_some(kv.yanked));

        Ok(is_yanked.unwrap_or_default())
    }
}
