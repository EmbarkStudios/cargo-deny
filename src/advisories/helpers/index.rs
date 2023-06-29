use crate::{Krate, Krates, Source};
use anyhow::Context as _;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::{borrow::Cow, collections::BTreeMap};
use tame_index::{
    index::{self, ComboIndexCache},
    Error,
};

pub struct Indices<'k> {
    pub indices: Vec<(&'k Source, Result<ComboIndexCache, Error>)>,
    pub cache: BTreeMap<(&'k str, &'k Source), tame_index::IndexKrate>,
}

impl<'k> Indices<'k> {
    pub fn load(krates: &'k Krates, cargo_home: crate::PathBuf) -> Self {
        let mut indices = Vec::<(&Source, Result<ComboIndexCache, Error>)>::new();

        for source in krates
            .krates()
            .filter_map(|k| k.source.as_ref().filter(|s| s.is_registry()))
        {
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

                    index::SparseIndex::with_path(cargo_home.clone(), &surl)
                        .map(ComboIndexCache::Sparse)
                }
                (SourceKind::CratesIo(false) | SourceKind::Registry, url) => {
                    let url = url
                        .map(|u| u.as_str())
                        .unwrap_or(tame_index::CRATES_IO_INDEX);

                    index::GitIndex::with_path(cargo_home.clone(), &url).map(ComboIndexCache::Git)
                }
                _ => unreachable!("source {source:?} is a registry, but not git nor sparse?"),
            };

            indices.push((source, index));
        }

        // Load the current entries into an in-memory cache so we can hopefully
        // remove any I/O in the rest of the check
        let set: std::collections::BTreeSet<_> = krates
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
                    .find_map(|(url, index)| index.as_ref().ok().filter(|_i| src == *url))?;

                index
                    .cached_krate(name.try_into().ok()?)
                    .ok()?
                    .map(|ik| ((name, src), ik))
            })
            .collect();

        Self { indices, cache }
    }

    #[inline]
    pub fn is_yanked(&self, krate: &'k Krate) -> anyhow::Result<bool> {
        // Ignore non-registry crates when checking, as a crate sourced
        // locally or via git can have the same name as a registry package
        let Some(src) = krate.source.as_ref().filter(|s| s.is_registry()) else { return Ok(false) };

        let index_krate = if let Some(ik) = self.cache.get(&(krate.name.as_str(), src)) {
            Cow::Borrowed(ik)
        } else {
            let index = self
                .indices
                .iter()
                .find_map(|(url, index)| (src == *url).then_some(index.as_ref()))
                .context("unable to find source index")?
                .map_err(|err| anyhow::anyhow!("failed to load index: {err:#}"))?;

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
