use crate::{Krate, Krates, Source};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::collections::BTreeMap;
use tame_index::{index::ComboIndexCache, Error, IndexLocation, IndexUrl};

type YankMap = Vec<(semver::Version, bool)>;

#[derive(Clone)]
pub enum Entry {
    Map(YankMap),
    Error(String),
}

pub struct Indices<'k> {
    pub indices: Vec<(&'k Source, Result<ComboIndexCache, Error>)>,
    pub cache: BTreeMap<(&'k str, &'k Source), Entry>,
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

            let index_url = match source {
                Source::CratesIo(_is_sparse) => IndexUrl::crates_io(
                    Some(krates.workspace_root().to_owned()),
                    Some(&cargo_home),
                    None,
                ),
                Source::Sparse(url) | Source::Registry(url) => Ok(url.as_str().into()),
                Source::Git { .. } => unreachable!(),
            };

            let index = index_url.and_then(|iu| {
                ComboIndexCache::new(IndexLocation::new(iu).with_root(Some(cargo_home.clone())))
            });

            indices.push((source, index));
        }

        #[allow(clippy::blocks_in_conditions)]
        let cargo_package_lock =
            match tame_index::utils::flock::LockOptions::cargo_package_lock(Some(cargo_home))
                .expect("unreachable")
                .shared()
                .lock(|path| {
                    log::info!("waiting for {path}...");
                    Some(std::time::Duration::from_secs(60))
                }) {
                Ok(fl) => fl,
                Err(err) => {
                    log::error!("unable to acquire cargo global package lock: {err:#}");
                    tame_index::utils::flock::FileLock::unlocked()
                }
            };

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
            .map(|(name, src)| {
                let read_entry = || -> Result<Entry, String> {
                    let res = match indices
                        .iter()
                        .find_map(|(url, index)| (src == *url).then_some(index))
                        .ok_or_else(|| "unable to locate index".to_owned())?
                    {
                        Ok(index) => {
                            match index.cached_krate(
                                name.try_into()
                                    .map_err(|e: tame_index::Error| e.to_string())?,
                                &cargo_package_lock,
                            ) {
                                Ok(Some(ik)) => {
                                    let yank_map = Self::load_index_krate(ik);
                                    Entry::Map(yank_map)
                                }
                                Ok(None) => Entry::Error(
                                    "unable to locate index entry for crate".to_owned(),
                                ),
                                Err(err) => Entry::Error(format!("{err:#}")),
                            }
                        }
                        Err(err) => Entry::Error(format!("{err:#}")),
                    };

                    Ok(res)
                };

                ((name, src), read_entry().unwrap_or_else(Entry::Error))
            })
            .collect();

        Self { indices, cache }
    }

    #[inline]
    fn load_index_krate(ik: tame_index::IndexKrate) -> YankMap {
        ik.versions
            .into_iter()
            .filter_map(|iv| Some((iv.version.parse().ok()?, iv.yanked)))
            .collect()
    }

    #[inline]
    pub fn is_yanked(&self, krate: &'k Krate) -> Result<bool, String> {
        // Ignore non-registry crates when checking, as a crate sourced
        // locally or via git can have the same name as a registry package
        let Some(src) = krate.source.as_ref().filter(|s| s.is_registry()) else {
            return Ok(false);
        };

        let Some(entry) = self.cache.get(&(krate.name.as_str(), src)) else {
            panic!("we should have a cache entry for {krate} by now");
        };

        match entry {
            Entry::Map(cache_entry) => {
                let is_yanked = cache_entry
                    .iter()
                    .find_map(|kv| (kv.0 == krate.version).then_some(kv.1));

                is_yanked.ok_or_else(|| format!("unable to locate version '{}'", krate.version))
            }
            Entry::Error(err) => Err(err.clone()),
        }
    }
}
