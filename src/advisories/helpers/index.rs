use crate::{Krate, Krates, PathBuf};
use url::Url;

pub(super) enum Index {
    Git(crates_index::Index),
    Http(crates_index::SparseIndex),
}

pub(super) struct Indices<'k> {
    indices: Vec<(&'k crate::Source, Option<Index>)>,
}

impl<'k> Indices<'k> {
    pub(super) fn load(krates: &'k Krates, disable_crates_io_yank_checking: bool) -> Self {
        let mut indices = Vec::<(&crate::Source, Option<Index>)>::new();

        // As of Rust 1.68, the sparse index is stable, but not the default and
        // must be manually enabled by users via .config/cargo.toml or env. This
        // doesn't actually change the source for crates.io packages, so we detect
        // if it's being used by checking the manifest paths
        if let Some(ksrc) = krates.krates().find_map(|k| {
            k.source.as_ref().filter(|_s| {
                k.is_crates_io()
                    && k.manifest_path
                        .as_str()
                        .contains("index.crates.io-6f17d22bba15001f")
            })
        }) {
            // SparseIndex::from_url doesn't fail if the sparse index doesn't
            // actually exist on disk :p
            let index = match crates_index::SparseIndex::from_url(crate::CRATES_IO_SPARSE)
                .and_then(|index| index.index_config().map(|_| index))
            {
                Ok(index) => Some(Index::Http(index)),
                Err(err) => {
                    log::error!(
                        "failed to load crates.io sparse index{}: {err}",
                        if crates_io_git_fallback {
                            ", falling back to git registry"
                        } else {
                            ""
                        }
                    );

                    if crates_io_git_fallback && krates.krates().any(|k| k.is_crates_io()) {
                        match crates_index::Index::new_cargo_default() {
                            Ok(i) => Some(Index::Git(i)),
                            Err(err) => {
                                log::warn!("failed to load crates.io git index: {err}");
                                None
                            }
                        }
                    } else {
                        None
                    }
                }
            };

            indices.push((ksrc, index));
        }

        for (krate, source) in krates
            .krates()
            .filter_map(|k| k.source.as_ref().map(|s| (k, s)))
        {
            if indices.iter().any(|(src, _)| *src == source) {
                continue;
            }

            use crate::SourceKind;
            let index = match (source.kind, source.url()) {
                (SourceKind::CratesIo(true) | SourceKind::Sparse, url) => {
                    let surl = if let Some(url) = url {
                        format!("sparse+{url}")
                    } else {
                        crate::CRATES_IO_SPARSE.to_owned()
                    };

                    match crates_index::SparseIndex::from_url(&surl) {
                        Ok(index) => Some(Index::Http(index)),
                        Err(err) => {
                            log::warn!("failed to load sparse index '{surl}' used by crate '{krate}': {err}");
                            None
                        }
                    }
                }
                (SourceKind::CratesIo(false), None) => {
                    match crates_index::Index::new_cargo_default() {
                        Ok(i) => Some(Index::Git(i)),
                        Err(err) => {
                            log::warn!(
                                "failed to load crates.io index used by crate '{krate}': {err}"
                            );
                            None
                        }
                    }
                }
                (SourceKind::Registry, Some(url)) => {
                    match crates_index::Index::from_url(url.as_str()) {
                        Ok(i) => Some(Index::Git(i)),
                        Err(err) => {
                            log::warn!(
                                "failed to load index '{url}' used by crate '{krate}': {err}"
                            );
                            None
                        }
                    }
                }
                _ => None,
            };

            indices.push((source, index));
        }

        Self { indices }
    }

    #[inline]
    pub(super) fn is_yanked(&self, krate: &Krate) -> anyhow::Result<bool> {
        // Ignore non-registry crates when checking, as a crate sourced
        // locally or via git can have the same name as a registry package
        let Some(src) = krate.source.as_ref().filter(|s| s.is_registry()) else { return Ok(false) };

        let index = self
            .indices
            .iter()
            .find_map(|(url, index)| index.as_ref().filter(|_i| src == *url))
            .context("failed to load source index")?;

        let index_krate = match index {
            Index::Git(gindex) => gindex
                .crate_(&krate.name)
                .context("failed to find crate in git index")?,
            Index::Http(hindex) => hindex
                .crate_from_cache(&krate.name)
                .context("failed to find crate in sparse index")?,
        };

        Ok(index_krate
            .versions()
            .iter()
            .any(|kv| kv.version() == krate.version.to_string() && kv.is_yanked()))
    }
}

fn url_to_index_path(mut root_path: PathBuf, url: &Url) -> anyhow::Result<PathBuf> {
    let (ident, _) = super::url_to_local_dir(url.as_str())?;
    db_path.push(ident);

    Ok(db_path)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn correct_crates_io_hashes() {
        let mut path = PathBuf::new();
        url_to_index_path(path, &Url::parse(crate::CRATES_IO_GIT).unwrap()).unwrap();
    }
}
