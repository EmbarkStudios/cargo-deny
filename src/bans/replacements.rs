//! Data for the crates.io crates that can be partially for fully replaced by `std` is sourced from <https://github.com/rust-lang/std-replacement-data>
//!
//! Current commit: b55f457
//!
//! For now I'm manually updating this for a couple of reasons:
//!
//! 1. The number of crates is fairly low at the moment
//! 2. The JSON data is not terribly useful as it is just a human readable text blob and a single url
//! 3. Retrieving the JSON would require an HTTP client, which I very much want to avoid
//! 4. Keeping a git clone would be doable, but puts us back in the same position that we need to parse and interpret the data for it to be useful

use anyhow::Context;

pub struct Replacement {
    data: &'static [u8],
}

impl Replacement {
    pub fn iter(&self) -> ReplacementIter {
        // The first 3 bytes are the number of items in each bucket
        let stable = self.data[0];
        let unstable = self.data[1];
        let unavailable = self.data[2];

        ReplacementIter {
            data: &self.data[3..],
            stable,
            unstable,
            unavailable,
            minor: None,
        }
    }
}

pub enum ReplacementItem {
    /// An API from a crate that has a stable replacement in std/core
    Stable {
        replacement: ApiReplacement,
        /// The minor version the replacement was added
        minor: u8,
    },
    /// An API from a crate that has a replacement in std/core, but which has not been stabilized
    Unstable { replacement: ApiReplacement },
    /// An API from a crate has no replacement in std/core despite other parts of the crate having them
    Unavailable { api: Api },
}

pub struct ReplacementIter {
    data: &'static [u8],
    stable: u8,
    unstable: u8,
    unavailable: u8,
    minor: Option<(u8, u8)>,
}

impl ReplacementIter {
    #[inline]
    fn read_api_replacement(&mut self) -> ApiReplacement {
        let krate = self.read_api();
        let std = self.read_api();
        let note = self.read_str();

        ApiReplacement {
            krate,
            std,
            note: (!note.is_empty()).then_some(note),
        }
    }

    #[inline]
    fn read_api(&mut self) -> Api {
        Api {
            name: self.read_str(),
            url: self.read_str(),
        }
    }

    #[inline]
    #[allow(unsafe_code)]
    fn read_str(&mut self) -> &'static str {
        let len = self.data[0] as usize;
        assert!(self.data.len() > len);
        // SAFETY: We control the input data, which only has utf-8 strings and has correct lengths etc
        let s = unsafe { std::str::from_utf8_unchecked(&self.data[1..1 + len]) };

        self.data = &self.data[1 + len..];

        s
    }
}

impl Iterator for ReplacementIter {
    type Item = ReplacementItem;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.minor.is_some() {
                let replacement = self.read_api_replacement();

                let Some((minor, count)) = &mut self.minor else {
                    unreachable!();
                };
                *count -= 1;

                let item = ReplacementItem::Stable {
                    replacement,
                    minor: *minor,
                };

                if *count == 0 {
                    self.minor = None;
                }

                return Some(item);
            }

            if self.stable > 0 {
                self.stable -= 1;

                self.minor = Some((self.data[0], self.data[1]));
                self.data = &self.data[2..];

                continue;
            }

            if self.unstable > 0 {
                self.unstable -= 1;
                return Some(ReplacementItem::Unstable {
                    replacement: self.read_api_replacement(),
                });
            }

            if self.unavailable > 0 {
                self.unavailable -= 1;
                return Some(ReplacementItem::Unavailable {
                    api: self.read_api(),
                });
            }

            return None;
        }
    }
}

pub struct Api {
    /// The path of the API
    pub name: &'static str,
    /// URL to the documentation or other information about the API
    pub url: &'static str,
}

pub struct ApiReplacement {
    /// The API that has a replacement in std, typically a function or macro
    pub krate: Api,
    /// The API in std
    pub std: Api,
    /// Note about this particular replacement, eg. partial support where a particular feature in the crates.io crate isn't available or there are notable differences
    pub note: Option<&'static str>,
}

#[allow(dead_code)]
struct ReplacementData {
    /// Memory map of the actual data
    inner: memmap2::Mmap,
    /// File lock to prevent write access by other instances of cargo-deny while we have the mmap open
    lock: tame_index::utils::flock::FileLock,
    /// The name of the crate and the block of data it occupies, minus said name
    entries: Vec<(String, &'static [u8])>,
}

#[inline]
#[allow(unsafe_code)]
fn read_str(buf: &[u8]) -> &str {
    let len = buf[0] as usize;
    assert!(buf.len() > len);
    // SAFETY: We control the input data, which only has utf-8 strings and has correct lengths etc
    unsafe { std::str::from_utf8_unchecked(&buf[1..1 + len]) }
}

impl ReplacementData {
    #[allow(unsafe_code)]
    fn load() -> anyhow::Result<Self> {
        let (lock, mut path) = ReplacementCtx::acquire_lock(false)?;
        path.push("all.bin");

        let file =
            std::fs::File::open(&path).with_context(|| format!("failed to open '{path}'"))?;

        // SAFETY: we've retrieved the file lock that prevents other cargo-deny processes from modifying the all.bin file,
        // though that doesn't preclude issues caused by other processes
        let inner = unsafe {
            memmap2::Mmap::map(&file).with_context(|| format!("failed to mmap '{path}'"))?
        };

        let header = inner.get(0..4).context("missing magic")?;
        anyhow::ensure!(header[..3] == [0xcd, 0xcd, 0xcd], "invalid magic");
        anyhow::ensure!(header[3] == 1, "unsupported version");

        let entries = unsafe {
            let mut ptr = inner.as_ptr().byte_add(4).cast::<u32>();
            let count = std::ptr::read_unaligned(ptr);

            anyhow::ensure!(count > 0, "we expected at least 1 entry");

            ptr = ptr.byte_add(4);

            let mut entries = Vec::with_capacity(count as usize);
            let len = inner.len();

            for _ in 0..count {
                let offset = std::ptr::read_unaligned(ptr) as usize;
                entries.push((
                    String::new(),
                    std::slice::from_raw_parts(inner.as_ptr().byte_add(offset), len - offset),
                ));
                ptr = ptr.byte_add(4);
            }

            for i in 0..entries.len() - 1 {
                let next = entries[i + 1].1.as_ptr();
                let this = &mut entries[i];

                let name = read_str(this.1);
                this.0 = name.to_owned();
                let start = this.1.as_ptr().byte_add(1 + name.len());
                this.1 = std::slice::from_raw_parts(start, next.offset_from_unsigned(start));
            }

            let this = entries.last_mut().unwrap();
            let name = read_str(this.1);
            this.0 = name.to_owned();
            let start = this.1.as_ptr().byte_add(1 + name.len());
            this.1 = std::slice::from_raw_parts(start, this.1.len() - 1 - name.len());

            entries
        };

        Ok(Self {
            inner,
            lock,
            entries,
        })
    }

    #[inline]
    fn entry(&self, name: &str) -> Option<Replacement> {
        let Ok(i) = self.entries.binary_search_by_key(&name, |e| e.0.as_str()) else {
            return None;
        };

        Some(Replacement {
            data: self.entries[i].1,
        })
    }
}

#[allow(dead_code)]
pub struct Replacements {
    cfg: super::cfg::StdReplacementConfig,
    hit: bitvec::prelude::BitVec,
    data: ReplacementData,
    replacements: Vec<(crate::Kid, Replacement)>,
}

impl Replacements {
    pub fn emit_diagnostics(
        self,
        krates: &crate::Krates,
        sink: &mut crate::diag::ErrorSink,
        id: crate::diag::FileId,
        colorize: bool,
    ) {
        let severity = self.cfg.level.into();

        for (kid, replacement) in self.replacements {
            let krates::Node::Krate { krate, .. } = krates.node_for_kid(&kid).unwrap() else {
                unreachable!();
            };

            let mut pack = crate::diag::Pack::with_kid(crate::diag::Check::Bans, kid);
            pack.push(super::diags::ReplacedInStd {
                krate,
                replacement,
                severity,
                colorize,
            });
            sink.push(pack);
        }

        for ignore in self
            .hit
            .into_iter()
            .zip(self.cfg.ignore)
            .filter_map(|(hit, ignore)| if !hit { Some(ignore) } else { None })
        {
            sink.push((
                crate::diag::Check::Bans,
                super::diags::UnmatchedReplacementIgnore {
                    ignore_cfg: &ignore,
                    id,
                },
            ));
        }
    }
}

pub struct ReplacementCtx {
    cfg: super::cfg::StdReplacementConfig,
}

impl ReplacementCtx {
    pub fn new(cfg: super::cfg::StdReplacementConfig) -> Self {
        Self { cfg }
    }

    fn acquire_lock(
        exclusive: bool,
    ) -> anyhow::Result<(tame_index::utils::flock::FileLock, crate::PathBuf)> {
        let mut path = crate::PathBuf::from_path_buf(std::env::temp_dir())
            .map_err(|td| anyhow::anyhow!("std::env::temp_dir gave {td:?} which is not utf-8"))?;
        path.push("cargo-deny");
        path.push(".lock");

        let mut lopts = tame_index::utils::flock::LockOptions::new(&path);

        if exclusive {
            lopts = lopts.exclusive(false);
        }

        let lock = lopts
            .lock(|path| {
                log::info!("waiting on std-replacement-data lock '{path}'");
                Some(std::time::Duration::from_secs(60))
            })
            .context("failed to acquire std-replacement-data lock")?;

        path.pop();
        path.push("std-replacement-data");

        Ok((lock, path))
    }

    pub fn sync() -> anyhow::Result<()> {
        let (_lock, path) = Self::acquire_lock(true)?;

        let res = crate::git::fetch_repo(
            "https://github.com/embarkstudios/std-replacement-data",
            &path,
            "collated",
        )?;
        log::debug!("{res} https://github.com/embarkstudios/std-replacement-data");

        Ok(())
    }

    pub fn process(self, krates: &crate::Krates) -> Option<Replacements> {
        use crate::cfg::Scope;

        if self.cfg.scope == Scope::None {
            return None;
        }

        let data = match ReplacementData::load() {
            Ok(d) => d,
            Err(error) => {
                log::error!("failed to load std-replacement-data - {error:#}");
                return None;
            }
        };

        let ws = krates
            .workspace_members()
            .filter_map(|wm| {
                if let krates::Node::Krate { id, .. } = wm {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<std::collections::BTreeSet<_>>();

        let transitive = self.cfg.scope == Scope::Transitive;
        let ignore_version = self.cfg.ignore_rust_version == Scope::Transitive;
        let mut hit = bitvec::vec::BitVec::repeat(false, self.cfg.ignore.len());
        let mut replacements = Vec::new();
        let default_version = self.cfg.rust_version.as_ref();

        let mut versions = smallvec::SmallVec::<[u8; 8]>::new();

        for krate in krates.krates() {
            // The std-replacement-data is specifically made for crates.io, so ignore the crate if it's not sourced there,
            // though this does mean we would miss git or path patches of crates with std replacements, but that seems like
            // a super niche concern
            if !krate.is_crates_io() {
                continue;
            }

            let Some(replacement) = data.entry(&krate.name) else {
                continue;
            };

            versions.clear();

            for r in replacement.iter() {
                let ReplacementItem::Stable { minor, .. } = r else {
                    continue;
                };

                if !versions.contains(&minor) {
                    versions.push(minor);
                }
            }

            let satisfies_rust_version = |dd: &crate::Krate, is_workspace: Option<bool>| -> bool {
                match self.cfg.ignore_rust_version {
                    Scope::All => return true,
                    Scope::None => {}
                    Scope::Workspace | Scope::Transitive => {
                        let is_workspace = is_workspace.unwrap_or_else(|| ws.contains(&dd.id));
                        if is_workspace ^ ignore_version {
                            return true;
                        }
                    }
                }

                dd.rust_version
                    .as_ref()
                    .or(default_version)
                    .is_none_or(|rv| versions.iter().any(|minor| rv.minor >= *minor as _))
            };

            let nid = krates.nid_for_kid(&krate.id).unwrap();
            let dds = krates.direct_dependents(nid);

            match self.cfg.scope {
                Scope::All => {
                    if !dds.iter().any(|dd| satisfies_rust_version(dd.krate, None)) {
                        continue;
                    }
                }
                Scope::Transitive | Scope::Workspace => {
                    if !dds.iter().any(|dd| {
                        let is_workspace = ws.contains(&dd.krate.id);
                        is_workspace ^ transitive
                            && satisfies_rust_version(dd.krate, Some(is_workspace))
                    }) {
                        continue;
                    }
                }
                Scope::None => unreachable!(),
            }

            if let Some(i) = self
                .cfg
                .ignore
                .iter()
                .position(|sr| crate::match_krate(krate, &sr.spec))
            {
                hit.set(i, true);
                continue;
            }

            replacements.push((krate.id.clone(), replacement));
        }

        Some(Replacements {
            cfg: self.cfg,
            hit,
            data,
            replacements,
        })
    }
}
