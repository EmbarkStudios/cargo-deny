#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GitSpec {
    Rev,
    Tag,
    Branch,
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum DependencySource {
    Version {
        version: Option<String>,
        path: Option<String>,
        registry: Option<String>,
    },
    Git {
        repo: String,
        spec: Option<(GitSpec, String)>,
    },
}

/// A dependency handled by Cargo
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Dependency {
    /// The name of the dependency (as it is set in its `Cargo.toml` and known to crates.io)
    pub name: String,
    optional: bool,
    /// List of features to add (or None to keep features unchanged).
    pub features: Option<Vec<String>>,
    default_features: bool,
    source: DependencySource,
    /// If the dependency is renamed, this is the new name for the dependency
    /// as a string.  None if it is not renamed.
    rename: Option<String>,
}

impl Default for Dependency {
    fn default() -> Dependency {
        Dependency {
            name: "".into(),
            rename: None,
            optional: false,
            features: None,
            default_features: true,
            source: DependencySource::Version {
                version: None,
                path: None,
                registry: None,
            },
        }
    }
}

impl Dependency {
    /// Create a new dependency with a name
    pub fn new(name: String) -> Dependency {
        Dependency {
            name,
            ..Dependency::default()
        }
    }

    /// Set dependency to a given version
    pub fn set_version(mut self, mut version: String) -> Dependency {
        // versions might have semver metadata appended which we do not want to
        // store in the cargo toml files.  This would cause a warning upon compilation
        // ("version requirement […] includes semver metadata which will be ignored")
        if let Some(ind) = version.find('+') {
            version.truncate(version.len() - ind - 1);
        }

        let (old_path, old_registry) = match self.source {
            DependencySource::Version { path, registry, .. } => (path, registry),
            _ => (None, None),
        };
        self.source = DependencySource::Version {
            version: Some(version),
            path: old_path,
            registry: old_registry,
        };
        self
    }

    /// Set dependency to a given repository
    pub fn set_git(mut self, repo: &str, spec: Option<(GitSpec, String)>) -> Dependency {
        self.source = DependencySource::Git {
            repo: repo.into(),
            spec,
        };
        self
    }

    /// Set dependency to a given path
    pub fn set_path(mut self, path: &str) -> Dependency {
        let old_version = match self.source {
            DependencySource::Version { version, .. } => version,
            _ => None,
        };
        self.source = DependencySource::Version {
            version: old_version,
            path: Some(path.replace('\\', "/")),
            registry: None,
        };
        self
    }

    /// Set whether the dependency is optional
    pub fn set_optional(mut self, opt: bool) -> Dependency {
        self.optional = opt;
        self
    }

    /// Set features as an array of string (does some basic parsing)
    pub fn set_features(mut self, features: Option<Vec<String>>) -> Dependency {
        self.features = features.map(|f| {
            f.iter()
                .map(|x| x.split(' ').map(String::from))
                .flatten()
                .filter(|s| !s.is_empty())
                .collect::<Vec<String>>()
        });
        self
    }

    /// Set the value of default-features for the dependency
    pub fn set_default_features(mut self, default_features: bool) -> Dependency {
        self.default_features = default_features;
        self
    }

    /// Set the alias for the dependency
    pub fn set_rename(mut self, rename: &str) -> Dependency {
        self.rename = Some(rename.into());
        self
    }

    /// Get the dependency name as defined in the manifest,
    /// that is, either the alias (rename field if Some),
    /// or the official package name (name field).
    pub fn name_in_manifest(&self) -> &str {
        &self.rename().unwrap_or(&self.name)
    }

    /// Set the value of registry for the dependency
    pub fn set_registry(mut self, registry: &str) -> Dependency {
        let old_version = match self.source {
            DependencySource::Version { version, .. } => version,
            _ => None,
        };
        self.source = DependencySource::Version {
            version: old_version,
            path: None,
            registry: Some(registry.into()),
        };
        self
    }

    /// Get version of dependency
    pub fn version(&self) -> Option<&str> {
        if let DependencySource::Version {
            version: Some(ref version),
            ..
        } = self.source
        {
            Some(version)
        } else {
            None
        }
    }

    /// Get the alias for the dependency (if any)
    pub fn rename(&self) -> Option<&str> {
        match &self.rename {
            Some(rename) => Some(&rename),
            None => None,
        }
    }

    /// Convert dependency to TOML
    ///
    /// Returns a tuple with the dependency's name and either the version as a `String`
    /// or the path/git repository as an `InlineTable`.
    /// (If the dependency is set as `optional` or `default-features` is set to `false`,
    /// an `InlineTable` is returned in any case.)
    pub fn to_toml(&self) -> (String, toml_edit::Item) {
        let data: toml_edit::Item = match (
            self.optional,
            self.features.as_ref(),
            self.default_features,
            self.source.clone(),
            self.rename.as_ref(),
        ) {
            // Extra short when version flag only
            (
                false,
                None,
                true,
                DependencySource::Version {
                    version: Some(v),
                    path: None,
                    registry: None,
                },
                None,
            ) => toml_edit::value(v),
            // Other cases are represented as an inline table
            (optional, features, default_features, source, rename) => {
                let mut data = toml_edit::InlineTable::default();

                match source {
                    DependencySource::Version {
                        version,
                        path,
                        registry,
                    } => {
                        if let Some(v) = version {
                            data.get_or_insert("version", v);
                        }
                        if let Some(p) = path {
                            data.get_or_insert("path", p);
                        }
                        if let Some(r) = registry {
                            data.get_or_insert("registry", r);
                        }
                    }
                    DependencySource::Git { repo, spec } => {
                        data.get_or_insert("git", repo);
                        spec.map(|s| {
                            let spec_str = match s.0 {
                                GitSpec::Branch => "branch",
                                GitSpec::Rev => "rev",
                                GitSpec::Tag => "tag",
                            };

                            data.get_or_insert(spec_str, s.1)
                        });
                    }
                }
                if self.optional {
                    data.get_or_insert("optional", optional);
                }
                if let Some(features) = features {
                    use std::iter::FromIterator;
                    let features = toml_edit::Value::from_iter(features.iter().cloned());
                    data.get_or_insert("features", features);
                }
                if !self.default_features {
                    data.get_or_insert("default-features", default_features);
                }
                if rename.is_some() {
                    data.get_or_insert("package", self.name.clone());
                }

                data.fmt();
                toml_edit::value(toml_edit::Value::InlineTable(data))
            }
        };

        (self.name_in_manifest().to_string(), data)
    }
}
