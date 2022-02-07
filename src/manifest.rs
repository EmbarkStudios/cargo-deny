//! This is basically a copy of some of cargo-edit, which is focused on
//! being a CLI and has a lot of dependencies that can be annoying to upgrade
//! throughout our graph, so for now we just copy some pieces we need

use anyhow::Error;

pub mod dependency;

pub use dependency as dep;

fn merge_inline_table(old_dep: &mut toml_edit::Item, new: &toml_edit::Item) {
    for (k, v) in new
        .as_inline_table()
        .expect("expected an inline table")
        .iter()
    {
        old_dep[k] = toml_edit::value(v.clone());
    }
}

fn str_or_1_len_table(item: &toml_edit::Item) -> bool {
    item.is_str() || item.as_table_like().map_or(false, |t| t.len() == 1)
}

fn merge_dependencies(old_dep: &mut toml_edit::Item, new: &dep::Dependency) {
    assert!(!old_dep.is_none());

    let new_toml = new.to_toml().1;

    if str_or_1_len_table(old_dep) {
        // The old dependency is just a version/git/path. We are safe to overwrite.
        *old_dep = new_toml;
    } else if old_dep.is_table_like() {
        for key in &["version", "path", "git"] {
            // remove this key/value pairs
            old_dep[key] = toml_edit::Item::None;
        }
        if let Some(name) = new_toml.as_str() {
            old_dep["version"] = toml_edit::value(name);
        } else {
            merge_inline_table(old_dep, &new_toml);
        }
    } else {
        unreachable!("Invalid old dependency type");
    }

    if let Some(t) = old_dep.as_inline_table_mut() {
        t.fmt();
    }
}

pub struct Manifest {
    pub doc: toml_edit::Document,
}

impl Manifest {
    pub fn get_dep_sections(&self) -> Vec<(Vec<String>, toml_edit::Item)> {
        let mut sections = Vec::new();

        for dependency_type in &["dev-dependencies", "build-dependencies", "dependencies"] {
            // Dependencies can be in the three standard sections...
            if self.doc[dependency_type].is_table_like() {
                sections.push((
                    vec![String::from(*dependency_type)],
                    self.doc[dependency_type].clone(),
                ));
            }

            // ... and in `target.<target>.(build-/dev-)dependencies`.
            let target_sections = self
                .doc
                .as_table()
                .get("target")
                .and_then(toml_edit::Item::as_table_like)
                .into_iter()
                .flat_map(toml_edit::TableLike::iter)
                .filter_map(|(target_name, target_table)| {
                    let dependency_table = &target_table[dependency_type];
                    dependency_table.as_table_like().map(|_| {
                        (
                            vec![
                                "target".to_string(),
                                target_name.to_string(),
                                String::from(*dependency_type),
                            ],
                            dependency_table.clone(),
                        )
                    })
                });

            sections.extend(target_sections);
        }

        sections
    }

    pub fn get_table<'a>(
        &'a mut self,
        table_path: &[String],
    ) -> Result<&'a mut toml_edit::Item, Error> {
        /// Descend into a manifest until the required table is found.
        fn descend<'a>(
            input: &'a mut toml_edit::Item,
            path: &[String],
        ) -> Result<&'a mut toml_edit::Item, Error> {
            if let Some(segment) = path.get(0) {
                let value = input[&segment].or_insert(toml_edit::table());

                if value.is_table_like() {
                    descend(value, &path[1..])
                } else {
                    anyhow::bail!("Unable to find '{}'", segment);
                }
            } else {
                Ok(input)
            }
        }

        descend(self.doc.as_item_mut(), table_path)
    }

    pub fn update_table_named_entry(
        &mut self,
        table_path: &[String],
        item_name: &str,
        dep: &dep::Dependency,
    ) -> Result<(), Error> {
        let table = self.get_table(table_path)?;

        // If (and only if) there is an old entry, merge the new one in.
        if !table[item_name].is_none() {
            merge_dependencies(&mut table[item_name], dep);
            if let Some(t) = table.as_inline_table_mut() {
                t.fmt();
            }
        }

        Ok(())
    }

    pub fn upgrade(&mut self, deps: &[dep::Dependency]) -> Result<(), Error> {
        for (table_path, table) in self.get_dep_sections() {
            let table_like = table.as_table_like().expect("Unexpected non-table");
            for (name, toml_item) in table_like.iter() {
                let dep_name = toml_item
                    .as_table_like()
                    .and_then(|t| t.get("package").and_then(|p| p.as_str()))
                    .unwrap_or(name);

                if let Some(update_dep) = deps.iter().find(|dep| dep.name == dep_name) {
                    self.update_table_named_entry(&table_path, name, update_dep)?;
                }
            }
        }

        Ok(())
    }
}

impl std::str::FromStr for Manifest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let doc: toml_edit::Document = s.parse()?;
        Ok(Self { doc })
    }
}
