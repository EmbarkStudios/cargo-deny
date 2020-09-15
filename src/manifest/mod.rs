//! This is basically a copy of some of cargo-edit, which is focused on
//! being a CLI and has a lot of dependencies that can be annoying to upgrade
//! throughout our graph, so for now we just copy some pieces we need

fn merge_inline_table(old_dep: &mut toml_edit::Item, new: &toml_edit::Item) {
    for (k, v) in new
        .as_inline_table()
        .expect("expected an inline table")
        .iter()
    {
        old_dep[k] = toml_edit::value(v.clone());
    }
}

fn merge_dependencies(old_dep: &mut toml_edit::Item, new: &Dependency) {
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
        t.fmt()
    }
}

struct Manifest {
    pub doc: toml_edit::Document,
}

impl Manifest {
    pub fn get_sections(&self) -> Vec<(Vec<String>, toml_edit::Item)> {
        let mut sections = Vec::new();

        for dependency_type in &["dev-dependencies", "build-dependencies", "dependencies"] {
            // Dependencies can be in the three standard sections...
            if self.data[dependency_type].is_table_like() {
                sections.push((
                    vec![String::from(*dependency_type)],
                    self.data[dependency_type].clone(),
                ))
            }

            // ... and in `target.<target>.(build-/dev-)dependencies`.
            let target_sections = self
                .data
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

    pub fn update_table_named_entry(
        &mut self,
        table_path: &[String],
        item_name: &str,
        dep: &Dependency,
        dry_run: bool,
    ) -> Result<()> {
        let table = self.get_table(table_path)?;
        let new_dep = dep.to_toml().1;

        // If (and only if) there is an old entry, merge the new one in.
        if !table[item_name].is_none() {
            // if let Err(e) = print_upgrade_if_necessary(&dep.name, &table[item_name], &new_dep) {
            //     eprintln!("Error while displaying upgrade message, {}", e);
            // }
            if !dry_run {
                merge_dependencies(&mut table[item_name], dep);
                if let Some(t) = table.as_inline_table_mut() {
                    t.fmt()
                }
            }
        }

        Ok(())
    }

    pub fn upgrade(
        &mut self,
        dependency: &Dependency,
        dry_run: bool,
        skip_compatible: bool,
    ) -> Result<()> {
        for (table_path, table) in self.get_sections() {
            let table_like = table.as_table_like().expect("Unexpected non-table");
            for (name, toml_item) in table_like.iter() {
                let dep_name = toml_item
                    .as_table_like()
                    .and_then(|t| t.get("package").and_then(|p| p.as_str()))
                    .unwrap_or(name);
                if dep_name == dependency.name {
                    if skip_compatible {
                        if let Some(old_version) = get_version(toml_item)?.as_str() {
                            if old_version_compatible(dependency, old_version)? {
                                continue;
                            }
                        }
                    }
                    self.manifest.update_table_named_entry(
                        &table_path,
                        &name,
                        dependency,
                        dry_run,
                    )?;
                }
            }
        }

        let mut file = self.get_file()?;
        self.write_to_file(&mut file)
            .chain_err(|| "Failed to write new manifest contents")
    }
}
