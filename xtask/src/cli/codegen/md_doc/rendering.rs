use super::{Doc, SchemaKey, Section, SectionData, TypeInfo};
use crate::cli::codegen::md_doc::{SchemaKeyOrigin, SchemaKeySegment};
use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use itertools::Itertools;
use serde_json::{json, Value};

pub(crate) struct RenderingConfig {
    pub(crate) root_file_base: RenderedSection,
}

pub(crate) struct File {
    path: Utf8PathBuf,
    rendered: RenderedSection,
}

#[derive(Clone, Debug)]
pub(crate) struct RenderedSection {
    header: String,
    body: String,
    children: Vec<RenderedSection>,
}

impl Doc {
    pub(crate) fn render(&self, cfg: &RenderingConfig) -> Vec<File> {
        let root_sections = self.root.children.iter().map(|section| {
            let key = &section.data.key;
            let header = format!("The `[{key}]` section");
            let body = format!("See [{key} config]({key}/cfg.html) for more info.");
            RenderedSection::leaf(header, body)
        });

        let mut rendered = cfg.root_file_base.clone();
        rendered.children.extend(root_sections);

        let root = File::new("cfg.md", rendered);

        let child_files = self.root.children.iter().map(|section| {
            let rendered = section.render();

            let key = &section.data.key;

            File::new(format!("{key}/cfg.md"), rendered)
        });

        let type_index_sections = self.type_index.values().map(Section::render).collect();

        let type_index = RenderedSection {
            header: "Type Index".to_owned(),
            body: "This is an index of common types used across the schema.".to_owned(),
            children: type_index_sections,
        };

        let type_index = File::new("type-index.md", type_index);

        itertools::chain([root, type_index], child_files).collect()
    }
}

impl RenderedSection {
    pub(crate) fn leaf(header: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            body: body.into(),
            children: vec![],
        }
    }

    /// Render the section as markdown with the headers starting at the given level
    fn to_markdown(&self, level: usize) -> String {
        let header = self.header.clone();
        let sharps = "#".repeat(level);
        let header = format!("{sharps} {header}");
        let body = self.body.clone();

        let children = self
            .children
            .iter()
            .map(|child| child.to_markdown(level + 1));

        itertools::chain([header, body], children).join("\n\n")
    }
}

impl Section {
    fn render(&self) -> RenderedSection {
        let children = [
            self.data.enum_doc(),
            self.data.default(),
            self.data.examples(),
        ];

        let child_schemas = self.children.iter().map(Section::render);

        let children = children
            .into_iter()
            .flatten()
            .chain(child_schemas)
            .collect();

        let header = self.data.header();

        RenderedSection {
            header,
            body: self.data.render_body(),
            children,
        }
    }
}

impl SectionData {
    fn header(&self) -> String {
        if let SchemaKeyOrigin::Definition(def) = &self.key.root {
            return format!("`{def}`");
        }
        let last_segment = self.key.segments.last().unwrap_or_else(|| {
            panic!(
                "Last segment must always be present in a key with the origin \
                 in root schema, but got empty key segments list: {:#?}",
                self.key
            )
        });

        match last_segment {
            SchemaKeySegment::Field(_) => format!("`{}`", self.key),
            SchemaKeySegment::Index => "Items".to_owned(),
            SchemaKeySegment::Variant(variant_name) => format!("Variant: `{variant_name}`"),
        }
    }

    fn render_body(&self) -> String {
        let top = [&self.type_info(), &self.format(), &self.field_requirement()];

        let top = top.into_iter().flatten().join("<br>\n");

        let parts = [&Some(top), &self.title, &self.description];

        let body = parts.into_iter().flatten().join("\n\n");

        body
    }

    fn field_requirement(&self) -> Option<String> {
        let SchemaKeySegment::Field(field) = self.key.segments.last()? else {
            return None;
        };

        let requirement = match field.required {
            true => "yes",
            false => "no",
        };
        Some(format!("**Required:** `{requirement}`"))
    }

    fn format(&self) -> Option<String> {
        let format = self
            .format
            .as_ref()
            .or_else(|| self.type_index_ref.as_ref()?.format.as_ref())?;

        Some(format!("**Format:** `{format}`"))
    }

    fn type_info(&self) -> Option<String> {
        let ty_ref = self.type_index_ref.as_ref().map(|ty_ref| {
            let definition = &ty_ref.definition;
            let anchor = definition.to_lowercase();
            format!("[`{definition}`](/checks2/type-index.html#{anchor})")
        });

        let ty = self
            .ty
            .as_ref()
            .or_else(|| self.type_index_ref.as_ref()?.ty.as_ref());

        let ty = if ty_ref.is_some() {
            ty.map(|ty| format!("`({ty})`"))
        } else {
            ty.map(|ty| format!("`{ty}`"))
        };

        let parts = [ty_ref, ty].iter().flatten().join(" ");

        if parts.is_empty() {
            return None;
        }

        Some(format!("**Type:** {parts}"))
    }

    fn default(&self) -> Option<RenderedSection> {
        self.default
            .as_ref()
            .map(|value| self.value_showcase("Default", value))
    }

    fn value_showcase(&self, header: &str, value: &Value) -> RenderedSection {
        let toml = self.key.render_value(value);
        RenderedSection::leaf(header, toml)
    }

    fn examples(&self) -> Option<RenderedSection> {
        match self.examples.as_slice() {
            [] => return None,
            [example] => return Some(self.value_showcase("Example", example)),
            _ => {}
        };

        let examples = self
            .examples
            .iter()
            .map(|value| {
                // Properly indent the example to fit into the markdown
                // list syntax
                let example = self.key.render_value(value);
                let example = example
                    .lines()
                    .enumerate()
                    .format_with("\n", |(i, line), f| {
                        if i == 0 {
                            f(&line)
                        } else {
                            f(&format_args!("  {line}"))
                        }
                    });

                format!("- {example}")
            })
            .join("\n");

        Some(RenderedSection::leaf("Examples", examples))
    }

    fn enum_doc(&self) -> Option<RenderedSection> {
        let doc = self
            .enum_schema
            .as_ref()?
            .iter()
            .map(|enum_variant| {
                let (value, description) = enum_variant.value_and_description();
                let value = format!("`{value}`");
                let doc = itertools::chain([value.as_str()], description).format(" - ");

                format!("- {doc}")
            })
            .join("\n\n");

        Some(RenderedSection::leaf("Possible values", doc))
    }
}

impl SchemaKey {
    fn render_value(&self, value: &Value) -> String {
        fn wrap(key: &[SchemaKeySegment], value: Value) -> Value {
            let Some((first, rest)) = key.split_first() else {
                return value;
            };

            match first {
                SchemaKeySegment::Field(_) => {
                    json!({ first.to_string(): wrap(rest, value) })
                }
                SchemaKeySegment::Index => {
                    json!([wrap(rest, value)])
                }
                // We use untagged one-of representations, so there is nothing
                // to wrap here
                SchemaKeySegment::Variant(_) => value,
            }
        }

        let mut value = wrap(&self.segments, value.clone());

        let is_primitive = !value.is_object() && !value.is_array();

        // TOML doesn't support primitive values at the top level, so we use
        // a hack to wrap it into an object
        if is_primitive {
            value = json!({ "value": value });
        }

        let toml = toml::to_string_pretty(&value).unwrap_or_else(|err| {
            panic!(
                "Failed to serialize value to TOML: {err:#?}\n\
                Value: {value:#?}",
            )
        });

        format!(
            "```toml\n\
            {toml}\
            ```",
        )
    }
}

impl File {
    fn new(path: impl Into<Utf8PathBuf>, rendered: RenderedSection) -> Self {
        Self {
            path: path.into(),
            rendered,
        }
    }

    pub(crate) fn write(&self, prefix: impl AsRef<Utf8Path>) -> Result<()> {
        let path = prefix.as_ref().join(&self.path);

        std::fs::create_dir_all(path.parent().unwrap())?;

        std::fs::write(&path, self.rendered.to_markdown(1))
            .with_context(|| format!("Failed to write to file: {path}"))
    }
}
