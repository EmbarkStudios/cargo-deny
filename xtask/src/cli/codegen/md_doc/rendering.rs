use super::{SchemaKey, Section, SectionData};
use crate::cli::codegen::md_doc::SchemaKeySegment;
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

impl super::Doc {
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

        itertools::chain([root], child_files).collect()
    }
}

impl Section {
    fn render(&self) -> RenderedSection {
        // let properties = gen_object_doc(root, 1, section, section.inner.try_as_object()?)?;

        // let section_key = &section.key.last().unwrap();

        //         let content = format!(
        //             "\
        // # The `[{section_key}]` section

        // {properties}
        // ",
        //         );

        //         write_file(format!("{section_key}/cfg.md"), &content)

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

        // if items.inner.is_primitive() && gen_generic_details(&items, paragraph_level)?.is_empty() {
        //     let ty = primitive_type_label(&items)?;
        //     return Ok(format!(
        //         "`array of {ty}`\n\n\
        //         {array_details}"
        //     ));
        // }

        RenderedSection {
            header,
            body: self.data.render_body(),
            children,
        }
    }
}

impl SectionData {
    fn header(&self) -> String {
        let suffix = match self.key.last_segment() {
            SchemaKeySegment::Field(field) => {
                let requirement = match field.required {
                    true => "required",
                    false => "optional",
                };
                format!("({requirement})")
            }
            SchemaKeySegment::Index => return "Items".to_owned(),
            SchemaKeySegment::Variant(variant_name) => format!("(as {variant_name})"),
        };

        let prefix = &self.key;

        format!("`{prefix}` {suffix}")
    }

    fn render_body(&self) -> String {
        let type_label = self.type_label().map(|label| format!("`{label}`"));

        let parts = [&type_label, &self.title, &self.description];

        let body = parts.into_iter().flatten().join("\n\n");

        body
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

    fn type_label(&self) -> Option<String> {
        let ty = self.ty.as_deref()?;

        let format = self.format.as_deref().map(|format| format!("({format})"));

        let label = itertools::chain([ty], format.as_deref()).join(" ");

        Some(label)
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
                            f(&format_args!("    {}", line))
                        }
                    });

                format!("- {example}")
            })
            .join("\n\n");

        Some(RenderedSection::leaf("Examples", examples))
    }

    fn enum_doc(&self) -> Option<RenderedSection> {
        let doc = self
            .enum_schema
            .as_ref()?
            .iter()
            .map(|enum_variant| {
                let (value, description) = enum_variant.value_and_description();
                let value = value.to_string();
                let doc = itertools::chain([value.as_str()], description).join("-");
                doc
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

        let value = wrap(&self.segments, value.clone());

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

        std::fs::create_dir_all(&path.parent().unwrap())?;

        std::fs::write(&path, &self.rendered.to_markdown(1))
            .with_context(|| format!("Failed to write to file: {path}"))
    }
}
