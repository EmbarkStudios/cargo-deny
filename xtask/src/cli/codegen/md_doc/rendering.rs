use super::{Doc, LeafType, SchemaKey, SchemaKeySegmentKind, Type, TypeDoc, TypeDocNode};
use crate::cli::codegen::md_doc::{SchemaKeyOrigin, SchemaKeySegment};
use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use itertools::Itertools;
use serde_json::{json, Value};

pub(crate) struct Renderer {
    pub(crate) root_file_base: RenderedSection,
}

impl Renderer {
    pub(crate) fn doc(&self, doc: &Doc) -> Vec<File> {
        let root_sections = doc.root.children.iter().map(|type_doc| {
            let key = &type_doc.inner.key;
            let header = format!("The `[{key}]` type_doc");
            let body = format!("See [{key} config]({key}/cfg.html) for more info.");
            let body = itertools::chain(&type_doc.inner.title, [&body]).join("\n\n");

            RenderedSection::leaf(header, body)
        });

        let mut rendered = self.root_file_base.clone();
        rendered.children.extend(root_sections);

        let root = File::new("cfg.md", rendered);

        let child_files = doc.root.children.iter().map(|type_doc| {
            let rendered = self.type_doc_node(type_doc);

            let key = &type_doc.inner.key;

            File::new(format!("{key}/cfg.md"), rendered)
        });

        let type_index_sections = doc
            .type_index
            .values()
            .map(|type_doc| self.type_doc_node(type_doc))
            .collect();

        let type_index = RenderedSection {
            header: "Type Index".to_owned(),
            body: "This is an index of common types used across the schema.".to_owned(),
            children: type_index_sections,
        };

        let type_index = File::new("type-index.md", type_index);

        itertools::chain([root, type_index], child_files).collect()
    }

    fn type_doc_node(&self, type_doc: &TypeDocNode) -> RenderedSection {
        let children = [
            self.enum_doc(&type_doc.inner.ty.inner),
            self.default(&type_doc.inner),
            self.examples(&type_doc.inner),
        ];

        let child_schemas = type_doc
            .children
            .iter()
            .map(|type_doc| self.type_doc_node(type_doc));

        let children = children
            .into_iter()
            .flatten()
            .chain(child_schemas)
            .collect();

        let header = self.type_doc_header(&type_doc.inner);

        RenderedSection {
            header,
            body: self.type_doc_body(&type_doc.inner),
            children,
        }
    }

    fn type_doc_header(&self, type_doc: &TypeDoc) -> String {
        if let SchemaKeyOrigin::Definition(def) = &type_doc.key.root {
            return format!("`{def}`");
        }
        let last_segment = type_doc.key.segments.last().unwrap_or_else(|| {
            panic!(
                "Last segment must always be present in a key with the origin \
                 in root schema, but got empty key segments list: {:#?}",
                type_doc.key
            )
        });

        match &last_segment.kind {
            SchemaKeySegmentKind::Field(_) => format!("`{}`", type_doc.key),
            SchemaKeySegmentKind::Index => "Array item".to_owned(),
            SchemaKeySegmentKind::Variant(variant_name) => format!("Variant: `{variant_name}`"),
        }
    }

    fn type_doc_body(&self, type_doc: &TypeDoc) -> String {
        let top = [
            &self.tag_for_type(type_doc),
            &self.tag_for_required(type_doc),
        ];

        let top = top.iter().copied().flatten().join("<br>\n");

        let parts = [&Some(top), &type_doc.title, &type_doc.description];

        parts.iter().copied().flatten().join("\n\n")
    }

    fn tag_for_required(&self, type_doc: &TypeDoc) -> Option<String> {
        let SchemaKeySegmentKind::Field(field) = &type_doc.key.segments.last()?.kind else {
            return None;
        };

        let requirement = match field.required {
            true => "yes",
            false => "no",
        };
        Some(format!("**Required:** `{requirement}`"))
    }

    fn tag_for_type(&self, type_doc: &TypeDoc) -> Option<String> {
        let ty_ref = type_doc.type_index_ref.as_ref().map(|ty_ref| {
            let definition = &ty_ref.definition;
            let anchor = definition.to_lowercase();
            format!("[`{definition}`](/checks2/type-index.html#{anchor})")
        });

        let ty = self
            .ty(&type_doc.ty)
            .or_else(|| self.ty(&type_doc.type_index_ref.as_ref()?.ty));

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

    fn leaf_type(&self, ty: &LeafType) -> Option<String> {
        let supplementary: Vec<_> = [
            ty.format.as_deref(),
            ty.enum_schema.is_some().then_some("enum"),
        ]
        .into_iter()
        .flatten()
        .collect();

        let rendered = match (&ty.ty, supplementary.as_slice()) {
            (Some(ty), &[]) => ty.clone(),
            (Some(ty), _) => format!("{ty} ({})", supplementary.join(", ")),
            (None, &[]) => return None,
            (None, &[first]) => first.to_owned(),
            (None, &[first, ref rest @ ..]) => format!("{first} ({})", rest.iter().format(", ")),
        };
        Some(rendered)
    }

    fn ty(&self, ty: &Type) -> Option<String> {
        let array_suffix = ty
            .array_items_ty
            .as_ref()
            .and_then(|items| self.leaf_type(items))
            .map(|items_ty| format!("<{items_ty}>"));

        let ty = self.leaf_type(&ty.inner)?;

        Some([Some(ty), array_suffix].into_iter().flatten().collect())
    }

    fn default(&self, type_doc: &TypeDoc) -> Option<RenderedSection> {
        let value = type_doc.default.as_ref()?;
        Some(self.value_showcase(type_doc, "Default", value))
    }

    fn value_showcase(&self, type_doc: &TypeDoc, header: &str, value: &Value) -> RenderedSection {
        let toml = self.value(&type_doc.key, value);
        RenderedSection::leaf(header, toml)
    }

    fn examples(&self, type_doc: &TypeDoc) -> Option<RenderedSection> {
        match type_doc.examples.as_slice() {
            [] => return None,
            [example] => return Some(self.value_showcase(type_doc, "Example", example)),
            _ => {}
        };

        let examples = type_doc
            .examples
            .iter()
            .map(|value| {
                // Properly indent the example to fit into the markdown
                // list syntax
                let example = self.value(&type_doc.key, value);
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

    fn enum_doc(&self, ty: &LeafType) -> Option<RenderedSection> {
        let doc = ty
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

    fn value(&self, key: &SchemaKey, value: &Value) -> String {
        fn wrap(key: &[SchemaKeySegment], value: Value) -> Value {
            let Some((first, rest)) = key.split_first() else {
                return value;
            };

            match &first.kind {
                SchemaKeySegmentKind::Field(_) => {
                    json!({ first.to_string(): wrap(rest, value) })
                }
                SchemaKeySegmentKind::Index => {
                    json!([wrap(rest, value)])
                }
                // We use untagged one-of representations, so there is nothing
                // to wrap here
                SchemaKeySegmentKind::Variant(_) => value,
            }
        }

        let mut value = wrap(&key.segments, value.clone());

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

    /// Render the type_doc as markdown with the headers starting at the given level
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

pub(crate) struct File {
    path: Utf8PathBuf,
    rendered: RenderedSection,
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
