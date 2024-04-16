use super::{
    Doc, LeafType, Path, PathOrigin, PathSegment, Schema, SchemaDoc, SchemaDocData, SchemaNode,
    Type,
};
use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use itertools::Itertools;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) struct Renderer {
    pub(crate) root_file_base: Section,
}

impl Renderer {
    pub(crate) fn doc(&self, doc: &Doc) -> Vec<File> {
        // let root_sections = doc.root.children.iter().map(|schema| {
        //     let key = &schema.doc.path;
        //     let header = format!("`[{key}]`");
        //     let body = format!("See [{key} config]({key}/cfg.html) for more info.");
        //     let body = itertools::chain(&schema.doc.title, [&body]).join("\n\n");

        //     RenderedSection::leaf(header, body)
        // });

        // let mut rendered = self.root_file_base.clone();
        // rendered.children.extend(root_sections);

        // let root = File::new("cfg.md", rendered);

        // let child_files = doc.root.children.iter().map(|schema| {
        //     let rendered = self.schema_node(schema);

        //     let key = &schema.doc.path;

        //     File::new(format!("{key}/cfg.md"), rendered)
        // });

        let root = NamedDocument {
            name: "root".to_owned(),
            document: Document {
                section: self.root_file_base.clone(),
                children: vec![NamedDocument {
                    name: "schema".to_owned(),
                    document: self.schema_node(&doc.root),
                }],
            },
        };

        let type_index = self.type_index(&doc.type_index);

        itertools::chain([root], type_index)
            .flat_map(NamedDocument::into_files)
            .collect()
    }

    fn type_index(&self, type_index: &BTreeMap<String, SchemaNode>) -> Option<NamedDocument> {
        if type_index.is_empty() {
            return None;
        }

        let children = type_index
            .iter()
            .map(|(name, schema)| NamedDocument {
                name: name.clone(),
                document: self.schema_node(schema),
            })
            .collect();

        let section = Section::leaf(
            "Type Index",
            "This is an index of common types used across the schema.",
        );

        let document = Document { section, children };

        Some(NamedDocument {
            name: "type-index".to_owned(),
            document,
        })
    }

    fn schema_node(&self, node: &SchemaNode) -> Document {
        match &node.schema.doc {
            SchemaDoc::Embedded(doc) => self.schema_embedded(&node, doc),
            SchemaDoc::Nested(doc) => self.schema_embedded(&node, doc),
            SchemaDoc::Ref(reference) => self.schema_ref(&node, reference),
        }
    }

    fn schema_ref(&self, node: &SchemaNode, reference: &str) -> Document {
        let (ref_name, url) = reference
            .strip_prefix("#/definitions/")
            .map(|definition| {
                let anchor = definition.to_lowercase();
                (definition, format!("/checks2/type-index.html#{anchor})"))
            })
            .unwrap_or_else(|| ("{ExternalSchema}", reference.to_owned()));

        let section = self.type_reference(&node.schema, ref_name, &url);

        Document::leaf(section)
    }

    fn type_reference(&self, schema: &Schema, ref_name: &str, url: &str) -> Section {
        let reference = format!("[`{ref_name}`]({url})");

        let ty = self
            .ty(&schema.ty)
            .map(|ty| format!(" `{ty}`"))
            .unwrap_or_default();

        let body = format!("**Type:**: {reference}{ty}");

        Section::leaf(self.section_header(schema), body)
    }

    fn schema_nested(&self, node: &SchemaNode, doc: &SchemaDocData) -> Document {
        let document = self.schema_embedded(node, doc);

        let name = node.schema.path.segments.last().unwrap().to_string();

        let nested = NamedDocument {
            name: name.clone(),
            document,
        };

        let url = format!("./{name}.md");
        let section = self.type_reference(&node.schema, "Nested", &url);

        Document {
            section,
            children: vec![nested],
        }
    }

    fn schema_embedded(&self, node: &SchemaNode, doc: &SchemaDocData) -> Document {
        let children = [
            self.enum_doc(&node.schema.ty.inner),
            self.default(&node.schema.path, &doc),
            self.examples(&node.schema.path, &doc),
        ];
        let child_schemas = node.children.iter().map(|schema| self.schema_node(schema));

        let (child_sections, child_docs): (Vec<_>, Vec<_>) = children
            .into_iter()
            .flatten()
            .map(Document::leaf)
            .chain(child_schemas)
            .map(|doc| (doc.section, doc.children))
            .unzip();

        let header = self.section_header(&node.schema);

        let section = Section {
            header,
            body: self.section_body(&node.schema, &doc),
            children: child_sections,
        };
        Document {
            section,
            children: itertools::concat(child_docs),
        }
    }

    fn section_header(&self, schema: &Schema) -> String {
        if let PathOrigin::Definition(def) = &schema.path.origin {
            return format!("`{def}`");
        }
        let Some(last_segment) = schema.path.segments.last() else {
            return "Schema".to_owned();
        };

        match &last_segment {
            PathSegment::Field(_) => format!("`{}`", schema.path),
            PathSegment::Index => "Array item".to_owned(),
            PathSegment::Variant(variant_name) => format!("Variant: `{variant_name}`"),
        }
    }

    fn section_body(&self, schema: &Schema, doc: &SchemaDocData) -> String {
        let top = [self.tag_for_type(&schema.ty), self.tag_for_required(schema)];

        let top = top.iter().flatten().join("<br>\n");

        let parts = [&Some(top), &doc.title, &doc.description];

        parts.iter().copied().flatten().join("\n\n")
    }

    fn tag_for_required(&self, schema: &Schema) -> Option<String> {
        let PathSegment::Field(field) = &schema.path.segments.last()? else {
            return None;
        };

        let requirement = match field.required {
            true => "yes",
            false => "no",
        };
        Some(format!("**Required:** `{requirement}`"))
    }

    fn tag_for_type(&self, ty: &Type) -> Option<String> {
        let ty = self.ty(&ty)?;
        Some(format!("**Type:** `{ty}`"))
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

    fn default(&self, path: &Path, doc: &SchemaDocData) -> Option<Section> {
        let value = doc.default.as_ref()?;
        Some(self.value_showcase(path, "Default", value))
    }

    fn value_showcase(&self, path: &Path, header: &str, value: &Value) -> Section {
        let toml = self.value(path, value);
        Section::leaf(header, toml)
    }

    fn examples(&self, path: &Path, doc: &SchemaDocData) -> Option<Section> {
        match doc.examples.as_slice() {
            [] => return None,
            [example] => return Some(self.value_showcase(path, "Example", example)),
            _ => {}
        };

        let examples = doc
            .examples
            .iter()
            .map(|value| {
                // Properly indent the example to fit into the markdown
                // list syntax
                let example = self.value(path, value);
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

        Some(Section::leaf("Examples", examples))
    }

    fn enum_doc(&self, ty: &LeafType) -> Option<Section> {
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

        Some(Section::leaf("Possible values", doc))
    }

    fn value(&self, key: &Path, value: &Value) -> String {
        fn wrap(key: &[PathSegment], value: Value) -> Value {
            let Some((first, rest)) = key.split_first() else {
                return value;
            };

            match &first {
                PathSegment::Field(_) => {
                    json!({ first.to_string(): wrap(rest, value) })
                }
                PathSegment::Index => {
                    json!([wrap(rest, value)])
                }
                // We use untagged one-of representations, so there is nothing
                // to wrap here
                PathSegment::Variant(_) => value,
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
pub(crate) struct Section {
    header: String,
    body: String,
    children: Vec<Section>,
}

impl Section {
    pub(crate) fn leaf(header: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            body: body.into(),
            children: vec![],
        }
    }

    /// Render the schema as markdown with the headers starting at the given level
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

struct NamedDocument {
    name: String,
    document: Document,
}

impl NamedDocument {
    fn into_files(self) -> Vec<File> {
        let mut files = vec![];
        let path = Utf8PathBuf::new();
        self.into_files_imp(path, &mut files);
        files
    }

    fn into_files_imp(self, path: Utf8PathBuf, files: &mut Vec<File>) {
        let file_name = format!("{}.md", self.name);
        let file = File::new(path.join(file_name), self.document.section);
        files.push(file);

        for child in self.document.children {
            child.into_files_imp(path.join(&self.name), files);
        }
    }
}

struct Document {
    section: Section,
    children: Vec<NamedDocument>,
}

impl Document {
    fn leaf(section: Section) -> Self {
        Self {
            section,
            children: vec![],
        }
    }
}

pub(crate) struct File {
    path: Utf8PathBuf,
    rendered: Section,
}

impl File {
    fn new(path: impl Into<Utf8PathBuf>, rendered: Section) -> Self {
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
