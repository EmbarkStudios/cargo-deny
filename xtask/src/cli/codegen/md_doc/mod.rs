mod rendering;

use self::rendering::{RenderedSection, RenderingConfig};
use crate::cli::codegen::input::{EnumVariantSchema, RootSchema, Schema};
use anyhow::Result;
use itertools::Itertools;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

pub(crate) struct Doc {
    root: Section,
    type_index: BTreeMap<String, Section>,
}

#[derive(Debug)]
struct SectionData {
    key: SchemaKey,
    title: Option<String>,
    description: Option<String>,
    default: Option<Value>,
    examples: Vec<Value>,
    format: Option<String>,
    ty: Option<String>,
    enum_schema: Option<Vec<EnumVariantSchema>>,
    type_index_ref: Option<String>,
}

#[derive(Debug)]
struct Section {
    data: SectionData,
    children: Vec<Section>,
}

struct RootContext<'a> {
    root: &'a RootSchema,
    type_index: &'a BTreeMap<String, &'a Schema>,
}

#[derive(Clone, Debug)]
struct KeyedSchema {
    key: SchemaKey,
    inner: Schema,
}

#[derive(Clone, Debug)]
struct SchemaKey {
    root: SchemaRoot,
    segments: Vec<SchemaKeySegment>,
}

#[derive(Clone, Debug)]
enum SchemaRoot {
    Root,
    Definition(String),
}

#[derive(Clone, Debug)]
enum SchemaKeySegment {
    Field(SchemaKeySegmentField),
    Index,
    Variant(String),
}

#[derive(Clone, Debug)]
struct SchemaKeySegmentField {
    name: String,
    required: bool,
}

impl Doc {
    fn from_root_schema(root: &RootSchema) -> Result<Self> {
        let schemas_in_root = root.schema.inner_schemas();
        let schemas_in_defs = root.definitions.values().flat_map(Schema::inner_schemas);

        let definition_ref_counts = itertools::chain(schemas_in_root, schemas_in_defs)
            .map(Schema::referenced_definition)
            .flatten_ok()
            .process_results(|iter| iter.counts())?;

        let unused_defs: Vec<_> = root
            .definitions
            .iter()
            .filter(|(def_name, _)| !definition_ref_counts.contains_key(def_name.as_str()))
            .collect();

        anyhow::ensure!(
            unused_defs.is_empty(),
            "Found unused definitions: {unused_defs:#?}",
        );

        let type_index: BTreeMap<_, _> = definition_ref_counts
            .into_iter()
            // For schemas that are repeatedly referenced, we want to include them in the
            // "Type Index". This is separate page where common types are defined such
            // that we don't duplicate their docs all over the place.
            .filter(|(_, count)| *count > 1)
            .map(|(def_name, _)| {
                let schema = root.find_definition(def_name)?;
                anyhow::Ok((def_name.to_owned(), schema))
            })
            .try_collect()?;

        let ctx = RootContext {
            root,
            type_index: &type_index,
        };

        Ok(Self {
            root: ctx.root_section()?,
            type_index: ctx.type_index_sections()?,
        })
    }
}

impl RootContext<'_> {
    fn root_section(&self) -> Result<Section> {
        let key = SchemaKey {
            root: SchemaRoot::Root,
            segments: vec![],
        };
        let root_schema = KeyedSchema::new(key, self.root.schema.clone());

        let section = self.section(root_schema)?;

        Ok(section)
    }

    fn type_index_sections(&self) -> Result<BTreeMap<String, Section>> {
        self.type_index
            .iter()
            .map(|(def_name, &schema)| {
                let key = SchemaKey {
                    root: SchemaRoot::Definition(def_name.clone()),
                    segments: vec![],
                };
                let schema = KeyedSchema::new(key, schema.clone());

                anyhow::Ok((def_name.clone(), self.section(schema)?))
            })
            .collect()
    }

    fn section(&self, schema: KeyedSchema) -> Result<Section> {
        let referenced_def = schema.inner.referenced_definition()?;

        // If this schema references a type from the type index, then avoid
        // inlining the schema and finish the section early.
        if referenced_def.is_some_and(|def| self.type_index.contains_key(def)) {
            return Ok(Section::leaf(self.section_data(schema.clone())?));
        }

        let schema = schema.inline_referenced_definition(self.root)?;

        let section_data = self.section_data(schema.clone())?;

        let children = if schema.inner.array_schema.is_some() {
            Self::array_children(schema)?
        } else if schema.inner.object_schema.is_some() {
            Self::object_children(schema)?
        } else if schema.inner.one_of.is_some() {
            Self::one_of_children(schema)?
        } else {
            vec![]
        };

        let children = children
            .into_iter()
            .map(|child| self.section(child))
            .try_collect()?;

        Ok(Section {
            data: section_data,
            children,
        })
    }

    fn array_children(schema: KeyedSchema) -> Result<Vec<KeyedSchema>> {
        let array = schema.inner.try_into_array()?;
        let key = schema.key.next_level(SchemaKeySegment::Index);
        let items = KeyedSchema::new(key, *array.items);
        Ok(vec![items])
    }

    fn object_children(schema: KeyedSchema) -> Result<Vec<KeyedSchema>> {
        let object = schema.inner.try_into_object()?;
        let properties = object
            .properties
            .into_iter()
            .map(|(key, value)| {
                let key = SchemaKeySegmentField {
                    name: key.clone(),
                    required: object.required.contains(&key),
                };

                let key = schema.key.next_level(SchemaKeySegment::Field(key));
                KeyedSchema::new(key, value)
            })
            .collect();

        Ok(properties)
    }

    fn one_of_children(schema: KeyedSchema) -> Result<Vec<KeyedSchema>> {
        let variants = schema.inner.try_into_one_of()?;

        let duplicates: Vec<_> = variants
            .iter()
            .map(|variant| &variant.name)
            .duplicates()
            .collect();

        anyhow::ensure!(
            duplicates.is_empty(),
            "Duplicate variant names found in one_of schema.\n\
            Duplicates: {duplicates:?}\n\
            Variants: {variants:#?}",
        );

        let variants = variants
            .into_iter()
            .map(|variant| {
                let key = schema
                    .key
                    .next_level(SchemaKeySegment::Variant(variant.name.clone()));

                KeyedSchema::new(key, variant.schema)
            })
            .collect();

        Ok(variants)
    }

    fn section_data(&self, schema: KeyedSchema) -> Result<SectionData> {
        let type_index_ref = schema
            .inner
            .referenced_definition()?
            .filter(|&def_name| self.type_index.contains_key(def_name))
            .map(ToOwned::to_owned);

        let base = SectionData {
            key: schema.key,
            title: schema.inner.title,
            description: schema.inner.description,
            default: schema.inner.default,
            examples: schema.inner.examples,
            format: schema.inner.format,
            ty: schema.inner.ty,
            enum_schema: schema.inner.enum_schema,
            type_index_ref,
        };

        Ok(base)
    }
}

impl Section {
    fn leaf(data: SectionData) -> Self {
        Self {
            data,
            children: vec![],
        }
    }
}

impl fmt::Display for SchemaKeySegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaKeySegment::Field(field) => f.write_str(&field.name),
            SchemaKeySegment::Index => f.write_str("N"),
            SchemaKeySegment::Variant(name) => f.write_str(name),
        }
    }
}

impl SchemaKey {
    fn next_level(&self, new_segment: SchemaKeySegment) -> Self {
        let mut segments = self.segments.clone();
        segments.push(new_segment);
        Self {
            root: self.root.clone(),
            segments,
        }
    }

    fn last_segment(&self) -> &SchemaKeySegment {
        self.segments.last().unwrap()
    }
}

impl fmt::Display for SchemaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut segments = self.segments.iter();

        if let Some(segment) = segments.next() {
            write!(f, "{segment}")?;
        }

        segments.try_for_each(|segment| match segment {
            SchemaKeySegment::Field(_) => write!(f, ".{segment}"),
            SchemaKeySegment::Index => write!(f, "[{segment}]"),
            SchemaKeySegment::Variant(_) => write!(f, " (as {segment})"),
        })
    }
}

impl KeyedSchema {
    fn new(key: SchemaKey, inner: Schema) -> Self {
        Self { key, inner }
    }

    fn inline_referenced_definition(self, root: &RootSchema) -> Result<Self> {
        Ok(Self::new(
            self.key,
            root.inline_referenced_definition(&self.inner)?,
        ))
    }
}

pub(crate) fn gen(root: &RootSchema) -> Result<()> {
    let out_dir = "docs/src/checks2";

    let header = "config";
    let body = "\
The top level config for cargo-deny, by default called `deny.toml`.

## Example - cargo-deny's own configuration

```ini
{{{{#include ../../../deny.toml}}}}
```";

    let cfg = RenderingConfig {
        root_file_base: RenderedSection::leaf(header, body),
    };

    let files = Doc::from_root_schema(root)?.render(&cfg);

    for file in files {
        file.write(out_dir)?;
    }

    Ok(())
}
