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
    enum_schema: Option<Vec<EnumVariantSchema>>,
    ty: Option<String>,
    format: Option<String>,
    type_index_ref: Option<TypeIndexRef>,
}

#[derive(Debug)]
struct TypeIndexRef {
    definition: String,
    ty: Option<String>,
    format: Option<String>,
}

#[derive(Debug)]
struct TypeInfo {
    inner: Option<String>,
    format: Option<String>,
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
    root: SchemaKeyOrigin,
    segments: Vec<SchemaKeySegment>,
}

#[derive(Clone, Debug)]
enum SchemaKeyOrigin {
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
            root: SchemaKeyOrigin::Root,
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
                    root: SchemaKeyOrigin::Definition(def_name.clone()),
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

        // Avoid adding useless documentation for item
        if array.items.is_undocumented_primitive() {
            return Ok(vec![]);
        }

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
        let type_index_ref = schema.inner.referenced_definition()?.and_then(|def_name| {
            let schema = self.type_index.get(def_name)?;
            Some(TypeIndexRef {
                definition: def_name.to_owned(),
                ty: schema.ty.clone(),
                format: schema.format.clone(),
            })
        });

        let ty = schema
            .inner
            .array_schema
            .as_ref()
            .map(|array_schema| {
                let suffix = array_schema
                    .items
                    .is_undocumented_primitive()
                    .then(|| {
                        array_schema
                            .items
                            .ty
                            .as_ref()
                            .map(|item_ty| format!("<{item_ty}>"))
                    })
                    .flatten();

                itertools::chain(["array"], suffix.as_deref()).collect()
            })
            .or(schema.inner.ty);

        let base = SectionData {
            key: schema.key,
            title: schema.inner.title,
            description: schema.inner.description,
            default: schema.inner.default,
            examples: schema.inner.examples,
            ty,
            format: schema.inner.format,
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
{{#include ../../../deny.toml}}
```";

    let cfg = RenderingConfig {
        root_file_base: RenderedSection::leaf(header, body),
    };

    let files = Doc::from_root_schema(root)?.render(&cfg);

    files.iter().try_for_each(|file| file.write(out_dir))?;

    Ok(())
}
