use super::input::{ArraySchema, EnumSchema, ObjectSchema, RootSchema, Schema};
use anyhow::{Context, Result};
use itertools::Itertools;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

struct Doc {
    root: Section,
    type_index: BTreeMap<String, Section>,
}

struct SectionData {
    key: SchemaKey,
    title: Option<String>,
    description: Option<String>,
    default: Option<Value>,
    examples: Vec<Value>,
    format: Option<String>,
    ty: Option<String>,
    enum_schema: Option<EnumSchema>,
    type_index_ref: Option<String>,
}

struct Section {
    data: SectionData,
    children: Vec<Section>,
}

impl Doc {
    fn from_root_schema(root: &RootSchema) -> Result<Self> {
        let schemas_in_root = root.schema.inner_schemas();
        let schemas_in_defs = root.definitions.values().flat_map(Schema::inner_schemas);

        let definition_ref_counts = itertools::chain(schemas_in_root, schemas_in_defs)
            .map(Schema::referenced_definition)
            .flatten_ok()
            .process_results(Itertools::counts)?;

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
            .filter(|(def_name, count)| *count > 1)
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

struct RootContext<'a> {
    root: &'a RootSchema,
    type_index: &'a BTreeMap<String, &'a Schema>,
}

impl RootContext<'_> {
    fn root_section(&self) -> Result<Section> {
        let key = SchemaKey {
            root: SchemaRoot::Root,
            segments: vec![],
        };
        let root_schema = KeyedSchema::new(key, self.root.schema.clone());
        self.section(root_schema)
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
        let section_data = self.section_data(schema.clone())?;

        let referenced_def = schema.inner.referenced_definition()?;

        // If this schema references a type from the type index, then avoid
        // inlining the schema and finish the section early.
        if referenced_def.is_some_and(|def| self.type_index.contains_key(def)) {
            return Ok(Section::leaf(section_data));
        }

        let schema = schema.inline_referenced_definition(&self.root)?;

        let children = if schema.inner.array_schema.is_some() {
            self.array_children(schema)?
        } else if schema.inner.object_schema.is_some() {
            self.object_children(schema)?
        } else if schema.inner.one_of.is_some() {
            self.one_of_children(schema)?
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

    fn array_children(&self, schema: KeyedSchema) -> Result<Vec<KeyedSchema>> {
        let array = schema.inner.try_into_array()?;
        let key = schema.key.next_level(SchemaKeySegment::Index);
        let items = KeyedSchema::new(key, *array.items);
        Ok(vec![items])
    }

    fn object_children(&self, schema: KeyedSchema) -> Result<Vec<KeyedSchema>> {
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

    fn one_of_children(&self, schema: KeyedSchema) -> Result<Vec<KeyedSchema>> {
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

pub(crate) fn gen(root: &RootSchema) -> Result<()> {
    gen_root_doc(root)?;

    for (key, schema) in &root.schema.try_as_object()?.properties {
        let schema = KeyedSchema::inlined(root, vec![], SchemaKeySegment::Field(key), schema)?;

        gen_section_doc(root, &schema)?;
    }

    Ok(())
}

fn gen_section_doc(root: &RootSchema, section: &KeyedSchema<'_>) -> Result<()> {
    let properties = gen_object_doc(root, 1, section, section.inner.try_as_object()?)?;

    let section_key = &section.key.last().unwrap();

    let content = format!(
        "\
# The `[{section_key}]` section

{properties}
",
    );

    write_file(format!("{section_key}/cfg.md"), &content)
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

impl fmt::Display for SchemaKeySegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaKeySegment::Field(field) => f.write_str(&field.name),
            SchemaKeySegment::Index => f.write_str("N"),
            SchemaKeySegment::Variant(name) => f.write_str(name),
        }
    }
}

impl SchemaKeySegment {
    fn unwrap_field(&self) -> &SchemaKeySegmentField {
        match self {
            SchemaKeySegment::Field(field) => field,
            _ => panic!("Expected field, found: {self:#?}"),
        }
    }
}

impl SchemaKey {
    fn next_level(&self, new_segment: SchemaKeySegment) -> Self {
        let mut segments = self.segments.clone();
        segments.push(new_segment);
        Self { segments }
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

fn gen_detailed_schema_doc(
    root: &RootSchema,
    paragraph_level: usize,
    schema: &KeyedSchema<'_>,
) -> Result<String> {
    if let Some(array_schema) = &schema.inner.array_schema {
        return gen_array_doc(root, paragraph_level + 1, schema, array_schema);
    }

    if let Some(object) = &schema.inner.object_schema {
        return gen_object_doc(root, paragraph_level + 1, schema, object);
    }

    if let Some(enum_schema) = &schema.inner.enum_schema {
        return gen_enum_doc(schema, enum_schema, paragraph_level + 1);
    }

    if let Some(variants) = &schema.inner.one_of {
        return gen_one_of_doc(root, schema, variants, paragraph_level);
    }

    gen_primitive_type_doc(schema, paragraph_level)
}

fn primitive_type_label(schema: &KeyedSchema<'_>) -> Result<String> {
    let ty = schema.inner.ty.as_deref().with_context(|| {
        format!(
            "Expected type for schema, but found none: `{}`.\nSchema: {:#?}",
            schema.full_key(),
            schema.inner
        )
    })?;

    let format = schema
        .inner
        .format
        .as_deref()
        .map(|format| format!("({format})"));

    let doc = itertools::chain!([ty], format.as_deref()).join(" ");

    Ok(doc)
}

fn gen_primitive_type_doc(schema: &KeyedSchema<'_>, paragraph_level: usize) -> Result<String> {
    let ty = primitive_type_label(schema)?;
    let description = gen_generic_details(schema, paragraph_level)?;

    Ok(format!("`{ty}`\n\n{description}"))
}

fn value_to_toml(schema: &KeyedSchema<'_>, value: &Value) -> Result<String> {
    fn wrap(key: &[SchemaKeySegment], value: &Value) -> Value {
        let Some((first, rest)) = key.split_first() else {
            return value.clone();
        };

        match first {
            SchemaKeySegment::Field(_) => {
                serde_json::json!({ first.to_string(): wrap(rest, value) })
            }
            SchemaKeySegment::Index => {
                serde_json::json!([wrap(rest, value)])
            }
        }
    }

    let value = wrap(&schema.key, value);

    let toml = toml::to_string_pretty(&value)
        .with_context(|| format!("Serialized value: {:#?}", value))?;

    Ok(format!(
        "```toml\n\
        {toml}\
        ```",
    ))
}

fn gen_examples(schema: &KeyedSchema<'_>, paragraph_level: usize) -> Result<Option<String>> {
    let examples = match schema.inner.examples.as_slice() {
        [] => return Ok(None),
        [example] => gen_value_showcase("Example", example, schema, paragraph_level)?,
        examples => {
            let examples = examples
                .iter()
                .map(|value| value_to_toml(schema, value))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .format_with("\n", |example, f| {
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

                    f(&format_args!("- {example}"))
                });
            let paragraph = "#".repeat(paragraph_level + 1);

            format!("{paragraph} Examples\n\n{examples}")
        }
    };

    Ok(Some(examples))
}

fn gen_default(schema: &KeyedSchema<'_>, paragraph_level: usize) -> Result<Option<String>> {
    schema
        .inner
        .default
        .as_ref()
        .map(|value| gen_value_showcase("Default", value, schema, paragraph_level))
        .transpose()
}

fn gen_value_showcase(
    label: &str,
    value: &Value,
    schema: &KeyedSchema<'_>,
    paragraph_level: usize,
) -> Result<String> {
    let toml = value_to_toml(schema, value)?;
    let paragraph = "#".repeat(paragraph_level + 1);
    let showcase = format!("{paragraph} {label}\n\n{toml}");
    Ok(showcase)
}

fn gen_one_of_doc(
    root: &RootSchema,
    schema: &KeyedSchema<'_>,
    variants: &[Schema],
    paragraph_level: usize,
) -> Result<String> {
    let variants = variants
        .iter()
        .map(|variant| {
            let variant = KeyedSchema {
                inner: root.inline_referenced_definition(variant)?,
                key: schema.key.clone(),
            };

            let doc = gen_detailed_schema_doc(root, paragraph_level, &variant)?;

            Ok(doc)
        })
        .collect::<Result<Vec<_>>>()?
        .join("\n");

    Ok(format!("**One of the following:**\n\n{variants}"))
}

fn gen_enum_doc(
    schema: &KeyedSchema<'_>,
    enum_schema: &EnumSchema,
    paragraph_level: usize,
) -> Result<String> {
    let doc = enum_schema
        .values_and_descriptions()
        .map(|(value, description)| {
            let value = value.to_string();
            let description = description
                .map(|description| format!(" - {}", description))
                .unwrap_or_default();

            Ok(format!("* `{value}`{description}"))
        })
        .collect::<Result<Vec<_>>>()?
        .join("\n");

    let paragraph = "#".repeat(paragraph_level);

    let details = gen_generic_details(schema, paragraph_level)?;

    let doc = format!("\n\n{paragraph} Possible values\n\n{doc}\n---\n{details}");

    Ok(doc)
}

fn gen_array_doc(
    root: &RootSchema,
    paragraph_level: usize,
    schema: &KeyedSchema<'_>,
    array: &ArraySchema,
) -> Result<String> {
    let array_details = gen_generic_details(schema, paragraph_level)?;

    let items = KeyedSchema::inlined(
        root,
        schema.key.clone(),
        SchemaKeySegment::Index,
        &array.items,
    )?;

    if items.inner.is_primitive() && gen_generic_details(&items, paragraph_level)?.is_empty() {
        let ty = primitive_type_label(&items)?;
        return Ok(format!(
            "`array of {ty}`\n\n\
            {array_details}"
        ));
    }

    let paragraph = "#".repeat(paragraph_level);

    let details = gen_detailed_schema_doc(root, paragraph_level, &items)?;

    let doc = format!(
        "`array`\n\n\
        {array_details}\n\n\
        {paragraph} Items\n\n\
        {details}"
    );

    Ok(doc)
}

fn gen_object_property_doc(
    root: &RootSchema,
    paragraph_level: usize,
    object: &ObjectSchema,
    property: &KeyedSchema<'_>,
) -> Result<String> {
    let full_key = property.full_key();

    let property_key = property.key.last().unwrap().unwrap_field();

    let requirement = if object.required.contains(property_key) {
        "required"
    } else {
        "optional"
    };

    let paragraph = "#".repeat(paragraph_level);

    let details = gen_detailed_schema_doc(root, paragraph_level, property)?;

    let doc = format!(
        "{paragraph} `{full_key}` ({requirement})\n\n\
        {details}"
    );

    Ok(doc)
}

fn gen_root_doc(root: &RootSchema) -> Result<()> {
    let sections = root
        .schema
        .try_as_object()?
        .properties
        .keys()
        .map(|section| {
            format!(
                "## The `[{section}]` section\n\n\
                See [{section} config]({section}/cfg.html) for more info."
            )
        })
        .join("\n\n");

    let content = format!(
        "\
# config

The top level config for cargo-deny, by default called `deny.toml`.

## Example - cargo-deny's own configuration

```ini
{{{{#include ../../../deny.toml}}}}
```

{sections}"
    );

    write_file("cfg.md", &content)
}

fn write_file(path: impl AsRef<SchemaKey>, content: &str) -> Result<()> {
    let path = std::path::Path::new("docs/src/checks2").join(path);

    std::fs::create_dir_all(&path.parent().unwrap())?;

    std::fs::write(&path, content)
        .with_context(|| format!("Failed to write to file: {}", path.display()))
}
