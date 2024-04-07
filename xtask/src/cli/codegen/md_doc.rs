use super::input::{ArraySchema, EnumSchema, ObjectSchema, RootSchema, Schema};
use anyhow::{Context, Result};
use itertools::Itertools;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

struct MdDoc {
    sections: Vec<SchemaDocInline>,
    type_index: BTreeMap<String, SchemaDocInline>,
}

enum SchemaDoc {
    /// Stores the documentation directly
    Inline(SchemaDocInline),

    /// Refers to a type from the type index
    Ref(String),
}

struct SchemaDocInline {
    header: String,
    title: Option<String>,
    description: Option<String>,
    required: bool,
    default: Option<Value>,
    examples: Option<Vec<Value>>,
}

impl MdDoc {
    fn from_root_schema(root: &RootSchema) -> Result<Self> {
        let mut sections = vec![];

        let schemas_in_root = root.schema.inner_schemas();

        let schemas_in_defs = root
            .definitions
            .values()
            .flat_map(|schema| schema.inner_schemas());

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
                Ok((def_name.to_owned(), schema))
            })
            .try_collect()?;

        for (key, schema) in &root.schema.try_as_object()?.properties {
            let schema = KeyedSchema::resolve(root, vec![], KeySegment::Field(key), schema)?;

            let section = SchemaSection::from_keyed_schema(&schema)?;

            sections.push(section);
        }

        Ok(Self {
            sections,
            type_index,
        })
    }
}

pub(crate) fn gen(root: &RootSchema) -> Result<()> {
    gen_root_doc(root)?;

    for (key, schema) in &root.schema.try_as_object()?.properties {
        let schema = KeyedSchema::resolve(root, vec![], KeySegment::Field(key), schema)?;

        gen_section_doc(root, &schema)?;
    }

    Ok(())
}

fn gen_section_doc(root: &RootSchema, section: &KeyedSchema<'_>) -> Result<()> {
    let properties = gen_object_doc(root, 1, section, section.schema.try_as_object()?)?;

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
struct KeyedSchema<'a> {
    key: Vec<KeySegment<'a>>,
    schema: Schema,
}

#[derive(Clone, Debug)]
enum KeySegment<'a> {
    Field(&'a str),
    Index,
}

impl fmt::Display for KeySegment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySegment::Field(key) => write!(f, "{key}"),
            KeySegment::Index => write!(f, "N"),
        }
    }
}

impl KeySegment<'_> {
    fn unwrap_field(&self) -> &str {
        match self {
            KeySegment::Field(key) => key,
            KeySegment::Index => panic!("Expected field, found index"),
        }
    }
}

impl<'a> KeyedSchema<'a> {
    fn resolve(
        root: &RootSchema,
        parent_key: Vec<KeySegment<'a>>,
        key: KeySegment<'a>,
        schema: &Schema,
    ) -> Result<Self> {
        let mut new_key = parent_key;
        new_key.push(key);
        Ok(Self {
            key: new_key,
            schema: root.inline_referenced_definition(schema)?,
        })
    }

    fn full_key(&self) -> String {
        self.key
            .iter()
            .enumerate()
            .map(|(i, key)| {
                if let &KeySegment::Field(key) = key {
                    if i == 0 {
                        return key.to_owned();
                    }
                }
                match key {
                    KeySegment::Field(_) => format!(".{key}"),
                    KeySegment::Index => format!("[{key}]"),
                }
            })
            .collect()
    }
}

fn gen_detailed_schema_doc(
    root: &RootSchema,
    paragraph_level: usize,
    schema: &KeyedSchema<'_>,
) -> Result<String> {
    if let Some(array_schema) = &schema.schema.array_schema {
        return gen_array_doc(root, paragraph_level + 1, schema, array_schema);
    }

    if let Some(object) = &schema.schema.object_schema {
        return gen_object_doc(root, paragraph_level + 1, schema, object);
    }

    if let Some(enum_schema) = &schema.schema.enum_schema {
        return gen_enum_doc(schema, enum_schema, paragraph_level + 1);
    }

    if let Some(variants) = &schema.schema.one_of {
        return gen_one_of_doc(root, schema, variants, paragraph_level);
    }

    gen_primitive_type_doc(schema, paragraph_level)
}

fn primitive_type_label(schema: &KeyedSchema<'_>) -> Result<String> {
    let ty = schema.schema.ty.as_deref().with_context(|| {
        format!(
            "Expected type for schema, but found none: `{}`.\nSchema: {:#?}",
            schema.full_key(),
            schema.schema
        )
    })?;

    let format = schema
        .schema
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
    fn wrap(key: &[KeySegment<'_>], value: &Value) -> Value {
        let Some((first, rest)) = key.split_first() else {
            return value.clone();
        };

        match first {
            KeySegment::Field(_) => {
                serde_json::json!({ first.to_string(): wrap(rest, value) })
            }
            KeySegment::Index => {
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
    let examples = match schema.schema.examples.as_slice() {
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
        .schema
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

fn gen_generic_details(schema: &KeyedSchema<'_>, paragraph_level: usize) -> Result<String> {
    let default = gen_default(schema, paragraph_level)?;
    let examples = gen_examples(schema, paragraph_level)?;

    let details = [
        &default,
        &schema.schema.title,
        &schema.schema.description,
        &examples,
    ]
    .into_iter()
    .flatten()
    .join("\n\n");

    Ok(details)
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
                schema: root.inline_referenced_definition(variant)?,
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

fn gen_object_doc(
    root: &RootSchema,
    paragraph_level: usize,
    schema: &KeyedSchema<'_>,
    object: &ObjectSchema,
) -> Result<String> {
    let object_details = gen_generic_details(schema, paragraph_level)?;

    let properties = object
        .properties
        .iter()
        .map(|(key, value)| {
            let field =
                KeyedSchema::resolve(root, schema.key.clone(), KeySegment::Field(key), value)?;

            gen_object_property_doc(root, paragraph_level + 1, object, &field)
        })
        .collect::<Result<Vec<_>>>()?
        .join("\n\n");

    Ok([object_details, properties].join("\n\n"))
}

fn gen_array_doc(
    root: &RootSchema,
    paragraph_level: usize,
    schema: &KeyedSchema<'_>,
    array: &ArraySchema,
) -> Result<String> {
    let array_details = gen_generic_details(schema, paragraph_level)?;

    let items = KeyedSchema::resolve(root, schema.key.clone(), KeySegment::Index, &array.items)?;

    if items.schema.is_primitive() && gen_generic_details(&items, paragraph_level)?.is_empty() {
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

fn write_file(path: impl AsRef<Path>, content: &str) -> Result<()> {
    let path = std::path::Path::new("docs/src/checks2").join(path);

    std::fs::create_dir_all(&path.parent().unwrap())?;

    std::fs::write(&path, content)
        .with_context(|| format!("Failed to write to file: {}", path.display()))
}
