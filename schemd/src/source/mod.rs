mod traversal;

pub(crate) use traversal::*;

use crate::prelude::*;
use crate::serdex;
use camino::Utf8Path;
use duplicate::duplicate_item;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Deref;

type Object = BTreeMap<String, Value>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RootSchema {
    #[serde(flatten)]
    pub(crate) schema: Schema,

    // Use an aliases to support more recent versions of JSONSchema
    #[serde(alias = "$defs")]
    pub(crate) definitions: BTreeMap<String, Schema>,

    /// Keep the rest of the fields in the schema so they are not lost during
    /// the deserialize -> serialize roundtrip.
    /// Unfortunatelly, we can't use `#[serde(flatten)]` with BTreeMap<String, Value>
    /// here because it contains a copy of fields from the flattened `schema` due
    /// a bug in serde. Probably: <https://github.com/serde-rs/serde/issues/2719>
    #[serde(flatten)]
    pub(crate) misc: MiscRootSchemaProperties,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct MiscRootSchemaProperties {
    #[serde(rename = "$id")]
    id: String,

    #[serde(rename = "$schema")]
    schema: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]

pub(crate) struct Schema {
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub(crate) ty: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) format: Option<String>,

    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) deprecated: bool,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) examples: Vec<Value>,

    #[serde(flatten)]
    pub(crate) object_schema: Option<ObjectSchema>,

    #[serde(flatten)]
    pub(crate) array_schema: Option<ArraySchema>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "enum")]
    pub(crate) enum_schema: Option<Vec<Value>>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "anyOf")]
    pub(crate) any_of: Option<Vec<Schema>>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "oneOf")]
    pub(crate) one_of: Option<Vec<Schema>>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "oneOf")]
    pub(crate) all_of: Option<Vec<Schema>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "$ref")]
    pub(crate) reference: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) default: Option<Value>,

    /// Extensions for taplo TOML language server
    #[serde(skip_serializing_if = "Option::is_none", rename = "x-taplo")]
    pub(crate) x_taplo: Option<Value>,

    /// Extensions for schemd itself
    #[serde(skip_serializing_if = "Option::is_none", rename = "x-schemd")]
    pub(crate) x_schemd: Option<XSchemd>,

    /// If [`Some`] specifies the original reference that was inlined into this
    /// from a [`Self::reference`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) inlined_from: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct XSchemd {
    /// Adds metadata to each member of an enum.
    #[serde(skip_serializing_if = "Option::is_none")]
    members: Option<Vec<Option<XSchemdMember>>>,

    /// Set a header that will be used instead of a generated one for this schema
    /// in documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) doc_header: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct XSchemdMember {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,

    /// Override the name of the variant. It's main use case is when generating
    /// a Rust enum, which requires a name for each variant. However, it's also
    /// useful for documentation purposes as a succinct display name for the
    /// variant. By default the variant name is inferred from the `$ref` or
    /// from the `type` clause of the schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
}

// /// Unfortunately we can't use an internally-tagged enum here with associated data
// /// because when flattening such enum with `#[serde(flatten)]` we end up with
// /// duplicate data in `other: Object` field as well, which then results in broken
// /// serialization that outputs duplicate keys in JSON objects. This is a bug in
// /// serde: <https://github.com/serde-rs/serde/issues/2200>
// #[derive(Serialize, Deserialize, Debug, Clone)]
// #[serde(tag = "type", rename_all = "lowercase")]
// pub(crate) enum SchemaType {
//     Object,
//     Array,
//     String,
//     Integer,
//     Number,
//     Boolean,
//     Null,
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ObjectSchema {
    /// Properties are defined via an [`IndexMap`] to preserve the order as they
    /// are defined in the schema. This way we can put more important properties
    /// at the top of the generated documentation by defining them first in the
    /// schema.
    pub(crate) properties: IndexMap<String, Schema>,

    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(crate) required: BTreeSet<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ArraySchema {
    pub(crate) items: Box<Schema>,
}

pub(crate) struct SchemaEntry<'a> {
    pub(crate) schema: &'a Schema,
    pub(crate) level: usize,
}

impl Schema {
    fn x_schemd_members(
        x_schemd: &Option<XSchemd>,
    ) -> impl Iterator<Item = Option<XSchemdMember>> + '_ {
        x_schemd
            .as_ref()
            .and_then(|x_schemd| x_schemd.members.as_deref())
            .into_iter()
            .flatten()
            .map(Clone::clone)
            // Pad the missing members with `None`s at the end
            .chain(std::iter::repeat(None))
    }

    #[duplicate_item(
        schema_list               reference(x) as_ref   iter;
        [schema_list]      [&x]         [as_ref] [iter];
        [schema_list_mut]  [&mut x]     [as_mut] [iter_mut];
    )]
    pub(crate) fn schema_list(self: reference([Self])) -> Option<SchemaList<reference([Self])>> {
        let (schemas, kind) = None
            .or_else(|| self.any_of.as_ref().zip(Some(SchemaListKind::AnyOf)))
            .or_else(|| self.one_of.as_ref().zip(Some(SchemaListKind::OneOf)))
            .or_else(|| self.all_of.as_ref().zip(Some(SchemaListKind::AllOf)))?;

        let items = schemas
            .iter()
            .zip(Self::x_schemd_members(&self.x_schemd))
            .map(|(schema, x_schemd)| SchemaListItem { schema, x_schemd })
            .collect();

        Some(SchemaList { kind, items })
    }

    pub(crate) fn enum_variants(&self) -> Option<impl Iterator<Item = EnumVariant> + '_> {
        let enum_schema = self.enum_schema.as_deref()?;

        let iter = enum_schema
            .iter()
            .zip(Self::x_schemd_members(&self.x_schemd))
            .map(|(value, x_schemd)| EnumVariant {
                value: value.clone(),
                x_schemd,
            });

        Some(iter)
    }

    /// Returns all schemas stored inside of this one. It doesn't traverse through
    /// `$ref`s in schemas. The iterator is depth-first.
    pub(crate) fn entries(&self) -> impl Iterator<Item = SchemaEntry<'_>> {
        let mut stack = vec![SchemaEntry {
            schema: self,
            level: 0,
        }];

        std::iter::from_fn(move || {
            let entry = stack.pop()?;
            let schema = entry.schema;

            let object_properties = schema
                .object_schema
                .iter()
                .flat_map(|object| object.properties.values());

            let schema_list = schema.schema_list();
            let schema_list_items = schema_list
                .iter()
                .flat_map(|list| &list.items)
                .map(|item| item.schema);

            let array_items = schema
                .array_schema
                .as_ref()
                .map(|array| array.items.as_ref());

            let new_entries = std::iter::empty()
                .chain(object_properties)
                .chain(schema_list_items)
                .chain(array_items)
                .map(|schema| SchemaEntry {
                    schema,
                    level: entry.level + 1,
                });

            stack.extend(new_entries);

            Some(entry)
        })
    }

    fn try_downcast_as<'a, T>(&'a self, schema: &'a Option<T>, label: &str) -> Result<&'a T> {
        schema
            .as_ref()
            .with_context(|| format!("Expected {label} schema, but got {self:#?}"))
    }

    fn try_downcast_into<T>(self, schema: Option<T>, label: &str) -> Result<T> {
        schema.with_context(|| format!("Expected {label} schema, but got {self:#?}"))
    }

    pub(crate) fn try_as_array(&self) -> Result<&ArraySchema> {
        self.try_downcast_as(&self.array_schema, "array")
    }

    pub(crate) fn try_into_array(self) -> Result<ArraySchema> {
        let array_schema = self.array_schema.clone();
        self.try_downcast_into(array_schema, "array")
    }

    pub(crate) fn try_as_object(&self) -> Result<&ObjectSchema> {
        self.try_downcast_as(&self.object_schema, "object")
    }

    pub(crate) fn try_into_object(self) -> Result<ObjectSchema> {
        let object_schema = self.object_schema.clone();
        self.try_downcast_into(object_schema, "object")
    }

    pub(crate) fn try_as_enum(&self) -> Result<&[Value]> {
        self.try_downcast_as(&self.enum_schema, "enum")
            .map(Vec::as_slice)
    }

    pub(crate) fn try_into_enum(self) -> Result<Vec<Value>> {
        let enum_schema = self.enum_schema.clone();
        self.try_downcast_into(enum_schema, "enum")
    }

    pub(crate) fn try_as_one_of(&self) -> Result<&[Schema]> {
        self.try_downcast_as(&self.any_of, "one-of")
            .map(Vec::as_slice)
    }

    pub(crate) fn try_into_one_of(self) -> Result<Vec<Schema>> {
        let one_of_schema = self.any_of.clone();
        self.try_downcast_into(one_of_schema, "one-of")
    }

    pub(crate) fn try_description(&self) -> Result<&str> {
        self.description
            .as_deref()
            .with_context(|| format!("Expected description for schema, but found none: {self:#?}"))
    }

    pub(crate) fn referenced_definition_name(&self) -> Option<&str> {
        self.reference.as_ref()?.strip_prefix("#/$defs/")
    }

    pub(crate) fn is_undocumented_primitive(&self) -> bool {
        matches!(
            self,
            Self {
                ty: _,
                format: _,
                deprecated: false,
                examples,
                object_schema: None,
                array_schema: None,
                enum_schema: None,
                any_of: None,
                one_of: None,
                all_of: None,
                title: None,
                description: None,
                reference: None,
                default: None,
                x_taplo: None,
                x_schemd: None,
                inlined_from: _,
            }
            if examples.is_empty()
        )
    }

    pub(crate) fn inline_reference(&mut self, referenced_value: &Schema) {
        // Values from the schema should take priority
        merge_json_mut(self, referenced_value);
        self.inlined_from = self.reference.take();
    }
}

impl RootSchema {
    pub(crate) fn from_file(path: impl AsRef<Utf8Path>) -> Result<Self> {
        let input = fs::read_to_string(path.as_ref())?;
        let input: Self = serde_yaml::from_str(&input)?;
        Ok(input)
    }

    pub(crate) fn remove_definition(&mut self, definition: &str) -> Result<Schema> {
        self.definitions
            .remove(definition)
            .with_context(|| format!("Reference to unknown definition: `{definition}`"))
    }

    pub(crate) fn definition(&self, definition: &str) -> Result<&Schema> {
        self.definitions
            .get(definition)
            .with_context(|| format!("Reference to unknown definition: `{definition}`"))
    }

    fn referenced_definition(&self, schema: &Schema) -> Result<Option<&Schema>> {
        let Some(definition) = schema.referenced_definition_name() else {
            return Ok(None);
        };

        let definition = self.definition(definition).with_context(|| {
            format!(
                "error inside of schema: {}",
                serdex::json::to_string_pretty(schema)
            )
        })?;

        Ok(Some(definition))
    }

    pub(crate) fn inline_referenced_definition(&self, schema: &Schema) -> Result<Schema> {
        let Some(definition) = self.referenced_definition(schema)? else {
            return Ok(schema.clone());
        };

        let mut output = definition.clone();
        output.inline_reference(schema);

        Ok(output)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EnumVariant {
    pub(crate) value: Value,
    pub(crate) x_schemd: Option<XSchemdMember>,
}

impl EnumVariant {
    pub(crate) fn description(&self) -> Option<&str> {
        self.x_schemd.as_ref()?.description.as_deref()
    }
}

#[derive(Debug)]
pub(crate) struct SchemaList<T> {
    pub(crate) kind: SchemaListKind,
    pub(crate) items: Vec<SchemaListItem<T>>,
}

#[derive(Debug)]
pub(crate) enum SchemaListKind {
    OneOf,
    AnyOf,
    AllOf,
}

#[derive(Debug)]
pub(crate) struct SchemaListItem<T> {
    pub(crate) schema: T,
    pub(crate) x_schemd: Option<XSchemdMember>,
}

impl<T> SchemaListItem<T>
where
    T: Deref<Target = Schema> + fmt::Debug,
{
    pub(crate) fn name(&self) -> Result<&str> {
        self.x_schemd
            .as_ref()
            .and_then(|x_schemd| x_schemd.name.as_deref())
            .or_else(|| {
                self.schema
                    .reference
                    .as_ref()
                    .or(self.schema.inlined_from.as_ref())?
                    .as_str()
                    .strip_prefix("#/$defs/")
            })
            .or(self.schema.ty.as_deref())
            .with_context(|| format!("Expected name for one-of variant, but got: {self:#?}"))
    }
}

fn merge_json_mut<T: serde::Serialize + serde::de::DeserializeOwned>(dest: &mut T, src: &T) {
    let mut dest_value = serde_json::to_value(&*dest).unwrap();
    let src_value = serde_json::to_value(src).unwrap();

    merge_json_values_mut(&mut dest_value, src_value);

    *dest = serde_json::from_value(dest_value).unwrap();
}

pub(crate) fn merge_json_values_mut(a: &mut Value, b: Value) {
    use serde_json::map::Entry;

    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            for (key, b_value) in b {
                match a.entry(key) {
                    Entry::Occupied(mut a_value) => {
                        merge_json_values_mut(a_value.get_mut(), b_value);
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(b_value);
                    }
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            a.extend(b);
        }
        (a, b) => *a = b,
    }
}
