use anyhow::{Context, Result};
use camino::Utf8Path;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

type Object = BTreeMap<String, Value>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct RootSchema {
    #[serde(flatten)]
    pub(crate) schema: Schema,

    pub(crate) definitions: BTreeMap<String, Schema>,

    // Keep the rest of the fields in the schema so they are not lost during
    // the deserialize -> serialize roundtrip.
    #[serde(flatten)]
    pub(crate) other: Object,
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
    pub(crate) enum_schema: Option<Vec<EnumVariantSchema>>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "oneOf")]
    pub(crate) one_of: Option<Vec<OneOfVariantSchema>>,

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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub(crate) enum EnumVariantSchema {
    Documented(DocumentedEnumSchema),
    Undocumented(Value),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct DocumentedEnumSchema {
    pub(crate) description: String,

    #[serde(flatten)]
    value: CustomEnumValue,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
enum CustomEnumValue {
    Named { value: Value, name: String },
    Inferred { value: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct OneOfVariantSchema {
    /// Override the name of the variant. It's main use case is when generating
    /// a Rust enum, which requires a name for each variant. However, it's also
    ///  useful for documentation purposes as a succinct display name for the
    /// variant. By default the variant name is inferred from the `$ref` or
    /// from the `type` clause of the schema.
    pub(crate) name: Option<String>,

    #[serde(flatten)]
    pub(crate) schema: Schema,
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
    pub(crate) fn is_primitive(&self) -> bool {
        self.object_schema.is_none()
            && self.array_schema.is_none()
            && self.enum_schema.is_none()
            && self.one_of.is_none()
    }

    /// Returns all schemas stored inside of this one. It doesn't resolve
    /// references. The iterator is depth-first.
    pub(crate) fn entries<'a>(&'a self) -> impl Iterator<Item = SchemaEntry<'a>> {
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

            let one_of_variants = schema
                .one_of
                .iter()
                .flatten()
                .map(|variant| &variant.schema);

            let array_items = schema.array_schema.iter().map(|array| array.items.as_ref());

            let new_entries = std::iter::empty()
                .chain(object_properties)
                .chain(one_of_variants)
                .chain(array_items)
                .map(|schema| SchemaEntry {
                    schema,
                    level: entry.level + 1,
                });

            stack.extend(new_entries);

            Some(entry)
        })
    }

    pub(crate) fn traverse_mut(&mut self, visit: impl Fn(&mut Schema) -> Result<()>) -> Result<()> {
        visit(self)?;

        if let Some(object) = &mut self.object_schema {
            object.properties.values_mut().try_for_each(&visit)?;
        }

        if let Some(array) = &mut self.array_schema {
            visit(&mut array.items)?;
        }

        if let Some(one_of) = &mut self.one_of {
            one_of
                .iter_mut()
                .map(|variant| &mut variant.schema)
                .try_for_each(&visit)?;
        }

        Ok(())
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

    pub(crate) fn try_as_enum(&self) -> Result<&[EnumVariantSchema]> {
        self.try_downcast_as(&self.enum_schema, "enum")
            .map(Vec::as_slice)
    }

    pub(crate) fn try_into_enum(self) -> Result<Vec<EnumVariantSchema>> {
        let enum_schema = self.enum_schema.clone();
        self.try_downcast_into(enum_schema, "enum")
    }

    pub(crate) fn try_as_one_of(&self) -> Result<&[OneOfVariantSchema]> {
        self.try_downcast_as(&self.one_of, "one-of")
            .map(Vec::as_slice)
    }

    pub(crate) fn try_into_one_of(self) -> Result<Vec<OneOfVariantSchema>> {
        let one_of_schema = self.one_of.clone();
        self.try_downcast_into(one_of_schema, "one-of")
    }

    pub(crate) fn try_description(&self) -> Result<&str> {
        self.description
            .as_deref()
            .with_context(|| format!("Expected description for schema, but found none: {self:#?}"))
    }

    pub(crate) fn referenced_definition(&self) -> Option<&str> {
        self.reference.as_ref()?.strip_prefix("#/definitions/")
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
                one_of: None,
                title: None,
                description: None,
                reference: None,
                default: None,
                x_taplo: None,
            }
            if examples.is_empty()
        )
    }
}

impl RootSchema {
    pub(crate) fn from_file(path: impl AsRef<Utf8Path>) -> Result<Self> {
        let input = fs::read_to_string("deny.schema.yml")?;
        let input: Self = serde_yaml::from_str(&input)?;
        Ok(input)
    }

    pub(crate) fn definition(&self, definition: &str) -> Result<&Schema> {
        self.definitions
            .get(definition)
            .with_context(|| format!("Reference to unknown definition: `{definition}`"))
    }

    fn referenced_definition(&self, schema: &Schema) -> Result<Option<&Schema>> {
        let Some(definition) = schema.referenced_definition() else {
            return Ok(None);
        };

        let definition = self
            .definition(definition)
            .with_context(|| format!("inside of schema: {schema:#?}"))?;

        Ok(Some(definition))
    }

    pub(crate) fn inline_referenced_definition(&self, schema: &Schema) -> Result<Schema> {
        let Some(definition) = self.referenced_definition(schema)? else {
            return Ok(schema.clone());
        };

        let mut output = definition.clone();

        // Values from the schema should take priority
        merge_json_mut(&mut output, schema);

        output.reference = None;

        Ok(output)
    }
}

impl OneOfVariantSchema {
    pub(crate) fn name(&self) -> Result<&str> {
        self.name
            .as_deref()
            .or_else(|| {
                self.schema
                    .reference
                    .as_deref()?
                    .strip_prefix("#/definitions/")
            })
            .or(self.schema.ty.as_deref())
            .with_context(|| format!("Expected name for one-of variant, but got: {self:#?}"))
    }
}

impl CustomEnumValue {
    fn to_json_value(&self) -> Value {
        match self {
            CustomEnumValue::Named { value, name: _ } => value.clone(),
            CustomEnumValue::Inferred { value } => value.clone().into(),
        }
    }
}

impl EnumVariantSchema {
    pub(crate) fn value_and_description(&self) -> (Value, Option<&str>) {
        match self {
            EnumVariantSchema::Documented(schema) => {
                let value = schema.value.to_json_value();
                let description = schema.description.as_str();
                (value, Some(description))
            }
            EnumVariantSchema::Undocumented(value) => (value.clone(), None),
        }
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
