use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

type Untyped = BTreeMap<String, Value>;

#[derive(Serialize, Deserialize, Debug)]
struct RootSchema {
    definitions: BTreeMap<String, Schema>,

    #[serde(flatten)]
    schema: Schema,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Schema {
    // kind: Option<SchemaKind>,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    enum_values: Option<Vec<String>>,

    // #[serde(rename = "x-taplo")]
    // x_taplo: Option<XTaplo>,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    reference: Option<String>,

    #[serde(flatten)]
    untyped: Untyped,
}

// #[derive(Serialize, Deserialize, Debug, Clone)]
// #[serde(tag = "type")]
// enum SchemaKind {
//     Object {
//         properties: BTreeMap<String, Schema>,
//     },
//     Array {
//         items: Box<Schema>,
//     },
//     String,
//     Integer,
//     Number,
//     Boolean,
//     Null,
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// struct XTaplo {
//     docs: XTaploDocs,

//     #[serde(flatten)]
//     untyped: Untyped,
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// struct XTaploDocs {
//     enum_values: Vec<String>,

//     #[serde(flatten)]
//     untyped: Untyped,
// }

// impl Schema {
//     fn merge(&mut self, other: &Schema) {
//         merge_serializable(self, other.clone());
//     }
// }

// fn merge_serializable<T: Serialize + DeserializeOwned>(a: &mut T, b: T) {
//     let mut a_value = serde_json::to_value(&a).unwrap();
//     let b_value = serde_json::to_value(b).unwrap();
//     merge_json_values(&mut a_value, b_value);

//     *a = serde_json::from_value(a_value).unwrap();
// }

fn merge_json_values(a: &mut Value, b: Value) {
    use serde_json::map::Entry;

    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            for (key, b_value) in b {
                match a.entry(key) {
                    Entry::Occupied(mut a_value) => merge_json_values(a_value.get_mut(), b_value),
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

fn inline_enum_refs(def: &mut Schema, enums: &BTreeMap<String, Schema>) -> anyhow::Result<()> {
    let mut def_value = serde_json::to_value(&def).unwrap();
    inline_enum_refs_imp(&mut def_value, enums)?;
    *def = serde_json::from_value(def_value).unwrap();
    Ok(())
}

fn inline_enum_refs_imp(
    def_value: &mut Value,
    enums: &BTreeMap<String, Schema>,
) -> anyhow::Result<()> {
    let Some(def) = def_value.as_object_mut() else {
        return Ok(());
    };

    for property in def.values_mut() {
        inline_enum_refs_imp(property, enums)?;
    }

    let Some(reference) = def.get("$ref") else {
        return Ok(());
    };

    let reference = reference
        .as_str()
        .with_context(|| format!("Reference must be a string, but found: {reference}"))?;

    let reference = reference.strip_prefix("#/definitions/").with_context(|| {
        format!("Reference not to #/definitions is not allowed, but found: {reference}")
    })?;

    let Some(enum_def) = enums.get(reference) else {
        return Ok(());
    };

    def.remove("$ref");

    let enum_def = serde_json::to_value(enum_def).unwrap();
    merge_json_values(def_value, enum_def);

    Ok(())
}

/// Generate the JSON schema based on the input YML schema.
pub(crate) fn codegen() -> anyhow::Result<()> {
    let root_schema = fs::read_to_string("deny.schema.yml")?;
    let mut root_schema: RootSchema = serde_yaml::from_str(&root_schema)?;

    let (enums, mut defs): (BTreeMap<String, _>, BTreeMap<_, _>) = root_schema
        .definitions
        .into_iter()
        .partition(|(_, val)| val.enum_values.is_some());

    for def in defs.values_mut() {
        inline_enum_refs(def, &enums)?;
    }

    root_schema.definitions = itertools::concat([enums, defs]);

    let output = serde_json::to_string_pretty(&root_schema)?;

    std::fs::write("deny.schema.json", output)?;

    Ok(())
}
