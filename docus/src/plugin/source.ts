import { z } from "zod";
import * as yaml from "yaml";
import * as fs from "fs";


// type foo = z.ZodObject<
//     {
//         title: z.ZodOptional<z.ZodString>;
//         description: z.ZodOptional<z.ZodString>;
//         $ref: z.ZodOptional<z.ZodString>;
//         default: z.ZodOptional<z.ZodUnknown>;
//         ... 4 more ...;
//         required: z.ZodOptional<...>;
//     },
//      "strip",
//     z.ZodTypeAny,
//     {
//     title?: string | undefined;
//     description?: string | undefined;
//     $ref?: string | undefined;
//     default?: unknown;
//     type?: string | undefined;
//     format?: string | undefined;
//     deprecated?: boolean | undefined;
//     examples?: unknown[] | undefined;
//     required?: string[] | undefined;
//     },
//     {
//     ...;
//     }
// >

const SchemaBase = z.object({
    title: z.string().optional(),
    description: z.string().optional(),
    $ref: z.string().optional(),
    default: z.unknown().optional(),

    type: z.string().optional(),
    format: z.string().optional(),
    deprecated: z.boolean().optional(),
    examples: z.array(z.unknown()).optional(),

    required: z.array(z.string()).optional(),

    // #[serde(flatten)]
    // pub(crate) object_schema: Option<ObjectSchema>,

    // #[serde(flatten)]
    // pub(crate) array_schema: Option<ArraySchema>,

    // #[serde(skip_serializing_if = "Option::is_none", rename = "enum")]
    // pub(crate) enum_schema: Option<Vec<EnumVariantSchema>>,

    // #[serde(skip_serializing_if = "Option::is_none", rename = "oneOf")]
    // pub(crate) one_of: Option<Vec<OneOfVariantSchema>>,
});

type Schema = z.infer<typeof SchemaBase> & {
    properties?: Record<string, Schema>;
    items?: Schema;
    oneOf?: { schema: Schema; name?: string }[];
    enum?: ({ value: unknown; name: string } | { value: string } | string | number)[];
};

const Schema: z.ZodType<Schema> = SchemaBase.extend({
    properties: z.lazy(() => z.record(Schema)).optional(),
    items: z.lazy(() => Schema).optional(),
    oneOf: z.lazy(() => z.array(Schema.extend({ name: z.string().optional() })).optional()),
    enum: z.lazy(() =>
        z.array(
            z.union([
                z.intersection(
                    z.object({
                        description: z.string(),
                    }),
                    z.union([
                        z.object({
                            value: z.unknown(),
                            name: z.string(),
                        }),
                        z.object({
                            value: z.string(),
                        }),
                    ])
                ),
                z.union([z.string(), z.number()])
            ]),
        ).optional()
    )
});

const RootSchema = Schema.extend({
    definitions: z.record(Schema),
});

type RootSchema = z.infer<typeof RootSchema>;


const schema = fs.readFileSync("../deny.schema.yml", { encoding: "utf-8" });

const parsed = yaml.parse(schema);
const result = RootSchema.parse(parsed);

console.log();

// pub(crate) struct SchemaEntry<'a> {
//     pub(crate) schema: &'a Schema,
//     pub(crate) level: usize,
// }

// impl Schema {
//     pub(crate) fn is_primitive(&self) -> bool {
//         self.object_schema.is_none()
//             && self.array_schema.is_none()
//             && self.enum_schema.is_none()
//             && self.one_of.is_none()
//     }

//     /// Returns all schemas stored inside of this one. It doesn't resolve
//     /// references.
//     pub(crate) fn entries<'a>(&'a self) -> impl Iterator<Item = SchemaEntry<'a>> {
//         let mut stack = vec![SchemaEntry {
//             schema: self,
//             level: 0,
//         }];

//         std::iter::from_fn(move || {
//             let entry = stack.pop()?;
//             let schema = entry.schema;

//             let object_properties = schema
//                 .object_schema
//                 .iter()
//                 .flat_map(|object| object.properties.values());

//             let one_of_variants = schema
//                 .one_of
//                 .iter()
//                 .flatten()
//                 .map(|variant| &variant.schema);

//             let array_items = schema.array_schema.iter().map(|array| array.items.as_ref());

//             let new_entries = std::iter::empty()
//                 .chain(object_properties)
//                 .chain(one_of_variants)
//                 .chain(array_items)
//                 .map(|schema| SchemaEntry {
//                     schema,
//                     level: entry.level + 1,
//                 });

//             stack.extend(new_entries);

//             Some(entry)
//         })
//     }

//     pub(crate) fn traverse_mut(&mut self, visit: impl Fn(&mut Schema) -> Result<()>) -> Result<()> {
//         visit(self)?;

//         if let Some(object) = &mut self.object_schema {
//             object.properties.values_mut().try_for_each(&visit)?;
//         }

//         if let Some(array) = &mut self.array_schema {
//             visit(&mut array.items)?;
//         }

//         if let Some(one_of) = &mut self.one_of {
//             one_of
//                 .iter_mut()
//                 .map(|variant| &mut variant.schema)
//                 .try_for_each(&visit)?;
//         }

//         Ok(())
//     }

//     fn try_downcast_as<'a, T>(&'a self, schema: &'a Option<T>, label: &str) -> Result<&'a T> {
//         schema
//             .as_ref()
//             .with_context(|| format!("Expected {label} schema, but got {self:#?}"))
//     }

//     fn try_downcast_into<T>(self, schema: Option<T>, label: &str) -> Result<T> {
//         schema.with_context(|| format!("Expected {label} schema, but got {self:#?}"))
//     }

//     pub(crate) fn try_as_array(&self) -> Result<&ArraySchema> {
//         self.try_downcast_as(&self.array_schema, "array")
//     }

//     pub(crate) fn try_into_array(self) -> Result<ArraySchema> {
//         let array_schema = self.array_schema.clone();
//         self.try_downcast_into(array_schema, "array")
//     }

//     pub(crate) fn try_as_object(&self) -> Result<&ObjectSchema> {
//         self.try_downcast_as(&self.object_schema, "object")
//     }

//     pub(crate) fn try_into_object(self) -> Result<ObjectSchema> {
//         let object_schema = self.object_schema.clone();
//         self.try_downcast_into(object_schema, "object")
//     }

//     pub(crate) fn try_as_enum(&self) -> Result<&[EnumVariantSchema]> {
//         self.try_downcast_as(&self.enum_schema, "enum")
//             .map(Vec::as_slice)
//     }

//     pub(crate) fn try_into_enum(self) -> Result<Vec<EnumVariantSchema>> {
//         let enum_schema = self.enum_schema.clone();
//         self.try_downcast_into(enum_schema, "enum")
//     }

//     pub(crate) fn try_as_one_of(&self) -> Result<&[OneOfVariantSchema]> {
//         self.try_downcast_as(&self.one_of, "one-of")
//             .map(Vec::as_slice)
//     }

//     pub(crate) fn try_into_one_of(self) -> Result<Vec<OneOfVariantSchema>> {
//         let one_of_schema = self.one_of.clone();
//         self.try_downcast_into(one_of_schema, "one-of")
//     }

//     pub(crate) fn try_description(&self) -> Result<&str> {
//         self.description
//             .as_deref()
//             .with_context(|| format!("Expected description for schema, but found none: {self:#?}"))
//     }

//     pub(crate) fn referenced_definition(&self) -> Option<&str> {
//         self.reference.as_ref()?.strip_prefix("#/definitions/")
//     }

//     pub(crate) fn is_undocumented_primitive(&self) -> bool {
//         matches!(
//             self,
//             Self {
//                 ty: _,
//                 format: _,
//                 deprecated: false,
//                 examples,
//                 object_schema: None,
//                 array_schema: None,
//                 enum_schema: None,
//                 one_of: None,
//                 title: None,
//                 description: None,
//                 reference: None,
//                 default: None,
//                 x_taplo: None,
//             }
//             if examples.is_empty()
//         )
//     }
// }

// impl RootSchema {
//     pub(crate) fn definition(&self, definition: &str) -> Result<&Schema> {
//         self.definitions
//             .get(definition)
//             .with_context(|| format!("Reference to unknown definition: `{definition}`"))
//     }

//     fn referenced_definition(&self, schema: &Schema) -> Result<Option<&Schema>> {
//         let Some(definition) = schema.referenced_definition() else {
//             return Ok(None);
//         };

//         let definition = self
//             .definition(definition)
//             .with_context(|| format!("inside of schema: {schema:#?}"))?;

//         Ok(Some(definition))
//     }

//     pub(crate) fn inline_referenced_definition(&self, schema: &Schema) -> Result<Schema> {
//         let Some(definition) = self.referenced_definition(schema)? else {
//             return Ok(schema.clone());
//         };

//         let mut output = definition.clone();

//         // Values from the schema should take priority
//         merge_json_mut(&mut output, schema);

//         output.reference = None;

//         Ok(output)
//     }
// }

// impl OneOfVariantSchema {
//     pub(crate) fn name(&self) -> Result<&str> {
//         self.name
//             .as_deref()
//             .or_else(|| {
//                 self.schema
//                     .reference
//                     .as_deref()?
//                     .strip_prefix("#/definitions/")
//             })
//             .or(self.schema.ty.as_deref())
//             .with_context(|| format!("Expected name for one-of variant, but got: {self:#?}"))
//     }
// }

// impl CustomEnumValue {
//     fn to_json_value(&self) -> Value {
//         match self {
//             CustomEnumValue::Named { value, name: _ } => value.clone(),
//             CustomEnumValue::Inferred { value } => value.clone().into(),
//         }
//     }
// }

// impl EnumVariantSchema {
//     pub(crate) fn value_and_description(&self) -> (Value, Option<&str>) {
//         match self {
//             EnumVariantSchema::Documented(schema) => {
//                 let value = schema.value.to_json_value();
//                 let description = schema.description.as_str();
//                 (value, Some(description))
//             }
//             EnumVariantSchema::Undocumented(value) => (value.clone(), None),
//         }
//     }
// }

// fn merge_json_mut<T: serde::Serialize + serde::de::DeserializeOwned>(dest: &mut T, src: &T) {
//     let mut dest_value = serde_json::to_value(&*dest).unwrap();
//     let src_value = serde_json::to_value(src).unwrap();

//     merge_json_values_mut(&mut dest_value, src_value);

//     *dest = serde_json::from_value(dest_value).unwrap();
// }

// pub(crate) fn merge_json_values_mut(a: &mut Value, b: Value) {
//     use serde_json::map::Entry;

//     match (a, b) {
//         (Value::Object(a), Value::Object(b)) => {
//             for (key, b_value) in b {
//                 match a.entry(key) {
//                     Entry::Occupied(mut a_value) => {
//                         merge_json_values_mut(a_value.get_mut(), b_value);
//                     }
//                     Entry::Vacant(entry) => {
//                         entry.insert(b_value);
//                     }
//                 }
//             }
//         }
//         (Value::Array(a), Value::Array(b)) => {
//             a.extend(b);
//         }
//         (a, b) => *a = b,
//     }
// }
