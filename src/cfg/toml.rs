mod de;
mod error;
mod tokens;

use super::Span;
use serde::{
    de::{self as des, IntoDeserializer},
    Deserialize,
};
use std::{borrow::Cow, fmt};

type DesErr = toml::de::Error;

#[derive(Debug)]
pub struct Value<'de> {
    pub value: ValueInner<'de>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Key<'de> {
    pub name: Cow<'de, str>,
    pub span: Span,
}

impl<'de> Ord for Key<'de> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl<'de> PartialOrd for Key<'de> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'de> PartialEq for Key<'de> {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
    }
}

impl<'de> Eq for Key<'de> {}

pub type Table<'de> = std::collections::BTreeMap<Key<'de>, Value<'de>>;
pub type Array<'de> = Vec<Value<'de>>;

#[derive(Debug)]
pub enum ValueInner<'de> {
    String(Cow<'de, str>),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Array<'de>),
    Table(Table<'de>),
}

impl<'de> ValueInner<'de> {
    pub fn type_str(&self) -> &'static str {
        match self {
            Self::String(..) => "string",
            Self::Integer(..) => "integer",
            Self::Float(..) => "float",
            Self::Boolean(..) => "boolean",
            Self::Array(..) => "array",
            Self::Table(..) => "table",
        }
    }
}

// impl<'de> des::Deserializer<'de> for Value<'de> {
//     type Error = DesErr;

//     fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: des::Visitor<'de>,
//     {
//         match self.value {
//             ValueInner::Boolean(v) => visitor.visit_bool(v),
//             ValueInner::Integer(n) => visitor.visit_i64(n),
//             ValueInner::Float(n) => visitor.visit_f64(n),
//             ValueInner::String(v) => visitor.visit_str(v.as_ref()),
//             ValueInner::Array(v) => {
//                 let len = v.len();
//                 let mut deserializer = SeqDeserializer::new(v);
//                 let seq = visitor.visit_seq(&mut deserializer)?;
//                 let remaining = deserializer.iter.len();
//                 if remaining == 0 {
//                     Ok(seq)
//                 } else {
//                     Err(des::Error::invalid_length(len, &"fewer elements in array"))
//                 }
//             }
//             ValueInner::Table(v) => {
//                 let len = v.len();
//                 let mut deserializer = MapDeserializer::new(v);
//                 let map = visitor.visit_map(&mut deserializer)?;
//                 let remaining = deserializer.iter.len();
//                 if remaining == 0 {
//                     Ok(map)
//                 } else {
//                     Err(des::Error::invalid_length(len, &"fewer elements in map"))
//                 }
//             }
//         }
//     }

//     #[inline]
//     fn deserialize_enum<V>(
//         self,
//         _name: &'static str,
//         _variants: &'static [&'static str],
//         visitor: V,
//     ) -> Result<V::Value, Self::Error>
//     where
//         V: des::Visitor<'de>,
//     {
//         match self.value {
//             ValueInner::String(variant) => visitor.visit_enum(variant.into_deserializer()),
//             ValueInner::Table(variant) => {
//                 if variant.is_empty() {
//                     Err(des::Error::custom(
//                         "wanted exactly 1 element, found 0 elements",
//                     ))
//                 } else if variant.len() != 1 {
//                     Err(des::Error::custom(
//                         "wanted exactly 1 element, more than 1 element",
//                     ))
//                 } else {
//                     let deserializer = MapDeserializer::new(variant);
//                     visitor.visit_enum(deserializer)
//                 }
//             }
//             _ => Err(des::Error::invalid_type(
//                 des::Unexpected::UnitVariant,
//                 &"string only",
//             )),
//         }
//     }

//     // `None` is interpreted as a missing field so be sure to implement `Some`
//     // as a present field.
//     fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: des::Visitor<'de>,
//     {
//         visitor.visit_some(self)
//     }

//     fn deserialize_newtype_struct<V>(
//         self,
//         _name: &'static str,
//         visitor: V,
//     ) -> Result<V::Value, Self::Error>
//     where
//         V: des::Visitor<'de>,
//     {
//         visitor.visit_newtype_struct(self)
//     }

//     fn deserialize_struct<V>(
//         self,
//         name: &'static str,
//         _fields: &'static [&'static str],
//         visitor: V,
//     ) -> Result<V::Value, Self::Error>
//     where
//         V: des::Visitor<'de>,
//     {
//         if name == super::span_tags::NAME {
//             let mut sd = SpanDeserializer::new(self);
//             visitor.visit_map(&mut sd)
//         } else {
//             self.deserialize_any(visitor)
//         }
//     }

//     serde::forward_to_deserialize_any! {
//         bool u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 char str string unit seq
//         bytes byte_buf map unit_struct tuple_struct tuple ignored_any identifier
//     }
// }

// struct SeqDeserializer<'de> {
//     iter: std::vec::IntoIter<Value<'de>>,
// }

// impl<'de> SeqDeserializer<'de> {
//     fn new(vec: Vec<Value<'de>>) -> Self {
//         SeqDeserializer {
//             iter: vec.into_iter(),
//         }
//     }
// }

// impl<'de> des::SeqAccess<'de> for SeqDeserializer<'de> {
//     type Error = DesErr;

//     fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
//     where
//         T: des::DeserializeSeed<'de>,
//     {
//         match self.iter.next() {
//             Some(value) => seed.deserialize(value).map(Some),
//             None => Ok(None),
//         }
//     }

//     fn size_hint(&self) -> Option<usize> {
//         match self.iter.size_hint() {
//             (lower, Some(upper)) if lower == upper => Some(upper),
//             _ => None,
//         }
//     }
// }

// struct MapDeserializer<'de> {
//     iter: <Table<'de> as IntoIterator>::IntoIter,
//     value: Option<Value<'de>>,
// }

// impl<'de> MapDeserializer<'de> {
//     fn new(map: Table<'de>) -> Self {
//         MapDeserializer {
//             iter: map.into_iter(),
//             value: None,
//         }
//     }
// }

// impl<'de> des::MapAccess<'de> for MapDeserializer<'de> {
//     type Error = DesErr;

//     fn next_key_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
//     where
//         T: des::DeserializeSeed<'de>,
//     {
//         match self.iter.next() {
//             Some((key, value)) => {
//                 self.value = Some(value);
//                 seed.deserialize(Value {
//                     value: ValueInner::String(key.into()),
//                     span: Default::default(),
//                 })
//                 .map(Some)
//             }
//             None => Ok(None),
//         }
//     }

//     fn next_value_seed<T>(&mut self, seed: T) -> Result<T::Value, Self::Error>
//     where
//         T: des::DeserializeSeed<'de>,
//     {
//         match self.value.take() {
//             Some(value) => seed.deserialize(value),
//             None => Err(des::Error::custom("value is missing")),
//         }
//     }

//     fn size_hint(&self) -> Option<usize> {
//         match self.iter.size_hint() {
//             (lower, Some(upper)) if lower == upper => Some(upper),
//             _ => None,
//         }
//     }
// }

// impl<'de> des::EnumAccess<'de> for MapDeserializer<'de> {
//     type Error = DesErr;
//     type Variant = MapEnumDeserializer<'de>;

//     fn variant_seed<V>(mut self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
//     where
//         V: des::DeserializeSeed<'de>,
//     {
//         use des::Error;
//         let (key, value) = match self.iter.next() {
//             Some(pair) => pair,
//             None => {
//                 return Err(Error::custom(
//                     "expected table with exactly 1 entry, found empty table",
//                 ));
//             }
//         };

//         let val = seed.deserialize(key.into_deserializer())?;
//         let variant = MapEnumDeserializer { value };

//         Ok((val, variant))
//     }
// }

// struct SpanDeserializer<'de> {
//     value: Option<Value<'de>>,
//     key: usize,
// }

// impl<'de> SpanDeserializer<'de> {
//     fn new(value: Value<'de>) -> Self {
//         Self {
//             value: Some(value),
//             key: 0,
//         }
//     }
// }

// impl<'de> des::MapAccess<'de> for SpanDeserializer<'de> {
//     type Error = DesErr;

//     fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
//     where
//         K: des::DeserializeSeed<'de>,
//     {
//         if self.key < super::span_tags::FIELDS.len() {
//             seed.deserialize(Value {
//                 value: ValueInner::String(super::span_tags::FIELDS[self.key].into()),
//                 span: Default::default(),
//             })
//             .map(Some)
//         } else {
//             Ok(None)
//         }
//     }

//     fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
//     where
//         V: des::DeserializeSeed<'de>,
//     {
//         let res = match self.key {
//             0 => seed.deserialize(Value {
//                 value: ValueInner::Integer(self.value.as_ref().unwrap().span.start as _),
//                 span: Default::default(),
//             }),
//             1 => seed.deserialize(Value {
//                 value: ValueInner::Integer(self.value.as_ref().unwrap().span.end as _),
//                 span: Default::default(),
//             }),
//             2 => seed.deserialize(self.value.take().unwrap().into_deserializer()),
//             _ => unreachable!(),
//         };

//         self.key += 1;
//         res
//     }

//     fn size_hint(&self) -> Option<usize> {
//         Some(super::span_tags::FIELDS.len() - self.key)
//     }
// }

// pub struct MapEnumDeserializer<'de> {
//     value: Value<'de>,
// }

// impl<'de> des::VariantAccess<'de> for MapEnumDeserializer<'de> {
//     type Error = DesErr;

//     fn unit_variant(self) -> Result<(), Self::Error> {
//         use des::Error;
//         match self.value.0.value {
//             ValueInner::Array(values) => {
//                 if values.is_empty() {
//                     Ok(())
//                 } else {
//                     Err(Error::custom("expected empty array"))
//                 }
//             }
//             ValueInner::Table(values) => {
//                 if values.is_empty() {
//                     Ok(())
//                 } else {
//                     Err(Error::custom("expected empty table"))
//                 }
//             }
//             e => Err(Error::custom(format!(
//                 "expected table, found {}",
//                 e.type_str()
//             ))),
//         }
//     }

//     fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
//     where
//         T: des::DeserializeSeed<'de>,
//     {
//         seed.deserialize(self.value.into_deserializer())
//     }

//     fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: des::Visitor<'de>,
//     {
//         use des::Error;
//         match self.value.0.value {
//             ValueInner::Array(values) => {
//                 if values.len() == len {
//                     serde::de::Deserializer::deserialize_seq(values.into_deserializer(), visitor)
//                 } else {
//                     Err(Error::custom(format!("expected tuple with length {}", len)))
//                 }
//             }
//             ValueInner::Table(values) => {
//                 let tuple_values: Result<Vec<_>, _> = values
//                     .into_iter()
//                     .enumerate()
//                     .map(|(index, (key, value))| match key.parse::<usize>() {
//                         Ok(key_index) if key_index == index => Ok(value),
//                         Ok(_) | Err(_) => Err(Error::custom(format!(
//                             "expected table key `{}`, but was `{}`",
//                             index, key
//                         ))),
//                     })
//                     .collect();
//                 let tuple_values = tuple_values?;

//                 if tuple_values.len() == len {
//                     serde::de::Deserializer::deserialize_seq(
//                         tuple_values.into_deserializer(),
//                         visitor,
//                     )
//                 } else {
//                     Err(Error::custom(format!("expected tuple with length {}", len)))
//                 }
//             }
//             e => Err(Error::custom(format!(
//                 "expected table, found {}",
//                 e.type_str()
//             ))),
//         }
//     }

//     fn struct_variant<V>(
//         self,
//         fields: &'static [&'static str],
//         visitor: V,
//     ) -> Result<V::Value, Self::Error>
//     where
//         V: des::Visitor<'de>,
//     {
//         des::Deserializer::deserialize_struct(
//             self.value.into_deserializer(),
//             "", // TODO: this should be the variant name
//             fields,
//             visitor,
//         )
//     }
// }

// impl<'de> des::IntoDeserializer<'de, DesErr> for Value<'de> {
//     type Deserializer = Self;

//     fn into_deserializer(self) -> Self {
//         self
//     }
// }

// pub fn deserialize_spanned<T: des::DeserializeOwned>(doc: &str) -> anyhow::Result<T> {
//     let root = de::from_str(doc)?;
//     Ok(T::deserialize(root.into_deserializer())?)
// }

#[test]
fn oh_god_please_work() {
    let s = r#"
[[fruit]]
name = "apple"

[fruit.physical]
color = "red"
shape = "round"

[[fruit.variety]]
name = "red delicious"

[[fruit.variety]]
name = "granny smith"

[[fruit]]
name = "banana"

[[fruit.variety]]
name = "plantain"
"#;
    let table = de::from_str(s).unwrap();

    panic!("{table:?}");
}
