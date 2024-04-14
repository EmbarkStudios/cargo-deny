mod rendering;

use self::rendering::{RenderedSection, Renderer};
use crate::cli::codegen::input::{EnumVariantSchema, RootSchema, Schema};
use anyhow::{Context, Result};
use itertools::Itertools;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

struct DocOptions<'a> {
    root: &'a RootSchema,
    max_level: usize,
}

pub(crate) struct Doc {
    root: TypeDocNode,
    type_index: BTreeMap<String, TypeDocNode>,
}

#[derive(Debug)]
struct TypeDoc {
    key: SchemaKey,
    title: Option<String>,
    description: Option<String>,
    default: Option<Value>,
    examples: Vec<Value>,
    ty: Type,
    type_index_ref: Option<TypeIndexRef>,
}

#[derive(Debug)]
struct TypeIndexRef {
    definition: String,
    ty: Type,
}

#[derive(Debug, Clone)]
struct LeafType {
    ty: Option<String>,
    format: Option<String>,
    enum_schema: Option<Vec<EnumVariantSchema>>,
}

impl LeafType {
    fn from_schema(schema: &Schema) -> Self {
        Self {
            ty: schema.ty.clone(),
            format: schema.format.clone(),
            enum_schema: schema.enum_schema.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct Type {
    inner: LeafType,

    /// [`LeafType`] exists to make sure we don't have recursion in this field.
    /// We describe at max two levels of nesting in type tags.
    array_items_ty: Option<LeafType>,
}

impl Type {
    fn from_schema(schema: &Schema) -> Self {
        let inner = LeafType::from_schema(schema);

        let array_items_ty = schema
            .array_schema
            .as_ref()
            .map(|array| LeafType::from_schema(&array.items));

        Self {
            inner,
            array_items_ty,
        }
    }
}

#[derive(Debug)]
struct TypeDocNode {
    inner: TypeDoc,
    children: Vec<TypeDocNode>,
}

struct CreateDoc<'a> {
    options: &'a DocOptions<'a>,
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

impl SchemaKey {
    fn push_inline_segment(&self, new_segment: SchemaKeySegmentKind) -> Self {
        let mut segments = self.segments.clone();
        segments.push(SchemaKeySegment::inline(new_segment));
        Self {
            root: self.root.clone(),
            segments,
        }
    }

    fn definition(&self) -> Option<&str> {
        self.segments.last()?.definition.as_deref()
    }
}

impl fmt::Display for SchemaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut segments = self.segments.iter();

        if let Some(segment) = segments.next() {
            write!(f, "{segment}")?;
        }

        segments.try_for_each(|segment| match &segment.kind {
            SchemaKeySegmentKind::Field(_) => write!(f, ".{segment}"),
            SchemaKeySegmentKind::Index => write!(f, " array item"),
            SchemaKeySegmentKind::Variant(_) => write!(f, " as {segment}"),
        })
    }
}

#[derive(Clone, Debug)]
enum SchemaKeyOrigin {
    Root,
    Definition(String),
}

#[derive(Clone, Debug)]
struct SchemaKeySegment {
    kind: SchemaKeySegmentKind,

    /// If this part of the key is a reference to a definition, then this field
    /// stores the name of that definition.
    definition: Option<String>,
}

impl SchemaKeySegment {
    fn inline(kind: SchemaKeySegmentKind) -> Self {
        Self {
            definition: None,
            kind,
        }
    }
}

#[derive(Clone, Debug)]
enum SchemaKeySegmentKind {
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
    fn new(options: DocOptions<'_>) -> Result<Self> {
        let DocOptions { root, max_level } = options;

        let all_schemas = || {
            let schemas_in_root = root.schema.entries();
            let schemas_in_defs = root.definitions.values().flat_map(Schema::entries);
            itertools::chain(schemas_in_root, schemas_in_defs)
        };

        let definition_ref_counts = all_schemas()
            .map(|entry| entry.schema.referenced_definition())
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

        let repeated_references: BTreeMap<_, _> = definition_ref_counts
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

        let flattened = all_schemas()
            .filter(|entry| entry.level % max_level == 0)
            .map(|entry| {
                let schema = entry.schema;

            })
            .collect();

        let ctx = CreateDoc {
            root,
            type_index: &repeated_references,
        };

        let mut doc = Self {
            root: ctx.root_type_doc()?,
            type_index: ctx.type_index_docs()?,
        };

        doc.flatten(max_level)?;

        Ok(doc)
    }

    fn flatten(&mut self, max_level: usize) -> Result<()> {
        FlattenDoc {
            ty_index: &mut self.type_index,
            max_level,
        }
        .flatten(&mut self.root, 0)
    }
}

struct FlattenDoc<'a> {
    ty_index: &'a mut BTreeMap<String, TypeDocNode>,
    max_level: usize,
}

impl FlattenDoc<'_> {
    fn flatten(&mut self, node: &mut TypeDocNode, level: usize) -> Result<()> {
        for child in &mut node.children {
            if level <= self.max_level {
                Self {
                    ty_index: self.ty_index,
                    max_level: self.max_level,
                }
            }

            self.flatten(child, level + 1)?;
        }

        if level <= self.max_level {
            return Ok(());
        }

        node.children.clear();

        let type_doc = &node.inner;

        let definition = type_doc
            .key
            .definition()
            .with_context(|| {
                format!(
                    "Can't flatten node at level {level}, because the name to \
                    assign to it in the type index can not be inferred.\n\
                    Schema key: {}\n\
                    Try moving the schema to a definition, and the definition key \
                    will be used as a name for this type in the type index",
                    type_doc.key
                )
            })?
            .to_owned();

        let type_index_entry = self.ty_index.get(&definition).unwrap_or_else(|| {
            panic!("We inlined this type before, so it must be in type index: {definition}")
        });

        let type_index_ref = TypeIndexRef {
            definition: definition.clone(),
            ty: type_index_entry.inner.ty.clone(),
        };

        let new_type_doc = TypeDoc {
            key: type_doc.key.clone(),
            title: None,
            description: None,
            default: None,
            examples: vec![],
            ty: type_doc.ty.clone(),
            type_index_ref: Some(type_index_ref),
        };

        let node = std::mem::replace(node, TypeDocNode::leaf(new_type_doc));

        self.ty_index.insert(definition, node);

        Ok(())
    }
}

impl CreateDoc<'_> {
    fn root_type_doc(&self) -> Result<TypeDocNode> {
        let key = SchemaKey {
            root: SchemaKeyOrigin::Root,
            segments: vec![],
        };
        let root_schema = KeyedSchema::new(key, self.root.schema.clone());

        self.type_doc_node(root_schema)
    }

    fn type_index_docs(&self) -> Result<BTreeMap<String, TypeDocNode>> {
        self.type_index
            .iter()
            .map(|(def_name, &schema)| {
                let key = SchemaKey {
                    root: SchemaKeyOrigin::Definition(def_name.clone()),
                    segments: vec![],
                };
                let schema = KeyedSchema::new(key, schema.clone());

                anyhow::Ok((def_name.clone(), self.type_doc_node(schema)?))
            })
            .collect()
    }

    fn type_doc_node(&self, schema: KeyedSchema) -> Result<TypeDocNode> {
        let referenced_def = schema.inner.referenced_definition()?;

        // If this schema references a type from the type index, then avoid
        // inlining the schema and finish the type doc early.
        if referenced_def.is_some_and(|def| self.type_index.contains_key(def)) {
            return Ok(TypeDocNode::leaf(self.type_doc(schema.clone())?));
        }

        let schema = schema.inline_referenced_definition(self.root)?;

        let type_doc = self.type_doc(schema.clone())?;

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
            .map(|child| self.type_doc_node(child))
            .try_collect()?;

        Ok(TypeDocNode {
            inner: type_doc,
            children,
        })
    }

    fn array_children(schema: KeyedSchema) -> Result<Vec<KeyedSchema>> {
        let array = schema.inner.try_into_array()?;

        // Avoid adding useless documentation for item
        if array.items.is_undocumented_primitive() {
            return Ok(vec![]);
        }

        let key = schema.key.push_inline_segment(SchemaKeySegmentKind::Index);
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

                let key = schema
                    .key
                    .push_inline_segment(SchemaKeySegmentKind::Field(key));
                KeyedSchema::new(key, value)
            })
            .collect();

        Ok(properties)
    }

    fn one_of_children(schema: KeyedSchema) -> Result<Vec<KeyedSchema>> {
        let variants = schema.inner.try_into_one_of()?;
        let names: Vec<_> = variants
            .iter()
            .map(|variant| variant.name().map(ToOwned::to_owned))
            .try_collect()?;

        let duplicates: Vec<_> = names.iter().duplicates().collect();

        anyhow::ensure!(
            duplicates.is_empty(),
            "Duplicate variant names found in one_of schema.\n\
            Duplicates: {duplicates:?}\n\
            Variants: {variants:#?}",
        );

        let variants = variants
            .into_iter()
            .zip(names)
            .map(|(variant, name)| {
                let key = schema
                    .key
                    .push_inline_segment(SchemaKeySegmentKind::Variant(name));

                KeyedSchema::new(key, variant.schema)
            })
            .collect();

        Ok(variants)
    }

    fn type_index_ref(&self, schema: &Schema) -> Result<Option<TypeIndexRef>> {
        let ty_index_ref = schema.referenced_definition()?.and_then(|def_name| {
            let ty = self
                .type_index
                .get(def_name)
                .copied()
                .map(Type::from_schema)?;

            Some(TypeIndexRef {
                definition: def_name.to_owned(),
                ty,
            })
        });

        Ok(ty_index_ref)
    }

    fn type_doc(&self, schema: KeyedSchema) -> Result<TypeDoc> {
        let type_index_ref = self.type_index_ref(&schema.inner)?;
        let ty = Type::from_schema(&schema.inner);

        let base = TypeDoc {
            key: schema.key,
            title: schema.inner.title,
            description: schema.inner.description,
            default: schema.inner.default,
            examples: schema.inner.examples,
            ty,
            type_index_ref,
        };

        Ok(base)
    }
}

impl TypeDocNode {
    fn leaf(data: TypeDoc) -> Self {
        Self {
            inner: data,
            children: vec![],
        }
    }
}

impl fmt::Display for SchemaKeySegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SchemaKeySegmentKind::Field(field) => f.write_str(&field.name),
            SchemaKeySegmentKind::Index => f.write_str("n"),
            SchemaKeySegmentKind::Variant(name) => f.write_str(name),
        }
    }
}

impl KeyedSchema {
    fn new(key: SchemaKey, inner: Schema) -> Self {
        Self { key, inner }
    }

    fn inline_referenced_definition(mut self, root: &RootSchema) -> Result<Self> {
        if let Some(last_segment) = self.key.segments.last_mut() {
            if let Some(definition) = self.inner.referenced_definition()? {
                last_segment.definition = Some(definition.to_owned());
            }
        }

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

    let renderer = Renderer {
        root_file_base: RenderedSection::leaf(header, body),
    };

    let files = renderer.doc(&Doc::new(root, 2)?);

    files.iter().try_for_each(|file| file.write(out_dir))?;

    Ok(())
}
