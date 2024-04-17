use crate::cli::codegen::source;
use anyhow::Result;
use serde_json::Value;
use std::fmt;

#[derive(Debug)]
pub(crate) struct SchemaNode {
    pub(crate) schema: Schema,
    pub(crate) children: Vec<SchemaNode>,
}

impl SchemaNode {
    pub(crate) fn leaf(schema: Schema) -> Self {
        Self {
            schema,
            children: vec![],
        }
    }
}

#[derive(Debug)]
pub(crate) struct Schema {
    pub(crate) path: Path,
    pub(crate) ty: Type,
    pub(crate) doc: SchemaDoc,
}

#[derive(Debug)]
pub(crate) enum SchemaDoc {
    /// Documentation should be embedded in the same file. The value is [`None`]
    Embedded(SchemaDocData),

    /// Schema should live as a nested document
    Nested(SchemaDocData),

    /// This schema is a reference to some other schema. It may be either a reference
    /// to a definition within the same schema or a reference to some external schema.
    Ref(SchemaDocRef),
}

impl SchemaDoc {
    pub(crate) fn reference(&self) -> Option<&str> {
        match self {
            SchemaDoc::Ref(reference) => Some(&reference.reference),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct SchemaDocRef {
    pub(crate) reference: String,

    /// Additional data that may override the details of the referenced schema.
    pub(crate) data: SchemaDocData,
}

#[derive(Debug)]
pub(crate) struct SchemaDocData {
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) default: Option<Value>,
    pub(crate) examples: Vec<Value>,
}

#[derive(Clone, Debug)]
pub(crate) struct Path {
    pub(crate) origin: PathOrigin,
    pub(crate) segments: Vec<PathSegment>,
}

impl Path {
    pub(crate) fn new(origin: PathOrigin) -> Self {
        Self {
            origin,
            segments: vec![],
        }
    }

    #[must_use]
    pub(crate) fn add_segment(&self, new_segment: PathSegment) -> Self {
        let mut segments = self.segments.clone();
        segments.push(new_segment);
        Self {
            origin: self.origin.clone(),
            segments,
        }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut segments = self.segments.iter();

        if let Some(segment) = segments.next() {
            if let PathSegment::Variant(_) = segment {
                write!(f, "As {segment}")?;
            } else {
                write!(f, "{segment}")?;
            }
        }

        segments.try_for_each(|segment| match &segment {
            PathSegment::Field(_) => write!(f, ".{segment}"),
            PathSegment::Index => write!(f, "{segment}"),
            PathSegment::Variant(_) => write!(f, "as {segment}"),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) enum PathOrigin {
    Root,
    Definition(String),
}

impl fmt::Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            PathSegment::Field(field) => f.write_str(&field.name),
            // .<nth>
            // [..]
            PathSegment::Index => f.write_str("[N]"),
            PathSegment::Variant(name) => write!(f, "{name}"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum PathSegment {
    Field(Field),
    Index,
    Variant(String),
}

#[derive(Clone, Debug)]
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) required: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct LeafType {
    pub(crate) ty: Option<String>,
    pub(crate) format: Option<String>,
    pub(crate) enum_schema: Option<Vec<source::EnumVariantSchema>>,
}

impl LeafType {
    fn from_source_schema(schema: &source::Schema) -> Self {
        Self {
            ty: schema.ty.clone(),
            format: schema.format.clone(),
            enum_schema: schema.enum_schema.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Type {
    pub(crate) inner: LeafType,

    /// [`LeafType`] exists to make sure we don't have recursion in this field.
    /// We describe at max two levels of nesting in type tags.
    pub(crate) array_items_ty: Option<LeafType>,
}

impl Type {
    pub(crate) fn from_source_schema(schema: &source::Schema) -> Self {
        let inner = LeafType::from_source_schema(schema);

        let array_items_ty = schema
            .array_schema
            .as_ref()
            .map(|array| LeafType::from_source_schema(&array.items));

        Self {
            inner,
            array_items_ty,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PathedSourceSchema {
    pub(crate) path: Path,
    pub(crate) inner: source::Schema,
}

impl PathedSourceSchema {
    pub(crate) fn new(path: Path, inner: source::Schema) -> Self {
        Self { path, inner }
    }

    pub(crate) fn origin(origin: PathOrigin, inner: source::Schema) -> Self {
        Self::new(Path::new(origin), inner)
    }

    fn inline_referenced_definition(mut self, root: &source::RootSchema) -> Result<Self> {
        self.inner = root.inline_referenced_definition(&self.inner)?;
        Ok(self)
    }
}
