use super::*;
use crate::dashie_schema::{ArraySchema, ObjectSchema, OneOfVariantSchema, RootSchema};
use crate::prelude::*;
use buildstructor::buildstructor;
use std::collections::BTreeMap;

pub(crate) struct Dom {
    pub(crate) root: SchemaNode,
    pub(crate) type_index: BTreeMap<String, SchemaNode>,
}

#[buildstructor]
impl Dom {
    #[builder]
    pub(crate) fn new(schema: RootSchema, max_nesting_in_file: Option<u8>) -> Result<Self> {
        let ctx = Context {
            root: schema,
            max_nesting_in_file: max_nesting_in_file.unwrap_or(2),
        };

        let doc = ctx.generate()?;

        Ok(doc)
    }

    // pub(crate) fn new(ctx: DocContext) -> Result<Self> {
    // let all_schemas = || {
    //     let schemas_in_root = root.schema.entries();
    //     let schemas_in_defs = root.definitions.values().flat_map(Schema::entries);
    //     itertools::chain(schemas_in_root, schemas_in_defs)
    // };

    // let definition_ref_counts = all_schemas()
    //     .map(|entry| entry.schema.referenced_definition())
    //     .flatten_ok()
    //     .process_results(|iter| iter.counts())?;

    // let unused_defs: Vec<_> = root
    //     .definitions
    //     .iter()
    //     .filter(|(def_name, _)| !definition_ref_counts.contains_key(def_name.as_str()))
    //     .collect();

    // anyhow::ensure!(
    //     unused_defs.is_empty(),
    //     "Found unused definitions: {unused_defs:#?}",
    // );

    // let repeated_references: BTreeMap<_, _> = definition_ref_counts
    //     .into_iter()
    //     // For schemas that are repeatedly referenced, we want to include them in the
    //     // "Type Index". This is separate page where common types are defined such
    //     // that we don't duplicate their docs all over the place.
    //     .filter(|(_, count)| *count > 1)
    //     .map(|(def_name, _)| {
    //         let schema = root.find_definition(def_name)?;
    //         anyhow::Ok((def_name.to_owned(), schema))
    //     })
    //     .try_collect()?;

    // let flattened = all_schemas()
    //     .filter(|entry| entry.level % max_level == 0)
    //     .map(|entry| {
    //         let schema = entry.schema;
    //     })
    //     .collect();

    // doc.flatten(max_level)?;

    //     Ok(doc)
    // }

    // fn flatten(&mut self, max_level: usize) -> Result<()> {
    //     FlattenDoc {
    //         ty_index: &mut self.type_index,
    //         max_level,
    //     }
    //     .flatten(&mut self.root, 0)
    // }
}

// struct FlattenDoc<'a> {
//     ty_index: &'a mut BTreeMap<String, TypeDocNode>,
//     max_level: usize,
// }

// impl FlattenDoc<'_> {
//     fn flatten(&mut self, node: &mut TypeDocNode, level: usize) -> Result<()> {
//         for child in &mut node.children {
//             if level <= self.max_level {
//                 Self {
//                     ty_index: self.ty_index,
//                     max_level: self.max_level,
//                 }
//             }

//             self.flatten(child, level + 1)?;
//         }

//         if level <= self.max_level {
//             return Ok(());
//         }

//         node.children.clear();

//         let type_doc = &node.inner;

//         let definition = type_doc
//             .key
//             .definition()
//             .with_context(|| {
//                 format!(
//                     "Can't flatten node at level {level}, because the name to \
//                     assign to it in the type index can not be inferred.\n\
//                     Schema key: {}\n\
//                     Try moving the schema to a definition, and the definition key \
//                     will be used as a name for this type in the type index",
//                     type_doc.key
//                 )
//             })?
//             .to_owned();

//         let type_index_entry = self.ty_index.get(&definition).unwrap_or_else(|| {
//             panic!("We inlined this type before, so it must be in type index: {definition}")
//         });

//         let type_index_ref = TypeIndexRef {
//             definition: definition.clone(),
//             ty: type_index_entry.inner.ty.clone(),
//         };

//         let new_type_doc = TypeDoc {
//             key: type_doc.key.clone(),
//             title: None,
//             description: None,
//             default: None,
//             examples: vec![],
//             ty: type_doc.ty.clone(),
//             type_index_ref: Some(type_index_ref),
//         };

//         let node = std::mem::replace(node, TypeDocNode::leaf(new_type_doc));

//         self.ty_index.insert(definition, node);

//         Ok(())
//     }
// }

struct Context {
    root: RootSchema,
    max_nesting_in_file: u8,
}

impl Context {
    fn generate(self) -> Result<Dom> {
        let root = PathedSourceSchema::origin(PathOrigin::Root, self.root.schema.clone());
        let root = self.schema_node(root)?;

        let definitions = self
            .root
            .definitions
            .iter()
            .map(|(def_name, schema)| {
                let origin = PathOrigin::Definition(def_name.clone());
                let schema = PathedSourceSchema::origin(origin, schema.clone());

                Ok((def_name.clone(), self.schema_node(schema)?))
            })
            .collect::<Result<_>>()?;

        Ok(Dom {
            root,
            type_index: definitions,
        })
    }

    fn schema_node(&self, schema: PathedSourceSchema) -> Result<SchemaNode> {
        //     if let Some(reference) = schema.inner.reference.clone() {
        //         self.schema_node_ref(schema, reference)
        //     } else {
        //         self.schema_node_non_ref(schema)
        //     }
        // }

        // fn schema_node_ref(&self, schema: PathedSourceSchema, reference: String) -> Result<SchemaNode> {
        //     let doc = SchemaDoc::Ref(reference);
        //     let path = schema.path;

        //     let inline = self
        //         .options
        //         .root
        //         .inline_referenced_definition(&schema.inner)?;

        //     let ty = Type::from_source_schema(&inline);

        //     let schema = Schema { path, ty, doc };

        //     Ok(SchemaNode::leaf(schema))
        // }

        // fn schema_node_non_ref(&self, schema: PathedSourceSchema) -> Result<SchemaNode> {
        let path = schema.path;

        let ty = Type::from_source_schema(&self.root.inline_referenced_definition(&schema.inner)?);

        let schema = schema.inner;

        let children = if let Some(array) = schema.array_schema {
            Self::array_children(&path, array)?
        } else if let Some(object) = schema.object_schema {
            Self::object_children(&path, object)?
        } else if let Some(variants) = schema.one_of {
            Self::one_of_children(&path, variants)?
        } else {
            vec![]
        };

        let children = children
            .into_iter()
            .map(|child| self.schema_node(child))
            .try_collect()?;

        let data = SchemaDocData {
            title: schema.title,
            description: schema.description,
            default: schema.default,
            examples: schema.examples,
        };

        let doc = if let Some(reference) = schema.reference.clone() {
            SchemaDoc::Ref(SchemaDocRef { reference, data })
        } else if path.segments.len() % (usize::from(self.max_nesting_in_file) + 1) == 0 {
            SchemaDoc::Nested(data)
        } else {
            SchemaDoc::Embedded(data)
        };

        let schema = Schema { path, ty, doc };

        Ok(SchemaNode { schema, children })
    }

    fn array_children(path: &Path, array: ArraySchema) -> Result<Vec<PathedSourceSchema>> {
        let path = path.add_segment(PathSegment::Index);
        let items = PathedSourceSchema::new(path, *array.items);
        Ok(vec![items])
    }

    fn object_children(path: &Path, object: ObjectSchema) -> Result<Vec<PathedSourceSchema>> {
        let properties = object
            .properties
            .into_iter()
            .map(|(name, value)| {
                let field = Field {
                    name: name.clone(),
                    required: object.required.contains(&name),
                };
                let path = path.add_segment(PathSegment::Field(field));
                PathedSourceSchema::new(path, value)
            })
            .collect();

        Ok(properties)
    }

    fn one_of_children(
        path: &Path,
        variants: Vec<OneOfVariantSchema>,
    ) -> Result<Vec<PathedSourceSchema>> {
        let names: Vec<_> = variants
            .clone()
            .into_iter()
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
                let path = path.add_segment(PathSegment::Variant(name));

                PathedSourceSchema::new(path, variant.schema)
            })
            .collect();

        Ok(variants)
    }
}
