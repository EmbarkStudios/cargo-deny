use super::{RootSchema, Schema};

pub(crate) trait Traverse<T> {
    fn traverse_mut(&mut self, visit: &mut dyn FnMut(&mut T)) {
        let result = self.try_traverse_mut(&mut |item| {
            visit(item);
            Ok::<(), std::convert::Infallible>(())
        });
        match result {
            Ok(()) => {}
            Err(infallible) => match infallible {},
        }
    }

    fn try_traverse_mut<E>(
        &mut self,
        visit: &mut dyn FnMut(&mut T) -> Result<(), E>,
    ) -> Result<(), E>;
}

impl Traverse<Schema> for Schema {
    fn try_traverse_mut<E>(
        &mut self,
        visit: &mut dyn FnMut(&mut Schema) -> Result<(), E>,
    ) -> Result<(), E> {
        visit(self)?;

        if let Some(object) = &mut self.object_schema {
            for schema in object.properties.values_mut() {
                schema.try_traverse_mut(visit)?;
            }
        }

        if let Some(array) = &mut self.array_schema {
            array.items.try_traverse_mut(visit)?;
        }

        if let Some(one_of) = &mut self.one_of {
            for variant in one_of {
                variant.schema.try_traverse_mut(visit)?;
            }
        }

        Ok(())
    }
}

impl Traverse<Schema> for RootSchema {
    fn try_traverse_mut<E>(
        &mut self,
        visit: &mut dyn FnMut(&mut Schema) -> Result<(), E>,
    ) -> Result<(), E> {
        self.definitions
            .values_mut()
            .chain([&mut self.schema])
            .try_for_each(|schema| schema.try_traverse_mut(visit))
    }
}
