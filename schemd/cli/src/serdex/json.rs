use serde::Serialize;

/// Shortcut for [`serde_json::to_string_pretty`] that unwraps the result, asserting
/// that it is serializable to JSON.
///
/// # Panics
///
/// Panics if [`serde_json::to_string_pretty`] returns an error.
/// It is fine for this function to panic, because the former function returns an error
/// due to a type-level mistake caused by a developer like serializing a map with non-string key to JSON.
/// Hopefully, the panic message should be clear enough for the developer to catch this problem.
#[track_caller]
pub(crate) fn to_string_pretty<T: Serialize>(value: T) -> String {
    serialize_imp(&value, serde_json::to_string_pretty)
}

#[track_caller]
fn serialize_imp<T, D>(value: T, ser: fn(T) -> serde_json::Result<D>) -> D
where
    T: Serialize,
{
    // Not using `map_err` to make `track_caller` work.
    match ser(value) {
        Ok(ok) => ok,
        Err(err) => panic!(
            "failed to serialize `{}` to JSON `{}`: {:?}",
            std::any::type_name::<T>(),
            std::any::type_name::<D>(),
            anyhow::Error::from(err)
        ),
    }
}
