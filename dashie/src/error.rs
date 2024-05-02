use crate::prelude::*;

pub(crate) fn fail_or_warn(ignore_error: bool, err: Error) -> Result {
    if !ignore_error {
        return Err(err)
    }

    warn!("{err:?}");

    Ok(())
}
