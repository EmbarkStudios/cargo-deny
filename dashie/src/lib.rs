mod cli;
mod source;
mod entrypoint;
mod md_doc;
mod error;
mod serdex;

pub use entrypoint::run;

mod prelude {
    pub(crate) use anyhow::{bail, ensure, Context as _, Error, format_err};
    pub(crate) use itertools::Itertools as _;
    pub(crate) use tracing::{info, debug, warn, error};

    pub(crate) type Result<T = (), E = anyhow::Error> = std::result::Result<T, E>;
}
