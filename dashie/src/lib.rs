mod cli;
mod dashie_schema;
mod entrypoint;
mod md_doc;

pub use entrypoint::run;

mod prelude {
    pub(crate) use anyhow::{bail, Context as _};
    pub(crate) use itertools::Itertools as _;
    pub(crate) use tracing::{info, warn};

    pub(crate) type Result<T = (), E = anyhow::Error> = std::result::Result<T, E>;
}
