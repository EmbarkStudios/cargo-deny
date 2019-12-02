use clap::arg_enum;
use std::path::PathBuf;

arg_enum! {
    #[derive(Copy, Clone, Debug)]
    pub enum MessageFormat {
        Human,
        Json,
    }
}

pub(crate) fn make_absolute_path(path: PathBuf, context_dir: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        context_dir.join(path)
    }
}
