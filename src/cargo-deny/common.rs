use std::path::{Path, PathBuf};

pub(crate) fn make_absolute_path(path: PathBuf, context_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        context_dir.join(path)
    }
}
