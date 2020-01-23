#[cfg(test)]
pub(crate) mod test {
    use std::path::PathBuf;

    pub(crate) struct ConfigData<T> {
        pub(crate) config: T,
        pub(crate) files: codespan::Files<String>,
        pub(crate) id: codespan::FileId,
    }

    pub(crate) fn load<T: serde::de::DeserializeOwned>(path: impl Into<PathBuf>) -> ConfigData<T> {
        let path = path.into();
        let contents = std::fs::read_to_string(&path).unwrap();

        let config = toml::from_str(&contents).unwrap();
        let mut files = codespan::Files::new();
        let id = files.add(path.to_string_lossy(), contents);

        ConfigData { config, files, id }
    }
}
