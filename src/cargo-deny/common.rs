use clap::arg_enum;

arg_enum! {
    #[derive(Copy, Clone, Debug)]
    pub enum MessageFormat {
        Human,
        Json,
    }
}
