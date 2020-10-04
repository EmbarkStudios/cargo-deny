use super::Pack;

pub enum ErrorSink {
    Channel(crossbeam::channel::Sender<Pack>),
    Vec(Vec<Pack>),
}

impl ErrorSink {
    pub fn push<P: Into<Pack>>(&mut self, pack: P) {
        match self {
            Self::Channel(chan) => chan.send(pack.into()).unwrap(),
            Self::Vec(v) => v.push(pack.into()),
        }
    }
}
