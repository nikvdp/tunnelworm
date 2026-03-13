use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
    #[error("usage error: {0}")]
    Usage(String),
    #[error("update error: {0}")]
    Update(String),
    #[error("session error: {0}")]
    Session(String),
    #[error("persistent state error: {0}")]
    PersistentState(String),
    #[error("authentication error: {0}")]
    Authentication(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Wormhole(#[from] magic_wormhole::WormholeError),
    #[error(transparent)]
    Forwarding(#[from] magic_wormhole::forwarding::ForwardingError),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
}

pub type Result<T> = std::result::Result<T, Error>;
