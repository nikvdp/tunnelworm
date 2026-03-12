use crate::{
    cli::FowlConfig,
    error::{Error, Result},
};

pub async fn run_fowl(_config: FowlConfig) -> Result<()> {
    Err(Error::NotImplemented("fowl runtime"))
}

pub async fn run_fowld() -> Result<()> {
    Err(Error::NotImplemented("fowld runtime"))
}
