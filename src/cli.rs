use clap::Parser;

use crate::{
    error::{Error, Result},
    spec::{LocalSpec, RemoteSpec},
};

#[derive(Debug, Clone)]
pub struct FowlConfig {
    pub mailbox: Option<String>,
    pub code_length: usize,
    pub code: Option<String>,
    pub locals: Vec<LocalSpec>,
    pub remotes: Vec<RemoteSpec>,
}

#[derive(Debug, Parser)]
#[command(name = "fowl")]
#[command(about = "Forward Over Wormhole, Locally")]
#[command(version)]
pub struct FowlCli {
    #[arg(long = "mailbox")]
    pub mailbox: Option<String>,
    #[arg(long = "code-length", default_value_t = 2)]
    pub code_length: usize,
    #[arg(long = "local", short = 'L')]
    pub local: Vec<String>,
    #[arg(long = "remote", short = 'R')]
    pub remote: Vec<String>,
    pub code: Option<String>,
}

impl TryFrom<FowlCli> for FowlConfig {
    type Error = Error;

    fn try_from(value: FowlCli) -> Result<Self> {
        let locals = value
            .local
            .iter()
            .map(|spec| LocalSpec::parse(spec))
            .collect::<Result<Vec<_>>>()?;
        let remotes = value
            .remote
            .iter()
            .map(|spec| RemoteSpec::parse(spec))
            .collect::<Result<Vec<_>>>()?;

        if locals.is_empty() && remotes.is_empty() {
            return Err(Error::Usage(
                "you must specify at least one --local/-L or --remote/-R spec".into(),
            ));
        }
        if value.code_length == 0 {
            return Err(Error::Usage("code length must be at least 1".into()));
        }

        Ok(Self {
            mailbox: value.mailbox,
            code_length: value.code_length,
            code: value.code,
            locals,
            remotes,
        })
    }
}
