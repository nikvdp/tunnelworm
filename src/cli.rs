use clap::Parser;
use std::path::PathBuf;

use crate::{
    error::{Error, Result},
    persistent::PersistentConfig,
    spec::{LocalSpec, RemoteSpec},
};

const FOWL_LONG_ABOUT: &str = "\
Create a TCP port forward between two terminals over a magic-wormhole session.

One side usually starts with -R to allocate a code. The other side joins with
that code and a matching -L rule. Matching forward declarations are still
required on both peers.";

const FOWL_AFTER_HELP: &str = "\
Examples:
  Named fowl-style forward, terminal 1 allocates a code and exposes the peer's
  local web server on port 7000:
    fowl -R web:9000:listen=7000

  Terminal 2 joins that code and agrees to the same logical forward:
    fowl -L web:7000:remote-connect=9000 7-cobalt-signal

  SSH-style syntax for the same job, terminal 1:
    fowl -R 7000:127.0.0.1:9000

  SSH-style syntax for the matching peer, terminal 2:
    fowl -L 7000:127.0.0.1:9000 7-cobalt-signal

  Bind the local listener to a specific interface:
    fowl -L web:7000:remote-connect=9000:bind=0.0.0.0 7-cobalt-signal

Notes:
  - Omit CODE to allocate a new code and print it.
  - Provide CODE to join an existing session.
  - Both peers must still provide corresponding -L and -R rules.";

#[derive(Debug, Clone)]
pub struct FowlConfig {
    pub mailbox: Option<String>,
    pub code_length: usize,
    pub code: Option<String>,
    pub locals: Vec<LocalSpec>,
    pub remotes: Vec<RemoteSpec>,
    pub persistent: bool,
    pub state: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(name = "fowl")]
#[command(about = "Create a TCP forward over a magic-wormhole session")]
#[command(long_about = FOWL_LONG_ABOUT)]
#[command(after_long_help = FOWL_AFTER_HELP)]
#[command(version)]
pub struct FowlCli {
    #[arg(long = "mailbox", help = "Override the mailbox websocket URL")]
    pub mailbox: Option<String>,
    #[arg(long = "code-length", default_value_t = 2, help = "Number of words to allocate when creating a new code")]
    pub code_length: usize,
    #[arg(
        long = "local",
        short = 'L',
        value_name = "SPEC",
        help = "Accept local listeners with fowl syntax or SSH syntax [bind_address:]port:host:hostport"
    )]
    pub local: Vec<String>,
    #[arg(
        long = "remote",
        short = 'R',
        value_name = "SPEC",
        help = "Offer remote listeners with fowl syntax or SSH syntax [bind_address:]port:host:hostport"
    )]
    pub remote: Vec<String>,
    #[arg(long = "persistent", help = "Store trust material on disk and hand off to the reconnecting daemon")]
    pub persistent: bool,
    #[arg(long = "state", value_name = "PATH", help = "Use an explicit persistent state file path")]
    pub state: Option<PathBuf>,
    #[arg(help = "Existing wormhole code to join; omit it to allocate a new code")]
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
            persistent: value.persistent,
            state: value.state,
        })
    }
}

impl FowlConfig {
    pub fn persistent_config(&self) -> Result<PersistentConfig> {
        PersistentConfig::from_fowl_config(self)
    }
}
