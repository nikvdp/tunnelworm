use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::{
    error::{Error, Result},
    persistent::PersistentConfig,
    spec::{LocalSpec, RemoteSpec},
};

const FOWL_LONG_ABOUT: &str = "\
Create a TCP port forward between two terminals over a magic-wormhole session.

Top-level `fowl ...` is the one-off path.
`fowl tunnel up ...` is the persistent tunnel path.

One side provides `--listen` and the peer provides `--connect`.
If you use SSH-style compatibility syntax instead, `-L` still needs a
corresponding `-R` on the peer and `-R` still needs a corresponding `-L`.";

const FOWL_AFTER_HELP: &str = "\
Examples:
  One-off forward, connector side allocates a code:
    fowl --connect localhost:22

  Matching one-off peer listens locally with that code:
    fowl --listen 127.0.0.1:9000 7-cobalt-signal

  Persistent tunnel, creator side allocates a reusable code:
    fowl tunnel up --connect localhost:22

  Persistent tunnel, join side reuses that code:
    fowl tunnel up --listen 127.0.0.1:9000 --code 7-cobalt-signal

  Inspect the stored state for one local participant:
    fowl tunnel status --state ./.fowl/7-cobalt-signal--abcd1234.json

  Inspect a tunnel by code when only one local state matches:
    fowl tunnel status --code 7-cobalt-signal

  SSH-style compatibility syntax still works for one-off flows:
    fowl -R 9000:localhost:22
    fowl -L 9000:localhost:22 7-cobalt-signal

Notes:
  - `--listen` always needs a complementary `--connect` on the peer.
  - `--connect` always needs a complementary `--listen` on the peer.
  - `-L` always needs a corresponding `-R` on the peer.
  - `-R` always needs a corresponding `-L` on the peer.";

#[derive(Debug, Clone)]
pub struct FowlConfig {
    pub mailbox: Option<String>,
    pub code_length: usize,
    pub code: Option<String>,
    pub locals: Vec<LocalSpec>,
    pub remotes: Vec<RemoteSpec>,
    pub state: Option<PathBuf>,
    pub overwrite: bool,
}

#[derive(Debug, Clone)]
pub struct TunnelStatusConfig {
    pub code: Option<String>,
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum FowlInvocation {
    Run(FowlConfig),
    TunnelUp(FowlConfig),
    TunnelStatus(TunnelStatusConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardHalf {
    Listen,
    Connect,
    Mixed,
}

#[derive(Debug, Clone, Args, Default)]
pub struct ForwardArgs {
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
    #[arg(
        long = "listen",
        visible_alias = "listen-to",
        value_name = "ADDR",
        help = "Accept local TCP connections at port or bind_address:port"
    )]
    pub listen: Vec<String>,
    #[arg(
        long = "connect",
        visible_alias = "connect-on",
        value_name = "ADDR",
        help = "Connect locally to host:port when the peer forwards traffic here"
    )]
    pub connect: Vec<String>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct CommonSessionArgs {
    #[arg(long = "mailbox", help = "Override the mailbox websocket URL")]
    pub mailbox: Option<String>,
    #[arg(long = "code-length", default_value_t = 2, help = "Number of words to allocate when creating a new code")]
    pub code_length: usize,
    #[command(flatten)]
    pub forwards: ForwardArgs,
}

#[derive(Debug, Clone, Args, Default)]
pub struct TopLevelArgs {
    #[command(flatten)]
    pub common: CommonSessionArgs,
    #[arg(long = "state", value_name = "PATH", help = "Use an explicit persistent state file path")]
    pub state: Option<PathBuf>,
    #[arg(help = "Existing wormhole code to join; omit it to allocate a new code")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Persistent tunnel lifecycle commands")]
pub struct TunnelArgs {
    #[command(subcommand)]
    pub command: TunnelCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum TunnelCommand {
    #[command(about = "Create or resume a persistent tunnel sidecar")]
    Up(TunnelUpArgs),
    #[command(about = "Inspect persistent tunnel state without starting the tunnel")]
    Status(TunnelStatusArgs),
}

#[derive(Debug, Clone, Args)]
#[command(about = "Create or resume one side of a persistent tunnel")]
pub struct TunnelUpArgs {
    #[command(flatten)]
    pub common: CommonSessionArgs,
    #[arg(long = "state", value_name = "PATH", help = "Use an explicit persistent state file path")]
    pub state: Option<PathBuf>,
    #[arg(long = "overwrite", help = "Replace conflicting local persistent state instead of refusing to start")]
    pub overwrite: bool,
    #[arg(long = "code", value_name = "CODE", help = "Join an existing persistent tunnel code instead of allocating one")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Inspect the stored state for one local tunnel participant")]
pub struct TunnelStatusArgs {
    #[arg(long = "code", value_name = "CODE", required_unless_present = "state", help = "Inspect the persistent tunnel state associated with this code")]
    pub code: Option<String>,
    #[arg(long = "state", value_name = "PATH", required_unless_present = "code", help = "Inspect an explicit persistent state file path")]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(name = "fowl")]
#[command(about = "Create a TCP forward over a magic-wormhole session")]
#[command(long_about = FOWL_LONG_ABOUT)]
#[command(after_long_help = FOWL_AFTER_HELP)]
#[command(version)]
#[command(subcommand_precedence_over_arg = true)]
pub struct FowlCli {
    #[command(subcommand)]
    pub command: Option<FowlSubcommand>,
    #[command(flatten)]
    pub top_level: TopLevelArgs,
}

#[derive(Debug, Clone, Subcommand)]
pub enum FowlSubcommand {
    Tunnel(TunnelArgs),
}

impl TryFrom<FowlCli> for FowlInvocation {
    type Error = Error;

    fn try_from(value: FowlCli) -> Result<Self> {
        match value.command {
            Some(FowlSubcommand::Tunnel(tunnel)) => match tunnel.command {
                TunnelCommand::Up(args) => Ok(Self::TunnelUp(build_config(
                    args.common,
                    args.code,
                    args.state,
                    args.overwrite,
                )?)),
                TunnelCommand::Status(args) => Ok(Self::TunnelStatus(TunnelStatusConfig {
                    code: args.code,
                    state: args.state,
                })),
            },
            None => Ok(Self::Run(build_config(
                value.top_level.common,
                value.top_level.code,
                value.top_level.state,
                false,
            )?)),
        }
    }
}

fn build_config(
    common: CommonSessionArgs,
    code: Option<String>,
    state: Option<PathBuf>,
    overwrite: bool,
) -> Result<FowlConfig> {
    let (locals, remotes) = parse_forward_args(common.forwards)?;

    if common.code_length == 0 {
        return Err(Error::Usage("code length must be at least 1".into()));
    }

    Ok(FowlConfig {
        mailbox: common.mailbox,
        code_length: common.code_length,
        code,
        locals,
        remotes,
        state,
        overwrite,
    })
}

fn parse_forward_args(forwards: ForwardArgs) -> Result<(Vec<LocalSpec>, Vec<RemoteSpec>)> {
    let mut locals = forwards
        .local
        .iter()
        .map(|spec| LocalSpec::parse(spec))
        .collect::<Result<Vec<_>>>()?;
    let mut remotes = forwards
        .remote
        .iter()
        .map(|spec| RemoteSpec::parse(spec))
        .collect::<Result<Vec<_>>>()?;

    for (index, spec) in forwards.listen.iter().enumerate() {
        locals.push(LocalSpec::parse_listen(spec, index + 1)?);
    }
    for (index, spec) in forwards.connect.iter().enumerate() {
        remotes.push(RemoteSpec::parse_connect(spec, index + 1)?);
    }

    if locals.is_empty() && remotes.is_empty() {
        return Err(Error::Usage(
            "you must specify at least one forward with --listen/--connect or --local/-L/--remote/-R"
                .into(),
        ));
    }

    Ok((locals, remotes))
}

impl FowlConfig {
    pub fn persistent_config(&self) -> Result<PersistentConfig> {
        PersistentConfig::from_fowl_config(self)
    }

    pub fn local_half(&self) -> ForwardHalf {
        match (!self.locals.is_empty(), !self.remotes.is_empty()) {
            (true, false) => ForwardHalf::Listen,
            (false, true) => ForwardHalf::Connect,
            _ => ForwardHalf::Mixed,
        }
    }

    pub fn peer_requirement_line(&self) -> &'static str {
        match self.local_half() {
            ForwardHalf::Listen => {
                "Peer must provide the complementary --connect side for this tunnel. In SSH-style compatibility syntax, that is the peer's -R side."
            },
            ForwardHalf::Connect => {
                "Peer must provide the complementary --listen side for this tunnel. In SSH-style compatibility syntax, that is the peer's -L side."
            },
            ForwardHalf::Mixed => {
                "Peer must provide the complementary half of each forward on the other side of the tunnel."
            },
        }
    }
}
