use clap::{builder::StyledStr, Args, Command, CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    persistent::PersistentConfig,
    spec::{LocalSpec, RemoteSpec},
};

const TUNNELWORM_LONG_ABOUT: &str = "\
Create a TCP port forward between two terminals over a magic-wormhole session.

Top-level `tunnelworm ...` is the one-off path.
`tunnelworm tunnel create ...` bootstraps a named persistent tunnel.
`tunnelworm tunnel up ...` starts a saved persistent tunnel by name.
`tunnelworm tunnel list`, `status`, and `delete` manage saved tunnel endpoints.
`tunnelworm self-update` refreshes the installed binaries from GitHub releases.

One side provides `--listen` and the peer provides `--connect`.
If you use SSH-style compatibility syntax instead, `-L` still needs a
corresponding `-R` on the peer and `-R` still needs a corresponding `-L`.";

const TUNNELWORM_AFTER_HELP: &str = "\
Examples:
  One-off forward, connector side allocates a code:
    tunnelworm --connect 22

  Matching one-off peer listens locally with that code:
    tunnelworm --listen 9000 7-cobalt-signal

  Named persistent tunnel, creator side bootstraps a saved tunnel:
    tunnelworm tunnel create office-ssh --connect 22

  Named persistent tunnel, peer side joins with the printed code:
    tunnelworm tunnel create laptop-ssh --listen 9000 --code 7-cobalt-signal

  Start one saved tunnel endpoint later by name:
    tunnelworm tunnel up office-ssh

  Start one saved tunnel endpoint later by explicit state path:
    tunnelworm tunnel up --state ./.tunnelworm/office-ssh--abcd1234.json

  Inspect one saved tunnel endpoint by name:
    tunnelworm tunnel status office-ssh

  List saved tunnel endpoints:
    tunnelworm tunnel list

  Delete one saved tunnel endpoint:
    tunnelworm tunnel delete office-ssh

  Generate a zsh completion script:
    tunnelworm completion zsh

  Update the installed binaries from the latest GitHub release:
    tunnelworm self-update

  SSH-style compatibility syntax still works for one-off flows:
    tunnelworm -R 9000:localhost:22
    tunnelworm -L 9000:localhost:22 7-cobalt-signal

Notes:
  - `--listen` always needs a complementary `--connect` on the peer.
  - `--connect` always needs a complementary `--listen` on the peer.
  - Bare ports on `--listen` and `--connect` default to loopback.
  - `-L` always needs a corresponding `-R` on the peer.
  - `-R` always needs a corresponding `-L` on the peer.";

const TUNNEL_CREATE_AFTER_HELP: &str = "\
Examples:
  Create the service side of a saved tunnel and print a bootstrap code:
    tunnelworm tunnel create office-ssh --connect 22

  Create the client side using the printed code from the other machine:
    tunnelworm tunnel create laptop-ssh --listen 9097 --code 7-cobalt-signal";

const TUNNEL_AFTER_HELP: &str = "\
Examples:
  Create the service side of a saved tunnel:
    tunnelworm tunnel create office-ssh --connect 22

  Start that saved tunnel later by name:
    tunnelworm tunnel up office-ssh";

const TUNNEL_UP_AFTER_HELP: &str = "\
Examples:
  Start a saved tunnel endpoint by name:
    tunnelworm tunnel up laptop-ssh

  Start a saved tunnel endpoint by explicit state file:
    tunnelworm tunnel up --state ./.tunnelworm/laptop-ssh--abcd1234.json";

const TUNNEL_LIST_AFTER_HELP: &str = "\
Example:
  List the saved tunnel endpoints available on this machine:
    tunnelworm tunnel list";

const TUNNEL_STATUS_AFTER_HELP: &str = "\
Examples:
  Inspect a saved tunnel endpoint by name:
    tunnelworm tunnel status laptop-ssh

  Inspect an explicit state file directly:
    tunnelworm tunnel status --state ./.tunnelworm/laptop-ssh--abcd1234.json";

const TUNNEL_DELETE_AFTER_HELP: &str = "\
Examples:
  Delete a saved tunnel endpoint by name:
    tunnelworm tunnel delete laptop-ssh

  Delete an explicit state file directly:
    tunnelworm tunnel delete --state ./.tunnelworm/laptop-ssh--abcd1234.json";

const COMPLETION_AFTER_HELP: &str = "\
Examples:
  Print a zsh completion script:
    tunnelworm completion zsh

  Save a bash completion script locally:
    tunnelworm completion bash > ~/.local/share/bash-completion/completions/tunnelworm";

const SELF_UPDATE_AFTER_HELP: &str = "\
Examples:
  Download the latest GitHub release and replace this binary:
    tunnelworm self-update

Notes:
  If a sibling tunnelwormd binary is installed next to tunnelworm, it is updated too.";

fn help_bold(value: &str) -> String {
    stdout_style().label(value)
}

fn help_header(value: &str) -> String {
    if std::io::stdout().is_terminal() {
        format!("\x1b[1;4m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

fn styled_top_level_long_about() -> StyledStr {
    StyledStr::from(format!(
        "{}\n\n{}:\n  {}  Create a one-off forward between two terminals\n  {}  Create one named persistent tunnel endpoint\n  {}      Start one saved tunnel endpoint by name\n\n{}:\n  {}         List saved tunnel endpoints\n  {}       Inspect one saved tunnel endpoint\n  {}       Remove one saved tunnel endpoint\n\n{}:\n  Use {} on one side and {} on the peer.\n  If you use {} or {} instead, they still need the opposite half on the peer.",
        help_bold("Create a TCP port forward between two terminals over a magic-wormhole session."),
        help_header("Preferred workflows"),
        help_bold("tunnelworm ..."),
        help_bold("tunnelworm tunnel create ..."),
        help_bold("tunnelworm tunnel up ..."),
        help_header("Management"),
        help_bold("tunnelworm tunnel list"),
        help_bold("tunnelworm tunnel status"),
        help_bold("tunnelworm tunnel delete"),
        help_header("Matching rules"),
        help_bold("--listen"),
        help_bold("--connect"),
        help_bold("-L"),
        help_bold("-R"),
    ))
}

fn styled_top_level_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm --connect 22\n    tunnelworm --listen 9000 7-cobalt-signal\n\n  {}:\n    tunnelworm tunnel create office-ssh --connect 22\n    tunnelworm tunnel create laptop-ssh --listen 9000 --code 7-cobalt-signal\n    tunnelworm tunnel up office-ssh\n\n  {}:\n    tunnelworm tunnel status office-ssh\n    tunnelworm tunnel list\n    tunnelworm tunnel delete office-ssh\n\n  {}:\n    tunnelworm completion zsh\n\n  {}:\n    tunnelworm self-update\n\n  {}:\n    tunnelworm -R 9000:localhost:22\n    tunnelworm -L 9000:localhost:22 7-cobalt-signal\n\n{}:\n  - `--listen` always needs a complementary `--connect` on the peer.\n  - `--connect` always needs a complementary `--listen` on the peer.\n  - Bare ports on `--listen` and `--connect` default to loopback.\n  - `-L` always needs a corresponding `-R` on the peer.\n  - `-R` always needs a corresponding `-L` on the peer.",
        help_header("Examples"),
        help_bold("One-off forward"),
        help_bold("Named persistent tunnel"),
        help_bold("Manage saved endpoints"),
        help_bold("Shell completion"),
        help_bold("Self-update"),
        help_bold("SSH-style compatibility syntax"),
        help_header("Notes"),
    ))
}

fn styled_tunnel_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm tunnel create office-ssh --connect 22\n\n  {}:\n    tunnelworm tunnel up office-ssh",
        help_header("Examples"),
        help_bold("Create the service side"),
        help_bold("Start that saved endpoint later"),
    ))
}

fn styled_tunnel_create_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm tunnel create office-ssh --connect 22\n\n  {}:\n    tunnelworm tunnel create laptop-ssh --listen 9097 --code 7-cobalt-signal",
        help_header("Examples"),
        help_bold("Create the service side and print a bootstrap code"),
        help_bold("Create the peer side using that printed code"),
    ))
}

fn styled_tunnel_up_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm tunnel up laptop-ssh\n\n  {}:\n    tunnelworm tunnel up --state ./.tunnelworm/laptop-ssh--abcd1234.json",
        help_header("Examples"),
        help_bold("Start a saved endpoint by name"),
        help_bold("Start a saved endpoint by explicit state file"),
    ))
}

fn styled_tunnel_list_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm tunnel list",
        help_header("Example"),
        help_bold("List the saved tunnel endpoints on this machine"),
    ))
}

fn styled_tunnel_status_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm tunnel status laptop-ssh\n\n  {}:\n    tunnelworm tunnel status --state ./.tunnelworm/laptop-ssh--abcd1234.json",
        help_header("Examples"),
        help_bold("Inspect a saved endpoint by name"),
        help_bold("Inspect an explicit state file directly"),
    ))
}

fn styled_tunnel_delete_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm tunnel delete laptop-ssh\n\n  {}:\n    tunnelworm tunnel delete --state ./.tunnelworm/laptop-ssh--abcd1234.json",
        help_header("Examples"),
        help_bold("Delete a saved endpoint by name"),
        help_bold("Delete an explicit state file directly"),
    ))
}

fn styled_completion_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm completion zsh\n\n  {}:\n    tunnelworm completion bash > ~/.local/share/bash-completion/completions/tunnelworm",
        help_header("Examples"),
        help_bold("Print a zsh completion script"),
        help_bold("Save a bash completion script locally"),
    ))
}

fn styled_self_update_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm self-update\n\n{}:\n  - This downloads the latest GitHub release for the current platform.\n  - If a sibling `tunnelwormd` is installed next to `tunnelworm`, it is updated too.",
        help_header("Examples"),
        help_bold("Download and install the latest release"),
        help_header("Notes"),
    ))
}

pub fn tunnelworm_command() -> Command {
    TunnelwormCli::command()
        .long_about(styled_top_level_long_about())
        .after_long_help(styled_top_level_after_help())
        .mut_subcommand("completion", |sub| {
            sub.after_long_help(styled_completion_after_help())
        })
        .mut_subcommand("self-update", |sub| {
            sub.after_long_help(styled_self_update_after_help())
        })
        .mut_subcommand("tunnel", |sub| {
            sub.after_long_help(styled_tunnel_after_help())
                .mut_subcommand("create", |sub| {
                    sub.after_long_help(styled_tunnel_create_after_help())
                })
                .mut_subcommand("up", |sub| sub.after_long_help(styled_tunnel_up_after_help()))
                .mut_subcommand("list", |sub| {
                    sub.after_long_help(styled_tunnel_list_after_help())
                })
                .mut_subcommand("status", |sub| {
                    sub.after_long_help(styled_tunnel_status_after_help())
                })
                .mut_subcommand("delete", |sub| {
                    sub.after_long_help(styled_tunnel_delete_after_help())
                })
        })
}

pub fn tunnelworm_completion_command() -> Command {
    TunnelwormCompletionCli::command()
        .long_about(styled_top_level_long_about())
        .after_long_help(styled_top_level_after_help())
        .mut_subcommand("completion", |sub| {
            sub.after_long_help(styled_completion_after_help())
        })
        .mut_subcommand("self-update", |sub| {
            sub.after_long_help(styled_self_update_after_help())
        })
        .mut_subcommand("tunnel", |sub| {
            sub.after_long_help(styled_tunnel_after_help())
                .mut_subcommand("create", |sub| {
                    sub.after_long_help(styled_tunnel_create_after_help())
                })
                .mut_subcommand("up", |sub| sub.after_long_help(styled_tunnel_up_after_help()))
                .mut_subcommand("list", |sub| {
                    sub.after_long_help(styled_tunnel_list_after_help())
                })
                .mut_subcommand("status", |sub| {
                    sub.after_long_help(styled_tunnel_status_after_help())
                })
                .mut_subcommand("delete", |sub| {
                    sub.after_long_help(styled_tunnel_delete_after_help())
                })
        })
}

pub fn parse_tunnelworm_cli() -> TunnelwormCli {
    let matches = tunnelworm_command().get_matches();
    TunnelwormCli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

#[derive(Debug, Clone)]
pub struct FowlConfig {
    pub tunnel_name: Option<String>,
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
    pub name: Option<String>,
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TunnelUpConfig {
    pub name: Option<String>,
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TunnelDeleteConfig {
    pub name: Option<String>,
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum TunnelwormInvocation {
    Run(FowlConfig),
    Completion(Shell),
    SelfUpdate,
    TunnelCreate(FowlConfig),
    TunnelUp(TunnelUpConfig),
    TunnelList,
    TunnelStatus(TunnelStatusConfig),
    TunnelDelete(TunnelDeleteConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardHalf {
    Listen,
    Connect,
    Mixed,
}

#[derive(Debug, Clone, Copy)]
pub struct AnsiStyle {
    enabled: bool,
}

pub fn stdout_style() -> AnsiStyle {
    AnsiStyle {
        enabled: std::io::stdout().is_terminal(),
    }
}

pub fn stderr_style() -> AnsiStyle {
    AnsiStyle {
        enabled: std::io::stderr().is_terminal(),
    }
}

impl AnsiStyle {
    fn paint(&self, value: &str, code: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{value}\x1b[0m")
        } else {
            value.to_string()
        }
    }

    pub fn heading(&self, value: &str) -> String {
        self.paint(value, "1;36")
    }

    pub fn label(&self, value: &str) -> String {
        self.paint(value, "1")
    }

    pub fn status(&self, value: &str) -> String {
        self.paint(value, "1;33")
    }

    pub fn error(&self, value: &str) -> String {
        self.paint(value, "1;31")
    }
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
        help = "Accept local TCP connections at port or bind_address:port; a bare port listens on loopback"
    )]
    pub listen: Vec<String>,
    #[arg(
        long = "connect",
        visible_alias = "connect-on",
        value_name = "ADDR",
        help = "Connect locally to port or host:port when the peer forwards traffic here; a bare port connects to loopback"
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
    #[arg(help = "Existing wormhole code to join; omit it to allocate a new code")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct CompletionTopLevelArgs {
    #[command(flatten)]
    pub common: CommonSessionArgs,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Persistent tunnel lifecycle commands")]
#[command(after_long_help = TUNNEL_AFTER_HELP)]
pub struct TunnelArgs {
    #[command(subcommand)]
    pub command: TunnelCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum TunnelCommand {
    #[command(about = "Create one named side of a persistent tunnel")]
    Create(TunnelCreateArgs),
    #[command(about = "Start one saved side of a persistent tunnel")]
    Up(TunnelUpArgs),
    #[command(about = "List saved persistent tunnel endpoints")]
    List(TunnelListArgs),
    #[command(about = "Inspect persistent tunnel state without starting the tunnel")]
    Status(TunnelStatusArgs),
    #[command(about = "Delete one saved persistent tunnel endpoint")]
    Delete(TunnelDeleteArgs),
}

#[derive(Debug, Clone, Args)]
#[command(about = "Create one named side of a persistent tunnel")]
#[command(after_long_help = TUNNEL_CREATE_AFTER_HELP)]
pub struct TunnelCreateArgs {
    #[arg(value_name = "NAME", help = "Local name for this saved tunnel endpoint")]
    pub name: String,
    #[command(flatten)]
    pub common: CommonSessionArgs,
    #[arg(long = "code", value_name = "CODE", help = "Join an existing bootstrap code instead of allocating a new one")]
    pub code: Option<String>,
    #[arg(long = "overwrite", help = "Replace an existing saved tunnel endpoint with the same local name")]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Start one saved side of a persistent tunnel")]
#[command(after_long_help = TUNNEL_UP_AFTER_HELP)]
pub struct TunnelUpArgs {
    #[arg(value_name = "NAME", required_unless_present = "state", help = "Local name of the saved tunnel endpoint to start")]
    pub name: Option<String>,
    #[arg(long = "state", value_name = "PATH", required_unless_present = "name", help = "Use an explicit persistent state file path")]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Inspect the stored state for one local tunnel participant")]
#[command(after_long_help = TUNNEL_STATUS_AFTER_HELP)]
pub struct TunnelStatusArgs {
    #[arg(value_name = "NAME", required_unless_present = "state", help = "Local name of the saved tunnel endpoint to inspect")]
    pub name: Option<String>,
    #[arg(long = "state", value_name = "PATH", required_unless_present = "name", help = "Inspect an explicit persistent state file path")]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
#[command(about = "List saved persistent tunnel endpoints")]
#[command(after_long_help = TUNNEL_LIST_AFTER_HELP)]
pub struct TunnelListArgs {}

#[derive(Debug, Clone, Args)]
#[command(about = "Delete one saved persistent tunnel endpoint")]
#[command(after_long_help = TUNNEL_DELETE_AFTER_HELP)]
pub struct TunnelDeleteArgs {
    #[arg(value_name = "NAME", required_unless_present = "state", help = "Local name of the saved tunnel endpoint to delete")]
    pub name: Option<String>,
    #[arg(long = "state", value_name = "PATH", required_unless_present = "name", help = "Delete an explicit persistent state file path")]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(name = "tunnelworm")]
#[command(about = "Create a TCP forward over a magic-wormhole session")]
#[command(long_about = TUNNELWORM_LONG_ABOUT)]
#[command(after_long_help = TUNNELWORM_AFTER_HELP)]
#[command(version)]
#[command(args_conflicts_with_subcommands = true)]
#[command(subcommand_precedence_over_arg = true)]
pub struct TunnelwormCli {
    #[command(subcommand)]
    pub command: Option<FowlSubcommand>,
    #[command(flatten)]
    pub top_level: TopLevelArgs,
}

#[derive(Debug, Parser)]
#[command(name = "tunnelworm")]
#[command(about = "Create a TCP forward over a magic-wormhole session")]
#[command(long_about = TUNNELWORM_LONG_ABOUT)]
#[command(after_long_help = TUNNELWORM_AFTER_HELP)]
#[command(version)]
#[command(args_conflicts_with_subcommands = true)]
#[command(subcommand_precedence_over_arg = true)]
pub struct TunnelwormCompletionCli {
    #[command(subcommand)]
    pub command: Option<FowlSubcommand>,
    #[command(flatten)]
    pub top_level: CompletionTopLevelArgs,
}

#[derive(Debug, Clone, Subcommand)]
pub enum FowlSubcommand {
    Completion(CompletionArgs),
    SelfUpdate(SelfUpdateArgs),
    Tunnel(TunnelArgs),
}

#[derive(Debug, Clone, Args)]
#[command(about = "Generate shell completion scripts")]
#[command(after_long_help = COMPLETION_AFTER_HELP)]
pub struct CompletionArgs {
    #[arg(value_name = "SHELL", help = "Shell to generate completions for")]
    pub shell: Shell,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Download and install the latest GitHub release")]
#[command(after_long_help = SELF_UPDATE_AFTER_HELP)]
pub struct SelfUpdateArgs {}

impl TryFrom<TunnelwormCli> for TunnelwormInvocation {
    type Error = Error;

    fn try_from(value: TunnelwormCli) -> Result<Self> {
        match value.command {
            Some(FowlSubcommand::Completion(args)) => Ok(Self::Completion(args.shell)),
            Some(FowlSubcommand::SelfUpdate(_)) => Ok(Self::SelfUpdate),
            Some(FowlSubcommand::Tunnel(tunnel)) => match tunnel.command {
                TunnelCommand::Create(args) => Ok(Self::TunnelCreate(build_config(
                    args.common,
                    args.code,
                    None,
                    args.overwrite,
                    false,
                    Some(args.name),
                )?)),
                TunnelCommand::Up(args) => Ok(Self::TunnelUp(TunnelUpConfig {
                    name: args.name,
                    state: args.state,
                })),
                TunnelCommand::List(_) => Ok(Self::TunnelList),
                TunnelCommand::Status(args) => Ok(Self::TunnelStatus(TunnelStatusConfig {
                    name: args.name,
                    state: args.state,
                })),
                TunnelCommand::Delete(args) => Ok(Self::TunnelDelete(TunnelDeleteConfig {
                    name: args.name,
                    state: args.state,
                })),
            },
            None => Ok(Self::Run(build_config(
                value.top_level.common,
                value.top_level.code,
                None,
                false,
                false,
                None,
            )?)),
        }
    }
}

fn build_config(
    common: CommonSessionArgs,
    code: Option<String>,
    state: Option<PathBuf>,
    overwrite: bool,
    allow_empty_forwards: bool,
    tunnel_name: Option<String>,
) -> Result<FowlConfig> {
    let (locals, remotes) = parse_forward_args(common.forwards, allow_empty_forwards)?;

    if common.code_length == 0 {
        return Err(Error::Usage("code length must be at least 1".into()));
    }

    Ok(FowlConfig {
        tunnel_name,
        mailbox: common.mailbox,
        code_length: common.code_length,
        code,
        locals,
        remotes,
        state,
        overwrite,
    })
}

fn parse_forward_args(
    forwards: ForwardArgs,
    allow_empty_forwards: bool,
) -> Result<(Vec<LocalSpec>, Vec<RemoteSpec>)> {
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
        if allow_empty_forwards {
            return Ok((locals, remotes));
        }
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

    pub fn local_summary(&self) -> String {
        match self.local_half() {
            ForwardHalf::Listen => {
                let spec = self.locals.first().expect("listen half needs a local spec");
                format!(
                    "listen on {}:{}",
                    spec.bind_interface.as_deref().unwrap_or("127.0.0.1"),
                    spec.local_listen_port
                        .map(|port| port.to_string())
                        .unwrap_or_else(|| "PORT".into())
                )
            },
            ForwardHalf::Connect => {
                let spec = self.remotes.first().expect("connect half needs a remote spec");
                format!(
                    "connect to {}:{}",
                    spec.connect_address.as_deref().unwrap_or("127.0.0.1"),
                    spec.local_connect_port
                        .map(|port| port.to_string())
                        .unwrap_or_else(|| "PORT".into())
                )
            },
            ForwardHalf::Mixed => "multiple forward halves".into(),
        }
    }

    pub fn peer_preferred_command(&self, code: &str, persistent: bool) -> Option<String> {
        let prefix = if persistent { "tunnelworm tunnel up" } else { "tunnelworm" };
        match self.local_half() {
            ForwardHalf::Listen => Some(format!("{prefix} --connect HOST:PORT {code}")),
            ForwardHalf::Connect => {
                Some(format!("{prefix} --listen LISTEN_HOST:LISTEN_PORT {code}"))
            },
            ForwardHalf::Mixed => None,
        }
    }

    pub fn peer_ssh_command(&self, code: &str) -> Option<String> {
        match self.local_half() {
            ForwardHalf::Listen => Some(format!(
                "tunnelworm -R {}:HOST:PORT {code}",
                self.locals
                    .first()
                    .and_then(|spec| spec.local_listen_port)
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "LISTEN_PORT".into())
            )),
            ForwardHalf::Connect => Some(format!(
                "tunnelworm -L LISTEN_PORT:{}:{} {code}",
                self.remotes
                    .first()
                    .and_then(|spec| spec.connect_address.clone())
                    .unwrap_or_else(|| "HOST".into()),
                self.remotes
                    .first()
                    .and_then(|spec| spec.local_connect_port)
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "PORT".into())
            )),
            ForwardHalf::Mixed => None,
        }
    }

    pub fn persistent_reuse_command(path: &Path) -> String {
        format!("tunnelworm tunnel up --state {}", path.display())
    }

    pub fn persistent_reset_command(&self, code: &str) -> Option<String> {
        let tunnel_name = self.tunnel_name.as_deref().unwrap_or(code);
        match self.local_half() {
            ForwardHalf::Listen => {
                let spec = self.locals.first()?;
                Some(format!(
                    "tunnelworm tunnel create {} --listen {}:{} --overwrite",
                    tunnel_name,
                    spec.bind_interface.as_deref().unwrap_or("127.0.0.1"),
                    spec.local_listen_port
                        .map(|port| port.to_string())
                        .unwrap_or_else(|| "PORT".into())
                ))
            },
            ForwardHalf::Connect => {
                let spec = self.remotes.first()?;
                let base = format!(
                    "tunnelworm tunnel create {} --connect {}:{}",
                    tunnel_name,
                    spec.connect_address.as_deref().unwrap_or("127.0.0.1"),
                    spec.local_connect_port
                        .map(|port| port.to_string())
                        .unwrap_or_else(|| "PORT".into())
                );
                if self.code.is_some() {
                    Some(format!("{base} --code {code} --overwrite"))
                } else {
                    Some(format!("{base} --overwrite"))
                }
            },
            ForwardHalf::Mixed => None,
        }
    }
}
