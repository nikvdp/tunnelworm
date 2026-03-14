use clap::{
    Args, Command, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum,
    builder::StyledStr,
};
use clap_complete::Shell;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
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

Top-level `tunnelworm ...` keeps the one-off forwarding path.
`tunnelworm open ...` opens a bare one-off tunnel with no port forward yet.
`tunnelworm tunnel create ...` bootstraps a named persistent tunnel, with or without an initial port forward.
`tunnelworm tunnel up ...` starts a saved persistent tunnel by name.
`tunnelworm tunnel list`, `status`, and `delete` manage saved tunnel endpoints.
`tunnelworm pipe <name>` streams stdin/stdout over one live named tunnel.
`tunnelworm send-file <name> ...` sends one file over a live named tunnel.
`tunnelworm self-update` refreshes the installed binary from GitHub releases.

One side provides `--listen` and the peer provides `--connect`.
If you use SSH-style compatibility syntax instead, `-L` still needs a
corresponding `-R` on the peer and `-R` still needs a corresponding `-L`.";

const TUNNELWORM_AFTER_HELP: &str = "\
Examples:
  Open a bare one-off tunnel and print a code:
    tunnelworm open

  Join that bare one-off tunnel with the printed code:
    tunnelworm open 7-cobalt-signal

  One-off forward, connector side allocates a code:
    tunnelworm --connect 22

  Matching one-off peer listens locally with that code:
    tunnelworm --listen 9000 7-cobalt-signal

  Named persistent tunnel, creator side bootstraps a saved tunnel with no initial forward:
    tunnelworm tunnel create office

  Named persistent tunnel, peer side joins that bare tunnel with the printed code:
    tunnelworm tunnel create laptop --code 7-cobalt-signal

  Named persistent tunnel, creator side bootstraps a saved tunnel:
    tunnelworm tunnel create office-ssh --connect 22

  Named persistent tunnel, peer side joins with the printed code:
    tunnelworm tunnel create laptop-ssh --listen 9000 --code 7-cobalt-signal

  Start one saved tunnel endpoint later by name:
    tunnelworm tunnel up office-ssh

  Start one saved tunnel endpoint later by explicit state path:
    tunnelworm tunnel up --state /path/to/tunnelworm/office-ssh--abcd1234.json

  Stream stdin over a live named tunnel:
    echo hello | tunnelworm pipe office-ssh

  Send one file over a live named tunnel:
    tunnelworm send-file office-ssh ./report.txt

  Open the remote login shell over a live named tunnel:
    tunnelworm shell office-ssh

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
  - Saved tunnel state defaults to the per-user tunnelworm state directory.
  - Use `--state-dir` to choose a different state directory or `--state` to point at one file.
  - `-L` always needs a corresponding `-R` on the peer.
  - `-R` always needs a corresponding `-L` on the peer.";

const TUNNEL_CREATE_AFTER_HELP: &str = "\
Examples:
  Create one saved tunnel endpoint with no initial port forward:
    tunnelworm tunnel create office

  Create the peer side of that bare tunnel using the printed code:
    tunnelworm tunnel create laptop --code 7-cobalt-signal

  Create the service side of a saved tunnel and print a bootstrap code:
    tunnelworm tunnel create office-ssh --connect 22

  Create the client side using the printed code from the other machine:
    tunnelworm tunnel create laptop-ssh --listen 9097 --code 7-cobalt-signal";

const TUNNEL_AFTER_HELP: &str = "\
Examples:
  Create one saved tunnel endpoint with no initial port forward:
    tunnelworm tunnel create office

  Create the service side of a saved tunnel:
    tunnelworm tunnel create office-ssh --connect 22

  Start that saved tunnel later by name:
    tunnelworm tunnel up office-ssh";

const TUNNEL_UP_AFTER_HELP: &str = "\
Examples:
  Start a saved tunnel endpoint by name:
    tunnelworm tunnel up laptop-ssh

  Start one bare saved tunnel endpoint by name:
    tunnelworm tunnel up office

  Start a saved tunnel endpoint by explicit state file:
    tunnelworm tunnel up --state /path/to/tunnelworm/laptop-ssh--abcd1234.json";

const TUNNEL_LIST_AFTER_HELP: &str = "\
Example:
  List the saved tunnel endpoints available on this machine:
    tunnelworm tunnel list";

const TUNNEL_STATUS_AFTER_HELP: &str = "\
Examples:
  Inspect a saved tunnel endpoint by name:
    tunnelworm tunnel status laptop-ssh

  Inspect an explicit state file directly:
    tunnelworm tunnel status --state /path/to/tunnelworm/laptop-ssh--abcd1234.json";

const TUNNEL_DELETE_AFTER_HELP: &str = "\
Examples:
  Delete a saved tunnel endpoint by name:
    tunnelworm tunnel delete laptop-ssh

  Delete an explicit state file directly:
    tunnelworm tunnel delete --state /path/to/tunnelworm/laptop-ssh--abcd1234.json";

const PIPE_AFTER_HELP: &str = "\
Examples:
  Send piped stdin through one live named tunnel:
    echo hello | tunnelworm pipe office-ssh

  Fully redirected stdio needs an explicit direction:
    tunnelworm pipe office-ssh --send < input.txt > /dev/null

Notes:
  If stdin is redirected and stdout is still a terminal, tunnelworm sends.
  If stdout is redirected and stdin is still a terminal, tunnelworm receives.
  If both stdin and stdout are redirected, pass --send or --receive explicitly.";

const SEND_FILE_AFTER_HELP: &str = "\
Examples:
  Send one file and keep its basename on the peer:
    tunnelworm send-file office-ssh ./report.txt

  Send one file to an explicit path on the peer:
    tunnelworm send-file office-ssh ./report.txt /tmp/inbox/report.txt

  Replace an existing destination file on the peer:
    tunnelworm send-file office-ssh ./report.txt /tmp/inbox/report.txt --overwrite

Notes:
  The peer writes into its tunnel process working directory unless you pass a remote path.
  `~` expands on both the sending and receiving sides.
  Existing destination files are rejected unless you pass --overwrite.
  `send` is a shorthand alias for `send-file`.";

const SHELL_AFTER_HELP: &str = "\
Examples:
  Open an interactive shell on the remote end of one live named tunnel:
    tunnelworm shell office-ssh

  Run one remote command and print its output locally:
    tunnelworm shell office-ssh --command 'pwd'

Notes:
  Without --command, tunnelworm starts the remote user's login shell.";

const PORTS_AFTER_HELP: &str = "\
Examples:
  List the current port forwards on one live tunnel:
    tunnelworm ports office

  Add one forward that listens locally and connects on the remote side:
    tunnelworm ports add office --local-listen 9097 --remote-connect 22

  Remove one forward by its numeric ID:
    tunnelworm ports remove office 1

Notes:
  Use `local` / `remote` terminology in this command family.
  A bare port like `9097` defaults to loopback on that side.";

const OPEN_AFTER_HELP: &str = "\
Examples:
  Open a bare one-off tunnel and print a bootstrap code:
    tunnelworm open

  Join a bare one-off tunnel with the printed code:
    tunnelworm open 7-cobalt-signal

Notes:
  A bare tunnel has no port forward yet.
  Use shell, pipe, send-file, or later port management against the live tunnel.";

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
  This replaces the installed `tunnelworm` binary in place.";

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
        "{}\n\n{}:\n  {}  Create a one-off forward between two terminals\n  {}       Open one bare one-off tunnel\n  {}  Create one named persistent tunnel endpoint\n  {}      Start one saved tunnel endpoint by name\n\n{}:\n  {}         List saved tunnel endpoints\n  {}       Inspect one saved tunnel endpoint\n  {}       Remove one saved tunnel endpoint\n\n{}:\n  Use {} on one side and {} on the peer.\n  If you use {} or {} instead, they still need the opposite half on the peer.",
        help_bold("Create a TCP port forward between two terminals over a magic-wormhole session."),
        help_header("Preferred workflows"),
        help_bold("tunnelworm ..."),
        help_bold("tunnelworm open ..."),
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
        "{}:\n  {}:\n    tunnelworm --connect 22\n    tunnelworm --listen 9000 7-cobalt-signal\n\n  {}:\n    tunnelworm tunnel create office-ssh --connect 22\n    tunnelworm tunnel create laptop-ssh --listen 9000 --code 7-cobalt-signal\n    tunnelworm tunnel up office-ssh\n\n  {}:\n    echo hello | tunnelworm pipe office-ssh\n\n  {}:\n    tunnelworm send-file office-ssh ./report.txt\n\n  {}:\n    tunnelworm shell office-ssh\n\n  {}:\n    tunnelworm tunnel status office-ssh\n    tunnelworm tunnel list\n    tunnelworm tunnel delete office-ssh\n\n  {}:\n    tunnelworm completion zsh\n\n  {}:\n    tunnelworm self-update\n\n  {}:\n    tunnelworm -R 9000:localhost:22\n    tunnelworm -L 9000:localhost:22 7-cobalt-signal\n\n{}:\n  - `--listen` always needs a complementary `--connect` on the peer.\n  - `--connect` always needs a complementary `--listen` on the peer.\n  - Bare ports on `--listen` and `--connect` default to loopback.\n  - `tunnelworm pipe` infers send or receive from stdio unless both ends are redirected.\n  - `tunnelworm send-file` writes into the peer's working directory unless you pass a remote path.\n  - Without `--command`, `tunnelworm shell` starts the remote login shell.\n  - `-L` always needs a corresponding `-R` on the peer.\n  - `-R` always needs a corresponding `-L` on the peer.",
        help_header("Examples"),
        help_bold("One-off forward"),
        help_bold("Named persistent tunnel"),
        help_bold("Pipe over a live named tunnel"),
        help_bold("Send one file over a live named tunnel"),
        help_bold("Shell over a live named tunnel"),
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
        "{}:\n  {}:\n    tunnelworm tunnel up laptop-ssh\n\n  {}:\n    tunnelworm tunnel up --state /path/to/tunnelworm/laptop-ssh--abcd1234.json",
        help_header("Examples"),
        help_bold("Start a saved endpoint by name"),
        help_bold("Start a saved endpoint by explicit state file"),
    ))
}

fn styled_open_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm open\n\n  {}:\n    tunnelworm open 7-cobalt-signal\n\n{}:\n  - A bare tunnel has no port forward yet.\n  - Use shell, pipe, send-file, or later port management against the live tunnel.",
        help_header("Examples"),
        help_bold("Open a bare one-off tunnel and print a code"),
        help_bold("Join a bare one-off tunnel with that code"),
        help_header("Notes"),
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
        "{}:\n  {}:\n    tunnelworm tunnel status laptop-ssh\n\n  {}:\n    tunnelworm tunnel status --state /path/to/tunnelworm/laptop-ssh--abcd1234.json",
        help_header("Examples"),
        help_bold("Inspect a saved endpoint by name"),
        help_bold("Inspect an explicit state file directly"),
    ))
}

fn styled_tunnel_delete_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm tunnel delete laptop-ssh\n\n  {}:\n    tunnelworm tunnel delete --state /path/to/tunnelworm/laptop-ssh--abcd1234.json",
        help_header("Examples"),
        help_bold("Delete a saved endpoint by name"),
        help_bold("Delete an explicit state file directly"),
    ))
}

fn styled_pipe_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    echo hello | tunnelworm pipe office-ssh\n\n  {}:\n    tunnelworm pipe office-ssh --send < input.txt > /dev/null\n\n{}:\n  - If stdin is redirected and stdout is still a terminal, tunnelworm sends.\n  - If stdout is redirected and stdin is still a terminal, tunnelworm receives.\n  - If both stdin and stdout are redirected, pass `--send` or `--receive` explicitly.",
        help_header("Examples"),
        help_bold("Send piped stdin through one live named tunnel"),
        help_bold("Force the sending side when both ends are redirected"),
        help_header("Notes"),
    ))
}

fn styled_send_file_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm send-file office-ssh ./report.txt\n\n  {}:\n    tunnelworm send-file office-ssh ./report.txt ~/inbox/report.txt\n\n  {}:\n    tunnelworm send-file office-ssh ./report.txt ~/inbox/report.txt --overwrite\n\n{}:\n  - The peer writes into its tunnel process working directory unless you pass a remote path.\n  - `~` expands on both the sending and receiving sides.\n  - Existing destination files are rejected unless you pass `--overwrite`.\n  - `send` is a shorthand alias for `send-file`.",
        help_header("Examples"),
        help_bold("Send one file and keep its basename on the peer"),
        help_bold("Send one file to an explicit path on the peer"),
        help_bold("Replace an existing destination file on the peer"),
        help_header("Notes"),
    ))
}

fn styled_shell_after_help() -> StyledStr {
    StyledStr::from(format!(
        "{}:\n  {}:\n    tunnelworm shell office-ssh\n\n  {}:\n    tunnelworm shell office-ssh --command 'pwd'\n\n{}:\n  - Without `--command`, tunnelworm starts the remote login shell.\n  - `--command` runs one remote command and returns its exit code locally.",
        help_header("Examples"),
        help_bold("Open an interactive shell on the remote end"),
        help_bold("Run one remote command and print its output locally"),
        help_header("Notes"),
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
        "{}:\n  {}:\n    tunnelworm self-update\n\n{}:\n  - This downloads the latest GitHub release for the current platform.\n  - It replaces the installed `tunnelworm` binary in place.",
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
        .mut_subcommand("open", |sub| sub.after_long_help(styled_open_after_help()))
        .mut_subcommand("self-update", |sub| {
            sub.after_long_help(styled_self_update_after_help())
        })
        .mut_subcommand("tunnel", |sub| {
            sub.after_long_help(styled_tunnel_after_help())
                .mut_subcommand("create", |sub| {
                    sub.after_long_help(styled_tunnel_create_after_help())
                })
                .mut_subcommand("up", |sub| {
                    sub.after_long_help(styled_tunnel_up_after_help())
                })
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
        .mut_subcommand("pipe", |sub| sub.after_long_help(styled_pipe_after_help()))
        .mut_subcommand("ports", |sub| {
            sub.after_long_help(StyledStr::from(PORTS_AFTER_HELP))
        })
        .mut_subcommand("send-file", |sub| {
            sub.after_long_help(styled_send_file_after_help())
        })
        .mut_subcommand("shell", |sub| {
            sub.after_long_help(styled_shell_after_help())
        })
}

pub fn tunnelworm_completion_command() -> Command {
    TunnelwormCompletionCli::command()
        .long_about(styled_top_level_long_about())
        .after_long_help(styled_top_level_after_help())
        .mut_subcommand("completion", |sub| {
            sub.after_long_help(styled_completion_after_help())
        })
        .mut_subcommand("open", |sub| sub.after_long_help(styled_open_after_help()))
        .mut_subcommand("self-update", |sub| {
            sub.after_long_help(styled_self_update_after_help())
        })
        .mut_subcommand("tunnel", |sub| {
            sub.after_long_help(styled_tunnel_after_help())
                .mut_subcommand("create", |sub| {
                    sub.after_long_help(styled_tunnel_create_after_help())
                })
                .mut_subcommand("up", |sub| {
                    sub.after_long_help(styled_tunnel_up_after_help())
                })
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
        .mut_subcommand("pipe", |sub| sub.after_long_help(styled_pipe_after_help()))
        .mut_subcommand("ports", |sub| {
            sub.after_long_help(StyledStr::from(PORTS_AFTER_HELP))
        })
        .mut_subcommand("send-file", |sub| {
            sub.after_long_help(styled_send_file_after_help())
        })
        .mut_subcommand("shell", |sub| {
            sub.after_long_help(styled_shell_after_help())
        })
}

pub fn parse_tunnelworm_cli() -> TunnelwormCli {
    try_parse_tunnelworm_cli_from(std::env::args_os()).unwrap_or_else(|error| error.exit())
}

pub fn try_parse_tunnelworm_cli_from<I, T>(
    args: I,
) -> std::result::Result<TunnelwormCli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = tunnelworm_command().try_get_matches_from(args)?;
    let mut cli = TunnelwormCli::from_arg_matches(&matches)?;
    populate_policy_rules(&mut cli, &matches);
    Ok(cli)
}

fn extract_policy_rules(matches: &clap::ArgMatches) -> Vec<TunnelPolicyRule> {
    let mut ordered = Vec::new();
    if let (Some(indices), Some(values)) = (
        matches.indices_of("allow"),
        matches.get_many::<TunnelCapability>("allow"),
    ) {
        for (index, capability) in indices.zip(values) {
            ordered.push((
                index,
                TunnelPolicyRule {
                    effect: TunnelPolicyEffect::Allow,
                    capability: *capability,
                },
            ));
        }
    }
    if let (Some(indices), Some(values)) = (
        matches.indices_of("deny"),
        matches.get_many::<TunnelCapability>("deny"),
    ) {
        for (index, capability) in indices.zip(values) {
            ordered.push((
                index,
                TunnelPolicyRule {
                    effect: TunnelPolicyEffect::Deny,
                    capability: *capability,
                },
            ));
        }
    }
    ordered.sort_by_key(|(index, _)| *index);
    ordered.into_iter().map(|(_, rule)| rule).collect()
}

fn populate_policy_rules(cli: &mut TunnelwormCli, matches: &clap::ArgMatches) {
    match cli.command.as_mut() {
        None => {
            cli.top_level.common.policy.ordered_rules = extract_policy_rules(matches);
        }
        Some(TunnelwormSubcommand::Open(args)) => {
            if let Some(("open", submatches)) = matches.subcommand() {
                args.policy.ordered_rules = extract_policy_rules(submatches);
            }
        }
        Some(TunnelwormSubcommand::Tunnel(tunnel)) => {
            if let Some(("tunnel", tunnel_matches)) = matches.subcommand()
                && let (TunnelCommand::Create(args), Some(("create", create_matches))) =
                    (&mut tunnel.command, tunnel_matches.subcommand())
            {
                args.common.policy.ordered_rules = extract_policy_rules(create_matches);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub tunnel_name: Option<String>,
    pub mailbox: Option<String>,
    pub code_length: usize,
    pub code: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub policy_rules: Vec<TunnelPolicyRule>,
    pub locals: Vec<LocalSpec>,
    pub remotes: Vec<RemoteSpec>,
    pub state: Option<PathBuf>,
    pub overwrite: bool,
}

#[derive(Debug, Clone)]
pub struct TunnelStatusConfig {
    pub name: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TunnelUpConfig {
    pub name: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TunnelDeleteConfig {
    pub name: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TunnelPipeConfig {
    pub name: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub state: Option<PathBuf>,
    pub mode: Option<crate::pipe::PipeMode>,
}

#[derive(Debug, Clone)]
pub struct TunnelShellConfig {
    pub name: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub state: Option<PathBuf>,
    pub command: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TunnelPortsListConfig {
    pub name: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TunnelPortsAddConfig {
    pub name: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub state: Option<PathBuf>,
    pub local_listen: Option<String>,
    pub local_connect: Option<String>,
    pub remote_listen: Option<String>,
    pub remote_connect: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TunnelPortsRemoveConfig {
    pub name: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub state: Option<PathBuf>,
    pub id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct TunnelSendFileConfig {
    pub name: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub source: Option<PathBuf>,
    pub destination: Option<PathBuf>,
    pub overwrite: bool,
}

#[derive(Debug, Clone)]
pub struct TunnelListConfig {
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum TunnelwormInvocation {
    Run(TunnelConfig),
    Open(TunnelConfig),
    Completion(Shell),
    InternalDaemon(InternalDaemonConfig),
    SelfUpdate,
    Pipe(TunnelPipeConfig),
    PortsList(TunnelPortsListConfig),
    PortsAdd(TunnelPortsAddConfig),
    PortsRemove(TunnelPortsRemoveConfig),
    SendFile(TunnelSendFileConfig),
    Shell(TunnelShellConfig),
    TunnelCreate(TunnelConfig),
    TunnelUp(TunnelUpConfig),
    TunnelList(TunnelListConfig),
    TunnelStatus(TunnelStatusConfig),
    TunnelDelete(TunnelDeleteConfig),
}

#[derive(Debug, Clone)]
pub struct InternalDaemonConfig {
    pub mailbox: Option<String>,
    pub code_length: usize,
    pub persistent_state: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardHalf {
    Listen,
    Connect,
    None,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum TunnelCapability {
    All,
    Ports,
    RemotePortMgmt,
    Shell,
    Pipe,
    SendFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelPolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelPolicyRule {
    pub effect: TunnelPolicyEffect,
    pub capability: TunnelCapability,
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

    pub fn code(&self, value: &str) -> String {
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
        help = "Accept local listeners with tunnelworm syntax or SSH syntax [bind_address:]port:host:hostport"
    )]
    pub local: Vec<String>,
    #[arg(
        long = "remote",
        short = 'R',
        value_name = "SPEC",
        help = "Offer remote listeners with tunnelworm syntax or SSH syntax [bind_address:]port:host:hostport"
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
pub struct PolicyArgs {
    #[arg(
        long = "allow",
        value_enum,
        value_name = "CAPABILITY",
        help = "Allow one remote capability on this machine"
    )]
    pub allow: Vec<TunnelCapability>,
    #[arg(
        long = "deny",
        value_enum,
        value_name = "CAPABILITY",
        help = "Deny one remote capability on this machine"
    )]
    pub deny: Vec<TunnelCapability>,
    #[arg(skip)]
    pub ordered_rules: Vec<TunnelPolicyRule>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct CommonSessionArgs {
    #[arg(long = "mailbox", help = "Override the mailbox websocket URL")]
    pub mailbox: Option<String>,
    #[arg(
        long = "code-length",
        default_value_t = 2,
        help = "Number of words to allocate when creating a new code"
    )]
    pub code_length: usize,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[command(flatten)]
    pub policy: PolicyArgs,
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
#[command(about = "Open a bare one-off tunnel with no initial port forward")]
#[command(after_long_help = OPEN_AFTER_HELP)]
pub struct TunnelOpenArgs {
    #[arg(long = "mailbox", help = "Override the mailbox websocket URL")]
    pub mailbox: Option<String>,
    #[arg(
        long = "code-length",
        default_value_t = 2,
        help = "Number of words to allocate when creating a new code"
    )]
    pub code_length: usize,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[command(flatten)]
    pub policy: PolicyArgs,
    #[arg(
        value_name = "CODE",
        help = "Existing wormhole code to join; omit it to allocate a new code"
    )]
    pub code: Option<String>,
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
    Create(Box<TunnelCreateArgs>),
    #[command(about = "Start one saved side of a persistent tunnel")]
    Up(TunnelUpArgs),
    #[command(about = "List saved persistent tunnel endpoints", alias = "ls")]
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
    #[arg(
        value_name = "NAME",
        help = "Local name for this saved tunnel endpoint"
    )]
    pub name: String,
    #[command(flatten)]
    pub common: CommonSessionArgs,
    #[arg(
        long = "code",
        value_name = "CODE",
        help = "Join an existing bootstrap code instead of allocating a new one"
    )]
    pub code: Option<String>,
    #[arg(
        long = "overwrite",
        help = "Replace an existing saved tunnel endpoint with the same local name"
    )]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Start one saved side of a persistent tunnel")]
#[command(after_long_help = TUNNEL_UP_AFTER_HELP)]
pub struct TunnelUpArgs {
    #[arg(
        value_name = "NAME",
        required_unless_present = "state",
        help = "Local name of the saved tunnel endpoint to start"
    )]
    pub name: Option<String>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long = "state",
        value_name = "PATH",
        required_unless_present = "name",
        help = "Use an explicit persistent state file path"
    )]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Inspect the stored state for one local tunnel participant")]
#[command(after_long_help = TUNNEL_STATUS_AFTER_HELP)]
pub struct TunnelStatusArgs {
    #[arg(
        value_name = "NAME",
        required_unless_present = "state",
        help = "Local name of the saved tunnel endpoint to inspect"
    )]
    pub name: Option<String>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long = "state",
        value_name = "PATH",
        required_unless_present = "name",
        help = "Inspect an explicit persistent state file path"
    )]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
#[command(about = "List saved persistent tunnel endpoints")]
#[command(after_long_help = TUNNEL_LIST_AFTER_HELP)]
pub struct TunnelListArgs {
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Delete one saved persistent tunnel endpoint")]
#[command(after_long_help = TUNNEL_DELETE_AFTER_HELP)]
pub struct TunnelDeleteArgs {
    #[arg(
        value_name = "NAME",
        required_unless_present = "state",
        help = "Local name of the saved tunnel endpoint to delete"
    )]
    pub name: Option<String>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long = "state",
        value_name = "PATH",
        required_unless_present = "name",
        help = "Delete an explicit persistent state file path"
    )]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Stream stdin/stdout over one live named tunnel")]
#[command(after_long_help = PIPE_AFTER_HELP)]
pub struct TunnelPipeArgs {
    #[arg(
        value_name = "NAME",
        help = "Local name of the saved tunnel endpoint to use"
    )]
    pub name: Option<String>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long = "state",
        value_name = "PATH",
        help = "Use an explicit persistent state file path"
    )]
    pub state: Option<PathBuf>,
    #[arg(
        long = "send",
        conflicts_with = "receive",
        help = "Treat this local pipe endpoint as the sending side"
    )]
    pub send: bool,
    #[arg(
        long = "receive",
        conflicts_with = "send",
        help = "Treat this local pipe endpoint as the receiving side"
    )]
    pub receive: bool,
}

#[derive(Debug, Clone, Args)]
pub struct TunnelPortsListArgs {
    #[arg(
        value_name = "NAME",
        help = "Local name of the saved tunnel endpoint to use"
    )]
    pub name: Option<String>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long = "state",
        value_name = "PATH",
        help = "Use an explicit persistent state file path"
    )]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct TunnelPortsAddArgs {
    #[arg(
        value_name = "NAME",
        help = "Local name of the saved tunnel endpoint to use"
    )]
    pub name: Option<String>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long = "state",
        value_name = "PATH",
        help = "Use an explicit persistent state file path"
    )]
    pub state: Option<PathBuf>,
    #[arg(
        long = "local-listen",
        value_name = "ADDR",
        help = "Listen locally on port or host:port"
    )]
    pub local_listen: Option<String>,
    #[arg(
        long = "local-connect",
        value_name = "ADDR",
        help = "Connect locally to port or host:port"
    )]
    pub local_connect: Option<String>,
    #[arg(
        long = "remote-listen",
        value_name = "ADDR",
        help = "Ask the remote side to listen on port or host:port"
    )]
    pub remote_listen: Option<String>,
    #[arg(
        long = "remote-connect",
        value_name = "ADDR",
        help = "Ask the remote side to connect to port or host:port"
    )]
    pub remote_connect: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct TunnelPortsRemoveArgs {
    #[arg(
        value_name = "NAME",
        help = "Local name of the saved tunnel endpoint to use"
    )]
    pub name: Option<String>,
    #[arg(value_name = "ID", help = "Numeric port-forward ID to remove")]
    pub id: Option<u32>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long = "state",
        value_name = "PATH",
        help = "Use an explicit persistent state file path"
    )]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum TunnelPortsSubcommand {
    #[command(
        about = "List the current live port forwards on one tunnel",
        alias = "ls"
    )]
    List(TunnelPortsListArgs),
    #[command(about = "Add one live port forward to one tunnel")]
    Add(TunnelPortsAddArgs),
    #[command(about = "Remove one live port forward from one tunnel")]
    Remove(TunnelPortsRemoveArgs),
}

#[derive(Debug, Clone, Args)]
#[command(about = "List or manage live port forwards on one tunnel")]
#[command(after_long_help = PORTS_AFTER_HELP)]
pub struct TunnelPortsArgs {
    #[command(subcommand)]
    pub command: Option<TunnelPortsSubcommand>,
    #[arg(
        value_name = "NAME",
        help = "Local name of the saved tunnel endpoint to use"
    )]
    pub name: Option<String>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long = "state",
        value_name = "PATH",
        help = "Use an explicit persistent state file path"
    )]
    pub state: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
#[command(about = "Send one file over one live named tunnel")]
#[command(after_long_help = SEND_FILE_AFTER_HELP)]
pub struct TunnelSendFileArgs {
    #[arg(
        value_name = "NAME",
        help = "Local name of the saved tunnel endpoint to use"
    )]
    pub name: Option<String>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(value_name = "SOURCE", help = "Local file to send to the peer")]
    pub source: Option<PathBuf>,
    #[arg(
        value_name = "REMOTE_DEST",
        help = "Optional destination path to write on the peer"
    )]
    pub destination: Option<PathBuf>,
    #[arg(
        long = "overwrite",
        help = "Replace an existing destination file on the peer"
    )]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Args)]
#[command(
    about = "Open the remote login shell, or run one remote command, over one live named tunnel"
)]
#[command(after_long_help = SHELL_AFTER_HELP)]
pub struct TunnelShellArgs {
    #[arg(
        value_name = "NAME",
        help = "Local name of the saved tunnel endpoint to use"
    )]
    pub name: Option<String>,
    #[arg(
        long = "state-dir",
        value_name = "PATH",
        help = "Override the default tunnel state directory"
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long = "state",
        value_name = "PATH",
        help = "Use an explicit persistent state file path"
    )]
    pub state: Option<PathBuf>,
    #[arg(
        long = "command",
        short = 'c',
        value_name = "COMMAND",
        help = "Run one remote command instead of starting the remote login shell"
    )]
    pub command: Option<String>,
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
    pub command: Option<TunnelwormSubcommand>,
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
    pub command: Option<TunnelwormSubcommand>,
    #[command(flatten)]
    pub top_level: CompletionTopLevelArgs,
}

#[derive(Debug, Clone, Subcommand)]
pub enum TunnelwormSubcommand {
    Completion(CompletionArgs),
    #[command(hide = true, name = "internal-daemon")]
    InternalDaemon(InternalDaemonArgs),
    Open(TunnelOpenArgs),
    SelfUpdate(SelfUpdateArgs),
    Pipe(TunnelPipeArgs),
    Ports(TunnelPortsArgs),
    #[command(alias = "send")]
    SendFile(TunnelSendFileArgs),
    Shell(TunnelShellArgs),
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

#[derive(Debug, Clone, Args)]
#[command(hide = true)]
pub struct InternalDaemonArgs {
    #[arg(long = "mailbox")]
    pub mailbox: Option<String>,
    #[arg(long = "code-length", default_value_t = 2)]
    pub code_length: usize,
    #[arg(long = "persistent-state")]
    pub persistent_state: Option<PathBuf>,
}

impl TryFrom<TunnelwormCli> for TunnelwormInvocation {
    type Error = Error;

    fn try_from(value: TunnelwormCli) -> Result<Self> {
        match value.command {
            Some(TunnelwormSubcommand::Completion(args)) => Ok(Self::Completion(args.shell)),
            Some(TunnelwormSubcommand::InternalDaemon(args)) => {
                Ok(Self::InternalDaemon(InternalDaemonConfig {
                    mailbox: args.mailbox,
                    code_length: args.code_length,
                    persistent_state: args.persistent_state,
                }))
            }
            Some(TunnelwormSubcommand::Open(args)) => Ok(Self::Open(TunnelConfig {
                tunnel_name: None,
                mailbox: args.mailbox,
                code_length: args.code_length,
                code: args.code,
                state_dir: args.state_dir,
                policy_rules: args.policy.ordered_rules,
                locals: Vec::new(),
                remotes: Vec::new(),
                state: None,
                overwrite: false,
            })),
            Some(TunnelwormSubcommand::SelfUpdate(_)) => Ok(Self::SelfUpdate),
            Some(TunnelwormSubcommand::Pipe(args)) => Ok(Self::Pipe(TunnelPipeConfig {
                name: args.name,
                state_dir: args.state_dir,
                state: args.state,
                mode: if args.send {
                    Some(crate::pipe::PipeMode::Send)
                } else if args.receive {
                    Some(crate::pipe::PipeMode::Receive)
                } else {
                    None
                },
            })),
            Some(TunnelwormSubcommand::Ports(args)) => match args.command {
                None => Ok(Self::PortsList(TunnelPortsListConfig {
                    name: args.name,
                    state_dir: args.state_dir,
                    state: args.state,
                })),
                Some(TunnelPortsSubcommand::List(list)) => {
                    Ok(Self::PortsList(TunnelPortsListConfig {
                        name: list.name,
                        state_dir: list.state_dir,
                        state: list.state,
                    }))
                }
                Some(TunnelPortsSubcommand::Add(add)) => Ok(Self::PortsAdd(TunnelPortsAddConfig {
                    name: add.name,
                    state_dir: add.state_dir,
                    state: add.state,
                    local_listen: add.local_listen,
                    local_connect: add.local_connect,
                    remote_listen: add.remote_listen,
                    remote_connect: add.remote_connect,
                })),
                Some(TunnelPortsSubcommand::Remove(remove)) => {
                    Ok(Self::PortsRemove(TunnelPortsRemoveConfig {
                        name: remove.name,
                        state_dir: remove.state_dir,
                        state: remove.state,
                        id: remove.id,
                    }))
                }
            },
            Some(TunnelwormSubcommand::SendFile(args)) => {
                Ok(Self::SendFile(TunnelSendFileConfig {
                    name: args.name,
                    state_dir: args.state_dir,
                    source: args.source,
                    destination: args.destination,
                    overwrite: args.overwrite,
                }))
            }
            Some(TunnelwormSubcommand::Shell(args)) => Ok(Self::Shell(TunnelShellConfig {
                name: args.name,
                state_dir: args.state_dir,
                state: args.state,
                command: args.command,
            })),
            Some(TunnelwormSubcommand::Tunnel(tunnel)) => match tunnel.command {
                TunnelCommand::Create(args) => {
                    let args = *args;
                    Ok(Self::TunnelCreate(build_config(
                        args.common,
                        args.code,
                        None,
                        args.overwrite,
                        true,
                        Some(args.name),
                    )?))
                }
                TunnelCommand::Up(args) => Ok(Self::TunnelUp(TunnelUpConfig {
                    name: args.name,
                    state_dir: args.state_dir,
                    state: args.state,
                })),
                TunnelCommand::List(args) => Ok(Self::TunnelList(TunnelListConfig {
                    state_dir: args.state_dir,
                })),
                TunnelCommand::Status(args) => Ok(Self::TunnelStatus(TunnelStatusConfig {
                    name: args.name,
                    state_dir: args.state_dir,
                    state: args.state,
                })),
                TunnelCommand::Delete(args) => Ok(Self::TunnelDelete(TunnelDeleteConfig {
                    name: args.name,
                    state_dir: args.state_dir,
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
) -> Result<TunnelConfig> {
    let (locals, remotes) = parse_forward_args(common.forwards, allow_empty_forwards)?;

    if common.code_length == 0 {
        return Err(Error::Usage("code length must be at least 1".into()));
    }

    Ok(TunnelConfig {
        tunnel_name,
        mailbox: common.mailbox,
        code_length: common.code_length,
        code,
        state_dir: common.state_dir,
        policy_rules: common.policy.ordered_rules,
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

impl TunnelConfig {
    pub fn persistent_config(&self) -> Result<PersistentConfig> {
        PersistentConfig::from_tunnel_config(self)
    }

    pub fn local_half(&self) -> ForwardHalf {
        match (!self.locals.is_empty(), !self.remotes.is_empty()) {
            (true, false) => ForwardHalf::Listen,
            (false, true) => ForwardHalf::Connect,
            (false, false) => ForwardHalf::None,
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
            }
            ForwardHalf::Connect => {
                let spec = self
                    .remotes
                    .first()
                    .expect("connect half needs a remote spec");
                format!(
                    "connect to {}:{}",
                    spec.connect_address.as_deref().unwrap_or("127.0.0.1"),
                    spec.local_connect_port
                        .map(|port| port.to_string())
                        .unwrap_or_else(|| "PORT".into())
                )
            }
            ForwardHalf::None => "no ports configured yet".into(),
            ForwardHalf::Mixed => "multiple forward halves".into(),
        }
    }

    pub fn peer_preferred_command(&self, code: &str, persistent: bool) -> Option<String> {
        let prefix = if persistent {
            "tunnelworm tunnel up"
        } else {
            "tunnelworm"
        };
        match self.local_half() {
            ForwardHalf::Listen => Some(format!("{prefix} --connect HOST:PORT {code}")),
            ForwardHalf::Connect => {
                Some(format!("{prefix} --listen LISTEN_HOST:LISTEN_PORT {code}"))
            }
            ForwardHalf::None => {
                if persistent {
                    Some(format!("tunnelworm tunnel create PEER_NAME --code {code}"))
                } else {
                    Some(format!("tunnelworm open {code}"))
                }
            }
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
            ForwardHalf::None | ForwardHalf::Mixed => None,
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
            }
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
            }
            ForwardHalf::None => {
                let base = format!("tunnelworm tunnel create {}", tunnel_name);
                if self.code.is_some() {
                    Some(format!("{base} --code {code} --overwrite"))
                } else {
                    Some(format!("{base} --overwrite"))
                }
            }
            ForwardHalf::Mixed => None,
        }
    }
}
