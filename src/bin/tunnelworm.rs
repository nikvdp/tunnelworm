use clap_complete::generate;
use std::env;
use std::ffi::OsString;
use std::io::{self, ErrorKind, Write};

use tunnelworm::{
    cli::{
        TunnelwormInvocation, stderr_style, try_parse_tunnelworm_cli_from, tunnelworm_command,
        tunnelworm_completion_command,
    },
    daemon::runtime::DaemonConfig,
    persistent,
};

#[async_std::main]
async fn main() {
    let raw_args: Vec<OsString> = env::args_os().collect();
    if let Some((typed, suggested, help_command)) =
        probable_top_level_subcommand_typo(&raw_args[1..])
    {
        eprintln!("error: unrecognized subcommand '{typed}'");
        eprintln!();
        eprintln!("  tip: a similar subcommand exists: '{suggested}'");
        eprintln!();
        let mut command = help_command;
        command
            .write_long_help(&mut io::stderr())
            .expect("help text should render");
        eprintln!();
        std::process::exit(2);
    }

    let args = match try_parse_tunnelworm_cli_from(raw_args.clone()) {
        Ok(args) => args,
        Err(error) => exit_with_clap_error_and_help(error, &raw_args[1..]),
    };
    let invocation = match TunnelwormInvocation::try_from(args) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("{} {error}", stderr_style().error("Error:"));
            print_matching_help(&raw_args[1..]);
            std::process::exit(2);
        }
    };
    let mut shell_exit_code: Option<u32> = None;

    let result = match invocation {
        TunnelwormInvocation::Run(config) => persistent::create_one_off_tunnel(&config).await,
        TunnelwormInvocation::Open(config) => persistent::create_one_off_tunnel(&config).await,
        TunnelwormInvocation::Completion(shell) => {
            let mut command = tunnelworm_completion_command();
            let name = command.get_name().to_string();
            let mut output = Vec::new();
            generate(shell, &mut command, name, &mut output);
            let mut output =
                String::from_utf8(output).expect("completion output must be valid utf-8");
            if matches!(shell, clap_complete::Shell::Zsh) {
                output = output.replace(
                    "compdef _tunnelworm tunnelworm",
                    "compdef _tunnelworm tunnelworm -p '*/tunnelworm'",
                );
            }
            if let Err(error) = io::stdout().write_all(output.as_bytes()) {
                if error.kind() == ErrorKind::BrokenPipe {
                    Ok(())
                } else {
                    Err(error.into())
                }
            } else {
                Ok(())
            }
        }
        TunnelwormInvocation::InternalDaemon(args) => {
            let config = DaemonConfig {
                mailbox: args.mailbox,
                code_length: args.code_length,
            };
            match args.persistent_state {
                Some(path) => tunnelworm::daemon::runtime::run_persistent(path).await,
                None => tunnelworm::daemon::runtime::run(config).await,
            }
        }
        TunnelwormInvocation::SelfUpdate => tunnelworm::self_update::run_self_update(),
        TunnelwormInvocation::Pipe(config) => persistent::run_named_pipe(&config).await,
        TunnelwormInvocation::PortsList(config) => persistent::list_tunnel_ports(&config),
        TunnelwormInvocation::PortsAdd(config) => persistent::add_tunnel_port(&config).await,
        TunnelwormInvocation::PortsRemove(config) => persistent::remove_tunnel_port(&config).await,
        TunnelwormInvocation::SendFile(config) => persistent::run_named_send_file(&config).await,
        TunnelwormInvocation::Shell(config) => match persistent::run_named_shell(&config).await {
            Ok(code) => {
                shell_exit_code = Some(code);
                Ok(())
            }
            Err(error) => Err(error),
        },
        TunnelwormInvocation::TunnelCreate(config) => {
            persistent::create_named_tunnel(&config).await
        }
        TunnelwormInvocation::TunnelUp(config) => persistent::up_named_tunnel(&config),
        TunnelwormInvocation::TunnelList => persistent::list_named_tunnels(),
        TunnelwormInvocation::TunnelStatus(config) => persistent::print_status(&config),
        TunnelwormInvocation::TunnelDelete(config) => persistent::delete_named_tunnel(&config),
    };

    if let Err(error) = result {
        eprintln!("{} {error}", stderr_style().error("Error:"));
        if matches!(error, tunnelworm::error::Error::Usage(_)) {
            print_matching_help(&raw_args[1..]);
        }
        std::process::exit(1);
    }
    if let Some(code) = shell_exit_code {
        std::process::exit(code as i32);
    }
}

fn exit_with_clap_error_and_help(error: clap::Error, args: &[OsString]) -> ! {
    let kind = error.kind();
    error.print().expect("clap errors should print");
    if matches!(
        kind,
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
    ) {
        std::process::exit(0);
    }
    eprintln!();
    print_matching_help(args);
    std::process::exit(2);
}

fn print_matching_help(args: &[OsString]) {
    let mut command = matching_help_command(args);
    command
        .write_long_help(&mut io::stderr())
        .expect("help text should render");
    eprintln!();
}

fn matching_help_command(args: &[OsString]) -> clap::Command {
    let mut command = tunnelworm_command();
    for arg in args {
        let Some(token) = arg.to_str() else {
            break;
        };
        if token.starts_with('-') {
            continue;
        }
        let Some(next) = command.get_subcommands().find(|sub| {
            sub.get_name() == token || sub.get_all_aliases().any(|alias| alias == token)
        }) else {
            if let Some((_, suggested)) = best_matching_subcommand(&command, token) {
                command = suggested.clone();
            }
            break;
        };
        command = next.clone();
    }
    command
}

fn best_matching_subcommand(
    command: &clap::Command,
    token: &str,
) -> Option<(String, clap::Command)> {
    let mut best: Option<(usize, clap::Command)> = None;
    let mut best_name: Option<String> = None;
    for subcommand in command.get_subcommands() {
        if subcommand.is_hide_set() {
            continue;
        }
        let mut consider = |candidate: &str| {
            let distance = edit_distance(token, candidate);
            if distance > 2 && !candidate.starts_with(token) && !token.starts_with(candidate) {
                return;
            }
            match &best {
                Some((best_distance, _)) if distance >= *best_distance => {}
                _ => {
                    best = Some((distance, subcommand.clone()));
                    best_name = Some(subcommand.get_name().to_string());
                }
            }
        };

        consider(subcommand.get_name());
        for alias in subcommand.get_all_aliases() {
            consider(alias);
        }
    }

    match (best, best_name) {
        (Some((_, command)), Some(name)) => Some((name, command)),
        _ => None,
    }
}

fn edit_distance(left: &str, right: &str) -> usize {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];

    for (left_index, left_char) in left.iter().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_char) in right.iter().enumerate() {
            let substitution_cost = usize::from(left_char != right_char);
            current[right_index + 1] = (previous[right_index + 1] + 1)
                .min(current[right_index] + 1)
                .min(previous[right_index] + substitution_cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[right.len()]
}

fn probable_top_level_subcommand_typo(
    args: &[OsString],
) -> Option<(String, String, clap::Command)> {
    let token = args.first()?.to_str()?;
    if token.starts_with('-') || looks_like_wormhole_code(token) {
        return None;
    }

    let command = tunnelworm_command();
    if command
        .get_subcommands()
        .any(|sub| {
            !sub.is_hide_set()
                && (sub.get_name() == token || sub.get_all_aliases().any(|alias| alias == token))
        })
    {
        return None;
    }

    let (suggested, help_command) = best_matching_subcommand(&command, token)?;
    Some((token.to_string(), suggested, help_command))
}

fn looks_like_wormhole_code(token: &str) -> bool {
    let mut parts = token.split('-');
    matches!(parts.next(), Some(first) if first.chars().all(|ch| ch.is_ascii_digit()))
        && parts.next().is_some()
}
