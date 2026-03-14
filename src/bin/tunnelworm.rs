use clap_complete::generate;
use std::env;
use std::ffi::OsString;
use std::io::{self, ErrorKind, Write};

use tunnelworm::{
    cli::{
        TunnelwormInvocation, stderr_style, try_parse_tunnelworm_cli_from, tunnelworm_command,
        tunnelworm_completion_command,
    },
    persistent,
};

#[async_std::main]
async fn main() {
    let raw_args: Vec<OsString> = env::args_os().collect();

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
            break;
        };
        command = next.clone();
    }
    command
}
