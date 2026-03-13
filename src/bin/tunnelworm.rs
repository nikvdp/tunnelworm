use clap::CommandFactory;
use clap_complete::generate;
use std::io::{self, ErrorKind, Write};

use tunnelworm::{
    cli::{
        parse_tunnelworm_cli, stderr_style, tunnelworm_completion_command, TunnelwormInvocation,
    },
    persistent,
};

#[async_std::main]
async fn main() {
    let args = parse_tunnelworm_cli();
    let invocation = match TunnelwormInvocation::try_from(args) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("{} {error}", stderr_style().error("Error:"));
            std::process::exit(2);
        },
    };

    let result = match invocation {
        TunnelwormInvocation::Run(config) => tunnelworm::session::run_fowl(config).await,
        TunnelwormInvocation::Completion(shell) => {
            let mut command = tunnelworm_completion_command();
            let name = command.get_name().to_string();
            let mut output = Vec::new();
            generate(shell, &mut command, name, &mut output);
            let mut output = String::from_utf8(output).expect("completion output must be valid utf-8");
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
        },
        TunnelwormInvocation::TunnelCreate(config) => persistent::create_named_tunnel(&config).await,
        TunnelwormInvocation::TunnelUp(config) => persistent::up_named_tunnel(&config),
        TunnelwormInvocation::TunnelList => persistent::list_named_tunnels(),
        TunnelwormInvocation::TunnelStatus(config) => persistent::print_status(&config),
        TunnelwormInvocation::TunnelDelete(config) => persistent::delete_named_tunnel(&config),
    };

    if let Err(error) = result {
        eprintln!("{} {error}", stderr_style().error("Error:"));
        std::process::exit(1);
    }
}
