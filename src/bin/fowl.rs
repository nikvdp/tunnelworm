use clap::{CommandFactory, Parser};
use clap_complete::generate;
use std::io::{self, ErrorKind, Write};

use fowl_rs::{
    cli::{stderr_style, FowlCli, FowlCompletionCli, FowlInvocation},
    persistent,
};

#[async_std::main]
async fn main() {
    let args = FowlCli::parse();
    let invocation = match FowlInvocation::try_from(args) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("{} {error}", stderr_style().error("Error:"));
            std::process::exit(2);
        },
    };

    let result = match invocation {
        FowlInvocation::Run(config) => fowl_rs::session::run_fowl(config).await,
        FowlInvocation::Completion(shell) => {
            let mut command = FowlCompletionCli::command();
            let name = command.get_name().to_string();
            let mut output = Vec::new();
            generate(shell, &mut command, name, &mut output);
            let mut output = String::from_utf8(output).expect("completion output must be valid utf-8");
            if matches!(shell, clap_complete::Shell::Zsh) {
                output = output.replace("compdef _fowl fowl", "compdef _fowl fowl -p '*/fowl'");
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
        FowlInvocation::TunnelCreate(config) => persistent::create_named_tunnel(&config).await,
        FowlInvocation::TunnelUp(config) => persistent::up_named_tunnel(&config),
        FowlInvocation::TunnelList => persistent::list_named_tunnels(),
        FowlInvocation::TunnelStatus(config) => persistent::print_status(&config),
        FowlInvocation::TunnelDelete(config) => persistent::delete_named_tunnel(&config),
    };

    if let Err(error) = result {
        eprintln!("{} {error}", stderr_style().error("Error:"));
        std::process::exit(1);
    }
}
