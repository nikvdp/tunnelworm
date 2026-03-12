use clap::Parser;

use fowl_rs::{
    cli::{FowlCli, FowlInvocation},
    persistent,
};

#[async_std::main]
async fn main() {
    let args = FowlCli::parse();
    let invocation = match FowlInvocation::try_from(args) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        },
    };

    let result = match invocation {
        FowlInvocation::Run(config) => {
            if config.persistent {
                persistent::initialize_or_exec(&config).await
            } else {
                fowl_rs::session::run_fowl(config).await
            }
        },
        FowlInvocation::TunnelUp(config) => persistent::initialize_or_exec(&config).await,
        FowlInvocation::TunnelStatus(config) => persistent::print_status(&config),
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
