use clap::Parser;

use fowl_rs::{
    cli::{stderr_style, FowlCli, FowlInvocation},
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
