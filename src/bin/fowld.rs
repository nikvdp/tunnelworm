use clap::Parser;

use fowl_rs::daemon::runtime::DaemonConfig;

#[derive(Debug, Parser)]
#[command(name = "fowld")]
#[command(about = "Forward Over Wormhole, Locally, Daemon")]
#[command(version)]
struct Args {
    #[arg(long = "mailbox")]
    mailbox: Option<String>,
    #[arg(long = "code-length", default_value_t = 2)]
    code_length: usize,
}

#[async_std::main]
async fn main() {
    let args = Args::parse();
    let config = DaemonConfig {
        mailbox: args.mailbox,
        code_length: args.code_length,
    };
    if let Err(error) = fowl_rs::daemon::runtime::run(config).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
