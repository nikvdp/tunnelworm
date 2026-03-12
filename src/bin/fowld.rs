use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "fowld")]
#[command(about = "Forward Over Wormhole, Locally, Daemon")]
struct Args {
    #[arg(long = "mailbox")]
    mailbox: Option<String>,
    #[arg(long = "code-length", default_value_t = 2)]
    code_length: usize,
}

#[async_std::main]
async fn main() {
    let _ = Args::parse();
    if let Err(error) = fowl_rs::session::run_fowld().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
