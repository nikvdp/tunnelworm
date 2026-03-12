use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "fowl")]
#[command(about = "Forward Over Wormhole, Locally")]
struct Args {
    #[arg(long = "mailbox")]
    mailbox: Option<String>,
    #[arg(long = "code-length", default_value_t = 2)]
    code_length: usize,
    #[arg(long = "local", short = 'L')]
    local: Vec<String>,
    #[arg(long = "remote", short = 'R')]
    remote: Vec<String>,
    code: Option<String>,
}

#[async_std::main]
async fn main() {
    let _ = Args::parse();
    if let Err(error) = fowl_rs::session::run_fowl().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
