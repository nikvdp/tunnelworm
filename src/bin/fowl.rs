use clap::Parser;

use fowl_rs::cli::{FowlCli, FowlConfig};

#[async_std::main]
async fn main() {
    let args = FowlCli::parse();
    let config = match FowlConfig::try_from(args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        },
    };

    if let Err(error) = fowl_rs::session::run_fowl(config).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
