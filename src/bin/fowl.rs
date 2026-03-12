use clap::Parser;

use fowl_rs::cli::{FowlCli, FowlConfig};
use fowl_rs::persistent;

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

    let result = if config.persistent {
        persistent::initialize_or_exec(&config).await
    } else {
        fowl_rs::session::run_fowl(config).await
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
