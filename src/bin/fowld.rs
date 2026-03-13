use clap::Parser;
use std::path::PathBuf;

use fowl_rs::daemon::runtime::DaemonConfig;

const FOWLD_LONG_ABOUT: &str = "\
Run the port forwarder as a JSON-line daemon over stdin and stdout.

Send one JSON command per line on stdin. The daemon emits JSON events on stdout.
Queue `local` or `remote` rules first, then start the session with either
`allocate-code` or `set-code`.";

const FOWLD_AFTER_HELP: &str = "\
Examples:
  Expose the peer's local service on port 22 through a listener on port 9097:
    fowld
    {\"kind\":\"remote\",\"listen\":\"tcp:9097:interface=127.0.0.1\",\"connect\":\"tcp:127.0.0.1:22\"}
    {\"kind\":\"allocate-code\"}

  On the peer, join with the printed code and allow the matching forward:
    fowld
    {\"kind\":\"local\",\"listen\":\"tcp:9097\",\"connect\":\"tcp:127.0.0.1:22\"}
    {\"kind\":\"set-code\",\"code\":\"7-cobalt-signal\"}

Events you should expect:
  - {\"kind\":\"welcome\",...}
  - {\"kind\":\"code-allocated\",\"code\":\"...\"}
  - {\"kind\":\"peer-connected\",...}
  - {\"kind\":\"listening\",\"listen\":\"tcp:9097:interface=127.0.0.1\",\"connect\":\"tcp:127.0.0.1:22\"}
  - {\"kind\":\"closed\"}

Notes:
  - `listen` accepts `tcp:PORT[:interface=HOST]`.
  - `connect` accepts `tcp:HOST:PORT`.
  - One forwarding direction per daemon session is supported today.";

#[derive(Debug, Parser)]
#[command(name = "fowld")]
#[command(about = "Run fowl as a JSON-line daemon on stdin and stdout")]
#[command(long_about = FOWLD_LONG_ABOUT)]
#[command(after_long_help = FOWLD_AFTER_HELP)]
#[command(version)]
struct Args {
    #[arg(long = "mailbox", help = "Override the mailbox websocket URL")]
    mailbox: Option<String>,
    #[arg(long = "code-length", default_value_t = 2, help = "Default word count when `allocate-code` omits `code_length`")]
    code_length: usize,
    #[arg(long = "persistent-state", hide = true)]
    persistent_state: Option<PathBuf>,
}

#[async_std::main]
async fn main() {
    let args = Args::parse();
    let config = DaemonConfig {
        mailbox: args.mailbox,
        code_length: args.code_length,
    };
    let result = match args.persistent_state {
        Some(path) => fowl_rs::daemon::runtime::run_persistent(path).await,
        None => fowl_rs::daemon::runtime::run(config).await,
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
