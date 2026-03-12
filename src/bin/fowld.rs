use clap::Parser;

use fowl_rs::daemon::runtime::DaemonConfig;

const FOWLD_LONG_ABOUT: &str = "\
Run the port forwarder as a JSON-line daemon over stdin and stdout.

Send one JSON command per line on stdin. The daemon emits JSON events on stdout.
Queue `local` or `remote` rules first, then start the session with either
`allocate-code` or `set-code`.";

const FOWLD_AFTER_HELP: &str = "\
Examples:
  Terminal 1: allocate a code and ask the peer to expose its local web server on
  port 7000:
    fowld
    {\"kind\":\"remote\",\"listen\":\"tcp:7000:interface=127.0.0.1\",\"connect\":\"tcp:127.0.0.1:9000\"}
    {\"kind\":\"allocate-code\"}

  Terminal 2: join with the printed code and allow the matching forward:
    fowld
    {\"kind\":\"local\",\"listen\":\"tcp:7000\",\"connect\":\"tcp:127.0.0.1:9000\"}
    {\"kind\":\"set-code\",\"code\":\"7-cobalt-signal\"}

  Close the active session:
    {\"kind\":\"session-close\"}

Events you should expect:
  - {\"kind\":\"welcome\",...}
  - {\"kind\":\"code-allocated\",\"code\":\"...\"}
  - {\"kind\":\"peer-connected\",...}
  - {\"kind\":\"listening\",\"listen\":\"tcp:7000:interface=127.0.0.1\",\"connect\":\"tcp:127.0.0.1:9000\"}
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
