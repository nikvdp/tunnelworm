use clap::{CommandFactory, FromArgMatches, Parser};
use std::path::PathBuf;

use tunnelworm::daemon::runtime::DaemonConfig;

const TUNNELWORMD_LONG_ABOUT: &str = "\
Run the port forwarder as a JSON-line daemon over stdin and stdout.

Send one JSON command per line on stdin. The daemon emits JSON events on stdout.
Queue `local` or `remote` rules first, then start the session with either
`allocate-code` or `set-code`.";

const TUNNELWORMD_AFTER_HELP: &str = "\
Examples:
  Expose the peer's local service on port 22 through a listener on port 9097:
    tunnelwormd
    {\"kind\":\"remote\",\"listen\":\"tcp:9097:interface=127.0.0.1\",\"connect\":\"tcp:127.0.0.1:22\"}
    {\"kind\":\"allocate-code\"}

  On the peer, join with the printed code and allow the matching forward:
    tunnelwormd
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

fn parse_args() -> Args {
    let style = tunnelworm::cli::stdout_style();
    let header = |value: &str| {
        if std::io::stdout().is_terminal() {
            format!("\x1b[1;4m{value}\x1b[0m")
        } else {
            value.to_string()
        }
    };
    let long_about = format!(
        "{}\n\n{}:\n  Send one JSON command per line on stdin.\n  Read one JSON event per line on stdout.\n\n{}:\n  Queue `local` or `remote` rules first.\n  Start the session with `allocate-code` or `set-code`.",
        style.label("Run the port forwarder as a JSON-line daemon over stdin and stdout."),
        header("How it works"),
        header("Session flow"),
    );
    let after_help = format!(
        "{}:\n  {}:\n    tunnelwormd\n    {{\"kind\":\"remote\",\"listen\":\"tcp:9097:interface=127.0.0.1\",\"connect\":\"tcp:127.0.0.1:22\"}}\n    {{\"kind\":\"allocate-code\"}}\n\n  {}:\n    tunnelwormd\n    {{\"kind\":\"local\",\"listen\":\"tcp:9097\",\"connect\":\"tcp:127.0.0.1:22\"}}\n    {{\"kind\":\"set-code\",\"code\":\"7-cobalt-signal\"}}\n\n{}:\n  - {{\"kind\":\"welcome\",...}}\n  - {{\"kind\":\"code-allocated\",\"code\":\"...\"}}\n  - {{\"kind\":\"peer-connected\",...}}\n  - {{\"kind\":\"listening\",\"listen\":\"tcp:9097:interface=127.0.0.1\",\"connect\":\"tcp:127.0.0.1:22\"}}\n  - {{\"kind\":\"closed\"}}\n\n{}:\n  - `listen` accepts `tcp:PORT[:interface=HOST]`.\n  - `connect` accepts `tcp:HOST:PORT`.\n  - One forwarding direction per daemon session is supported today.",
        header("Examples"),
        style.label("Create the side that exposes the peer's port 22 on local port 9097"),
        style.label("On the peer, join with the printed code and allow the matching forward"),
        header("Events you should expect"),
        header("Notes"),
    );
    let matches = Args::command()
        .long_about(long_about)
        .after_long_help(after_help)
        .get_matches();
    Args::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

#[derive(Debug, Parser)]
#[command(name = "tunnelwormd")]
#[command(about = "Run tunnelworm as a JSON-line daemon on stdin and stdout")]
#[command(long_about = TUNNELWORMD_LONG_ABOUT)]
#[command(after_long_help = TUNNELWORMD_AFTER_HELP)]
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
    let args = parse_args();
    let config = DaemonConfig {
        mailbox: args.mailbox,
        code_length: args.code_length,
    };
    let result = match args.persistent_state {
        Some(path) => tunnelworm::daemon::runtime::run_persistent(path).await,
        None => tunnelworm::daemon::runtime::run(config).await,
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
