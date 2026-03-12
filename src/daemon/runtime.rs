use async_channel::{Receiver, Sender};
use async_std::{io, prelude::*, task};
use futures::{FutureExt, select};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    cli::stderr_style,
    daemon::protocol::{InputCommand, OutputEvent},
    error::{Error, Result},
    forward::{self, ForwardEvent, ForwardPlan, ListenerPlan, TargetPlan},
    persistent::load_state,
    session::{self, SessionOptions},
};

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub mailbox: Option<String>,
    pub code_length: usize,
}

#[derive(Debug, Clone)]
enum StartMode {
    Allocate { code_length: usize },
    SetCode { code: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum RuleDirection {
    Local,
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonRule {
    direction: RuleDirection,
    listen: String,
    connect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonIntent {
    rules: Vec<DaemonRule>,
}

#[derive(Debug, Clone)]
struct TcpListen {
    host: String,
    port: u16,
}

#[derive(Debug, Clone)]
struct TcpConnect {
    host: String,
    port: u16,
}

fn parse_listen_endpoint(input: &str) -> Result<TcpListen> {
    let mut parts = input.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("tcp"), Some(port), None, None) => Ok(TcpListen {
            host: "127.0.0.1".into(),
            port: port
                .parse::<u16>()
                .map_err(|_| Error::Usage(format!("invalid listen endpoint port in {input:?}")))?,
        }),
        (Some("tcp"), Some(port), Some(interface), None) => {
            let (key, value) = interface.split_once('=').ok_or_else(|| {
                Error::Usage(format!("invalid listen endpoint option in {input:?}"))
            })?;
            if key != "interface" {
                return Err(Error::Usage(format!(
                    "unsupported listen endpoint option {key:?} in {input:?}"
                )));
            }
            Ok(TcpListen {
                host: value.to_string(),
                port: port
                    .parse::<u16>()
                    .map_err(|_| Error::Usage(format!("invalid listen endpoint port in {input:?}")))?,
            })
        },
        _ => Err(Error::Usage(format!(
            "unsupported listen endpoint {input:?}; expected tcp:PORT[:interface=HOST]"
        ))),
    }
}

fn parse_connect_endpoint(input: &str) -> Result<TcpConnect> {
    let mut parts = input.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("tcp"), Some(host), Some(port), None) => Ok(TcpConnect {
            host: host.to_string(),
            port: port
                .parse::<u16>()
                .map_err(|_| Error::Usage(format!("invalid connect endpoint port in {input:?}")))?,
        }),
        _ => Err(Error::Usage(format!(
            "unsupported connect endpoint {input:?}; expected tcp:HOST:PORT"
        ))),
    }
}

fn build_daemon_plan(here: &[DaemonRule], there: &[DaemonRule]) -> Result<ForwardPlan> {
    let mut listeners = Vec::new();
    let mut targets = Vec::new();

    for (idx, rule) in here.iter().enumerate() {
        let listen = parse_listen_endpoint(&rule.listen)?;
        let connect = parse_connect_endpoint(&rule.connect)?;
        match rule.direction {
            RuleDirection::Local => listeners.push(ListenerPlan {
                name: format!("rule-{}", idx + 1),
                listen_host: listen.host,
                listen_port: listen.port,
                connect_host: connect.host,
                connect_port: connect.port,
            }),
            RuleDirection::Remote => targets.push(TargetPlan {
                name: format!("rule-{}", idx + 1),
                connect_host: connect.host,
                connect_port: connect.port,
            }),
        }
    }

    for (idx, rule) in there.iter().enumerate() {
        let listen = parse_listen_endpoint(&rule.listen)?;
        let connect = parse_connect_endpoint(&rule.connect)?;
        match rule.direction {
            RuleDirection::Local => targets.push(TargetPlan {
                name: format!("peer-rule-{}", idx + 1),
                connect_host: connect.host,
                connect_port: connect.port,
            }),
            RuleDirection::Remote => listeners.push(ListenerPlan {
                name: format!("peer-rule-{}", idx + 1),
                listen_host: listen.host,
                listen_port: listen.port,
                connect_host: connect.host,
                connect_port: connect.port,
            }),
        }
    }

    if listeners.is_empty() && targets.is_empty() {
        return Err(Error::Usage(
            "no forwarding rules were configured on either side".into(),
        ));
    }
    if !listeners.is_empty() && !targets.is_empty() {
        return Err(Error::Usage(
            "bidirectional forwarding in one daemon session is not supported yet".into(),
        ));
    }

    Ok(ForwardPlan { listeners, targets })
}

async fn emit_event(sender: &Sender<OutputEvent>, event: OutputEvent) {
    let _ = sender.send(event).await;
}

async fn session_task(
    config: DaemonConfig,
    start_mode: StartMode,
    rules: Vec<DaemonRule>,
    events: Sender<OutputEvent>,
    cancel: Receiver<()>,
) {
    let result: Result<()> = async {
        let options = match start_mode {
            StartMode::Allocate { code_length } => SessionOptions {
                mailbox: config.mailbox.clone(),
                code_length,
                code: None,
                allocate_on_connect: false,
            },
            StartMode::SetCode { code } => SessionOptions {
                mailbox: config.mailbox.clone(),
                code_length: config.code_length,
                code: Some(code),
                allocate_on_connect: false,
            },
        };

        let prepared = session::prepare_session(options).await?;
        if let Some(welcome) = prepared.welcome.clone() {
            emit_event(&events, OutputEvent::Welcome { welcome }).await;
        }
        emit_event(&events, OutputEvent::CodeAllocated { code: prepared.code.clone() }).await;

        let mut connected = prepared.connect().await?;
        emit_event(
            &events,
            OutputEvent::PeerConnected {
                verifier: connected.verifier.clone(),
                versions: connected.peer_version.clone(),
            },
        )
        .await;

        let intent = DaemonIntent { rules };
        connected.wormhole.send_json(&intent).await?;
        let peer_intent: DaemonIntent = connected.wormhole.receive_json().await??;
        let plan = build_daemon_plan(&intent.rules, &peer_intent.rules)?;

        forward::run_forwarding(connected, plan, cancel, |event| match event {
            ForwardEvent::Listening {
                listen_host,
                listen_port,
                connect_host,
                connect_port,
                ..
            } => {
                let listen = format!("tcp:{listen_port}:interface={listen_host}");
                let connect = format!("tcp:{connect_host}:{connect_port}");
                let _ = events.send_blocking(OutputEvent::Listening { listen, connect });
            },
        })
        .await
    }
    .await;

    if let Err(error) = result {
        emit_event(&events, OutputEvent::Error { message: error.to_string() }).await;
    }
    emit_event(&events, OutputEvent::Closed {}).await;
}

async fn stdout_task(events: Receiver<OutputEvent>) -> Result<()> {
    let mut stdout = io::stdout();
    while let Ok(event) = events.recv().await {
        let line = serde_json::to_string(&event)?;
        stdout.write_all(line.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}

async fn stdin_task(lines: Sender<String>) {
    let stdin = io::BufReader::new(io::stdin());
    let mut input = stdin.lines();
    while let Some(line) = input.next().await {
        match line {
            Ok(line) => {
                if lines.send(line).await.is_err() {
                    break;
                }
            },
            Err(_) => break,
        }
    }
}

pub async fn run(config: DaemonConfig) -> Result<()> {
    let (line_tx, line_rx) = async_channel::unbounded::<String>();
    let (event_tx, event_rx) = async_channel::unbounded::<OutputEvent>();

    task::spawn(stdin_task(line_tx));
    task::spawn(stdout_task(event_rx));

    let mut rules: Vec<DaemonRule> = Vec::new();
    let mut cancel_tx: Option<Sender<()>> = None;
    let mut session_future = futures::future::pending::<()>().boxed_local().fuse();
    let mut session_started = false;

    loop {
        let line_fut = line_rx.recv().fuse();
        futures::pin_mut!(line_fut);

        select! {
            line = line_fut => {
                let line = match line {
                    Ok(line) => line,
                    Err(_) => break,
                };
                let command = match serde_json::from_str::<InputCommand>(&line) {
                    Ok(command) => command,
                    Err(error) => {
                        emit_event(&event_tx, OutputEvent::Error { message: format!("invalid input: {error}") }).await;
                        continue;
                    },
                };

                match command {
                    InputCommand::Local { listen, connect } => {
                        if session_started {
                            emit_event(&event_tx, OutputEvent::Error { message: "local commands are only accepted before the session starts".into() }).await;
                        } else {
                            rules.push(DaemonRule { direction: RuleDirection::Local, listen, connect });
                        }
                    },
                    InputCommand::Remote { listen, connect } => {
                        if session_started {
                            emit_event(&event_tx, OutputEvent::Error { message: "remote commands are only accepted before the session starts".into() }).await;
                        } else {
                            rules.push(DaemonRule { direction: RuleDirection::Remote, listen, connect });
                        }
                    },
                    InputCommand::AllocateCode { code_length } => {
                        if session_started {
                            emit_event(&event_tx, OutputEvent::Error { message: "the session has already started".into() }).await;
                            continue;
                        }
                        let (session_cancel_tx, session_cancel_rx) = async_channel::bounded::<()>(1);
                        cancel_tx = Some(session_cancel_tx);
                        session_future = session_task(
                            config.clone(),
                            StartMode::Allocate { code_length: code_length.unwrap_or(config.code_length) },
                            rules.clone(),
                            event_tx.clone(),
                            session_cancel_rx,
                        )
                        .boxed_local()
                        .fuse();
                        session_started = true;
                    },
                    InputCommand::SetCode { code } => {
                        if session_started {
                            emit_event(&event_tx, OutputEvent::Error { message: "the session has already started".into() }).await;
                            continue;
                        }
                        let (session_cancel_tx, session_cancel_rx) = async_channel::bounded::<()>(1);
                        cancel_tx = Some(session_cancel_tx);
                        session_future = session_task(
                            config.clone(),
                            StartMode::SetCode { code },
                            rules.clone(),
                            event_tx.clone(),
                            session_cancel_rx,
                        )
                        .boxed_local()
                        .fuse();
                        session_started = true;
                    },
                    InputCommand::SessionClose { .. } => {
                        if let Some(cancel_tx) = &cancel_tx {
                            let _ = cancel_tx.send(()).await;
                        } else {
                            emit_event(&event_tx, OutputEvent::Closed {}).await;
                            break;
                        }
                    },
                }
            },
            () = session_future => {
                break;
            }
        }
    }

    Ok(())
}

pub async fn run_persistent(_state_path: PathBuf) -> Result<()> {
    let mut state = load_state(&_state_path)?;
    if state.peer_public_key_hex.is_none() {
        return Err(Error::PersistentState(
            "persistent state is missing the trusted peer identity".into(),
        ));
    }

    let style = stderr_style();
    let intent = forward::CliIntent {
        locals: state.config.locals.clone(),
        remotes: state.config.remotes.clone(),
    };
    let mut retry_delay = 1u64;

    loop {
        let result: Result<()> = async {
            let prepared = session::prepare_session(SessionOptions {
                mailbox: state.config.mailbox.clone(),
                code_length: 2,
                code: Some(state.config.code.clone()),
                allocate_on_connect: true,
            })
            .await?;

            if let Some(welcome) = &prepared.welcome {
                eprintln!("{} {welcome}", style.label("Mailbox:"));
            }

            let mut connected = prepared.connect().await?;
            eprintln!("{} peer connected", style.status("Status:"));
            eprintln!("{} {}", style.label("Verifier:"), connected.verifier);
            session::authenticate_persistent_peer(&mut connected, &mut state).await?;

            let peer_intent = forward::exchange_cli_intents(&mut connected.wormhole, &intent).await?;
            let plan = forward::build_cli_plan(&intent, &peer_intent)?;
            let (_cancel_tx, cancel_rx) = async_channel::bounded(1);
            forward::run_forwarding(connected, plan, cancel_rx, |event| match event {
                ForwardEvent::Listening {
                    name,
                    listen_host,
                    listen_port,
                    connect_host,
                    connect_port,
                } => {
                    eprintln!(
                        "{} {name} on {listen_host}:{listen_port} -> {connect_host}:{connect_port}",
                        style.status("Listening:"),
                    );
                },
            })
            .await
        }
        .await;

        match result {
            Ok(()) => {
                retry_delay = 1;
                eprintln!("{} session ended; reconnecting...", style.status("Status:"));
            },
            Err(error) if is_hard_persistent_failure(&error) => return Err(error),
            Err(error) => {
                let retry_hint = persistent_retry_message(&state.config.code, &error, retry_delay);
                eprintln!("{} {retry_hint}", style.status("Status:"));
                task::sleep(std::time::Duration::from_secs(retry_delay)).await;
                retry_delay = next_retry_delay(&error, retry_delay);
                continue;
            },
        }
    }
}

fn is_hard_persistent_failure(error: &Error) -> bool {
    matches!(
        error,
        Error::Authentication(_) | Error::PersistentState(_) | Error::Usage(_)
    )
}

fn next_retry_delay(error: &Error, retry_delay: u64) -> u64 {
    if is_expected_rendezvous_gap(error) {
        1
    } else {
        (retry_delay * 2).min(5)
    }
}

fn persistent_retry_message(code: &str, error: &Error, retry_delay: u64) -> String {
    if is_expected_rendezvous_gap(error) {
        return format!(
            "waiting for the peer to claim code {code}; retrying in {retry_delay}s..."
        );
    }
    if is_transit_disconnect(error) {
        return format!("the previous tunnel session ended; retrying in {retry_delay}s...");
    }
    format!("{error}. Retrying in {retry_delay}s.")
}

fn is_expected_rendezvous_gap(error: &Error) -> bool {
    matches!(error, Error::Session(message) if message.contains("UnclaimedNameplate"))
}

fn is_transit_disconnect(error: &Error) -> bool {
    match error {
        Error::Wormhole(wormhole) => wormhole.to_string().contains("Transit error"),
        other => other.to_string().contains("Transit error"),
    }
}
