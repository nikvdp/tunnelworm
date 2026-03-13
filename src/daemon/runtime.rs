use async_channel::{Receiver, Sender};
use async_std::{io, net::{TcpListener, TcpStream}, prelude::*, task};
use fs2::FileExt;
use futures::{FutureExt, select};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::{
    cli::stderr_style,
    control::{ControlResponse, ControlServer, RuntimeControlRequest},
    daemon::protocol::{InputCommand, OutputEvent},
    error::{Error, Result},
    forward::{self, ForwardEvent, ForwardPlan, ListenerPlan, TargetPlan},
    mux::{ChannelKind, IncomingChannel, MuxSession, MuxTransport},
    pipe::PipeMode,
    persistent::{PersistentRole, TunnelRuntimePhase, TunnelRuntimeStatus, load_state, runtime_status_path},
    session::{self, SessionOptions},
    shell::{ShellOpen, ShellPacket, bridge_local_shell_stream, run_remote_shell, send_channel_packet, write_stream_packet},
    status_line::StatusLine,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PortForwardOpen {
    connect_host: String,
    connect_port: u16,
}

#[derive(Default)]
struct PipeBroker {
    pending_sender: Mutex<Option<async_std::os::unix::net::UnixStream>>,
    pending_channel: Mutex<Option<crate::mux::MuxChannel>>,
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
                listen_host: listen.host,
                listen_port: listen.port,
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
                listen_host: listen.host,
                listen_port: listen.port,
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

async fn bridge_stream_and_channel<S>(stream: S, channel: crate::mux::MuxChannel) -> Result<()>
where
    S: async_std::io::Read + async_std::io::Write + Clone + Unpin + Send + 'static,
{
    let mut reader = stream.clone();
    let mut writer = stream;
    let channel_for_send = channel.clone();
    let send_task = task::spawn(async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                channel_for_send.close().await?;
                return Ok::<(), Error>(());
            }
            channel_for_send.send(buffer[..read].to_vec()).await?;
        }
    });

    let recv_task = task::spawn(async move {
        while let Some(payload) = channel.recv().await? {
            writer.write_all(&payload).await?;
            writer.flush().await?;
        }
        Ok::<(), Error>(())
    });

    send_task.await?;
    recv_task.await?;
    Ok(())
}

async fn handle_incoming_channel(
    incoming: IncomingChannel,
    pipe_broker: Arc<PipeBroker>,
    runtime_status: &PersistentRuntimeStatus,
    style: &crate::cli::AnsiStyle,
) -> Result<()> {
    match incoming.kind {
        ChannelKind::Echo => {
            while let Some(payload) = incoming.channel.recv().await? {
                incoming.channel.send(payload).await?;
            }
            incoming.channel.close().await?;
            Ok(())
        },
        ChannelKind::PortForward => {
            let open: PortForwardOpen = serde_json::from_slice(&incoming.open_payload)?;
            let stream = TcpStream::connect((open.connect_host.as_str(), open.connect_port))
                .await
                .map_err(|error| {
                    Error::Session(format!(
                        "could not connect to local target {}:{}: {error}",
                        open.connect_host, open.connect_port
                    ))
                })?;
            let detail = format!(
                "peer port forward -> local {}:{}",
                open.connect_host, open.connect_port
            );
            runtime_status.write(TunnelRuntimeStatus {
                phase: TunnelRuntimePhase::Up,
                detail: Some(detail.clone()),
            })?;
            eprintln!("{} {detail}", style.status("Forwarding:"));
            bridge_stream_and_channel(stream, incoming.channel).await
        },
        ChannelKind::Pipe => {
            let (maybe_sender, maybe_channel) = take_pending_pipe_pair(&pipe_broker);
            match (maybe_sender, maybe_channel) {
                (Some(local_stream), None) => {
                    task::spawn(attach_pipe_stream(
                        PipeMode::Send,
                        local_stream,
                        incoming.channel,
                    ));
                    Ok(())
                },
                (None, None) => queue_pipe_channel(&pipe_broker, incoming.channel),
                (maybe_sender, Some(existing_channel)) => {
                    if let Some(local_stream) = maybe_sender {
                        let _ = queue_pipe_sender(&pipe_broker, local_stream);
                    }
                    let _ = queue_pipe_channel(&pipe_broker, existing_channel);
                    Err(Error::Session(
                        "another pipe channel is already waiting locally".into(),
                    ))
                },
            }
        },
        ChannelKind::Shell => {
            let open: ShellOpen = serde_json::from_slice(&incoming.open_payload)?;
            task::spawn(async move {
                if let Err(error) = run_remote_shell(incoming.channel.clone(), open).await {
                    let _ = send_channel_packet(
                        &incoming.channel,
                        &ShellPacket::Error {
                            message: error.to_string(),
                        },
                    )
                    .await;
                    let _ = incoming.channel.close().await;
                }
            });
            Ok(())
        },
    }
}

async fn drive_incoming_channels(
    session: MuxSession,
    pipe_broker: Arc<PipeBroker>,
    runtime_status: PersistentRuntimeStatus,
    style: crate::cli::AnsiStyle,
) {
    while let Ok(incoming) = session.next_incoming().await {
        let pipe_broker = pipe_broker.clone();
        let runtime_status = runtime_status.clone();
        let style = style.clone();
        task::spawn(async move {
            let _ = handle_incoming_channel(incoming, pipe_broker, &runtime_status, &style).await;
        });
    }
}

async fn drive_listener(
    listener_plan: ListenerPlan,
    session: MuxSession,
    runtime_status: PersistentRuntimeStatus,
    style: crate::cli::AnsiStyle,
    cancel: Receiver<()>,
) -> Result<()> {
    let listener = TcpListener::bind((listener_plan.listen_host.as_str(), listener_plan.listen_port))
        .await
        .map_err(|error| {
            Error::Session(format!(
                "could not listen on {}:{}: {error}",
                listener_plan.listen_host, listener_plan.listen_port
            ))
        })?;

    let detail = format!(
        "local {}:{} -> peer {}:{}",
        listener_plan.listen_host,
        listener_plan.listen_port,
        listener_plan.connect_host,
        listener_plan.connect_port
    );
    runtime_status.write(TunnelRuntimeStatus {
        phase: TunnelRuntimePhase::Up,
        detail: Some(detail.clone()),
    })?;
    eprintln!("{} {detail}", style.status("Listening:"));

    loop {
        let accept = listener.accept().fuse();
        let cancel_fut = cancel.recv().fuse();
        futures::pin_mut!(accept, cancel_fut);
        futures::select! {
            accepted = accept => {
                let (stream, _) = accepted.map_err(|error| {
                    Error::Session(format!(
                        "could not accept a local connection on {}:{}: {error}",
                        listener_plan.listen_host, listener_plan.listen_port
                    ))
                })?;
                let session = session.clone();
                let open = PortForwardOpen {
                    connect_host: listener_plan.connect_host.clone(),
                    connect_port: listener_plan.connect_port,
                };
                task::spawn(async move {
                    let result: Result<()> = async {
                        let channel = session
                            .open_channel(ChannelKind::PortForward, serde_json::to_vec(&open)?)
                            .await?;
                        bridge_stream_and_channel(stream, channel).await
                    }.await;
                    let _ = result;
                });
            },
            _ = cancel_fut => return Ok(()),
        }
    }
}

async fn attach_pipe_stream(
    mode: PipeMode,
    local_stream: async_std::os::unix::net::UnixStream,
    channel: crate::mux::MuxChannel,
) {
    let _ = match mode {
        PipeMode::Send => pump_local_to_channel(local_stream, channel).await,
        PipeMode::Receive => pump_channel_to_local(channel, local_stream).await,
    };
}

async fn pump_local_to_channel(
    mut local_stream: async_std::os::unix::net::UnixStream,
    channel: crate::mux::MuxChannel,
) -> Result<()> {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = local_stream.read(&mut buffer).await?;
        if read == 0 {
            channel.close().await?;
            return Ok(());
        }
        channel.send(buffer[..read].to_vec()).await?;
    }
}

async fn pump_channel_to_local(
    channel: crate::mux::MuxChannel,
    mut local_stream: async_std::os::unix::net::UnixStream,
) -> Result<()> {
    while let Some(payload) = channel.recv().await? {
        local_stream.write_all(&payload).await?;
        local_stream.flush().await?;
    }
    Ok(())
}

fn queue_pipe_sender(
    broker: &Arc<PipeBroker>,
    stream: async_std::os::unix::net::UnixStream,
) -> Result<()> {
    let mut pending_sender = broker
        .pending_sender
        .lock()
        .expect("pipe broker mutex poisoned");
    if pending_sender.is_some() {
        return Err(Error::Session(
            "a local pipe send command is already waiting for the peer".into(),
        ));
    }
    *pending_sender = Some(stream);
    Ok(())
}

fn queue_pipe_channel(
    broker: &Arc<PipeBroker>,
    channel: crate::mux::MuxChannel,
) -> Result<()> {
    let mut pending_channel = broker
        .pending_channel
        .lock()
        .expect("pipe broker mutex poisoned");
    if pending_channel.is_some() {
        return Err(Error::Session(
            "a remote pipe channel is already waiting for the local sender".into(),
        ));
    }
    *pending_channel = Some(channel);
    Ok(())
}

fn take_pending_pipe_pair(
    broker: &Arc<PipeBroker>,
) -> (
    Option<async_std::os::unix::net::UnixStream>,
    Option<crate::mux::MuxChannel>,
) {
    let mut pending_sender = broker
        .pending_sender
        .lock()
        .expect("pipe broker mutex poisoned");
    let mut pending_channel = broker
        .pending_channel
        .lock()
        .expect("pipe broker mutex poisoned");
    (pending_sender.take(), pending_channel.take())
}

fn clear_pending_pipe_state(broker: &Arc<PipeBroker>) {
    let _ = broker
        .pending_sender
        .lock()
        .expect("pipe broker mutex poisoned")
        .take();
    let _ = broker
        .pending_channel
        .lock()
        .expect("pipe broker mutex poisoned")
        .take();
}

async fn handle_runtime_control_request(
    request: RuntimeControlRequest,
    session: Option<MuxSession>,
    pipe_broker: Arc<PipeBroker>,
    state_path: &Path,
) -> Result<()> {
    match request {
        RuntimeControlRequest::Probe { reply } => {
            let state = load_state(state_path)?;
            let runtime_path = runtime_status_path(state_path);
            let runtime = if runtime_path.exists() {
                let bytes = fs::read(&runtime_path)?;
                serde_json::from_slice(&bytes)?
            } else {
                TunnelRuntimeStatus {
                    phase: TunnelRuntimePhase::Starting,
                    detail: Some("persistent worker is starting".into()),
                }
            };
            let _ = reply
                .send(Ok(ControlResponse::Probe {
                    tunnel_name: state.config.name,
                    code: state.config.code,
                    runtime,
                }))
                .await;
        },
        RuntimeControlRequest::Echo { payload, reply } => {
            let Some(session) = session else {
                let _ = reply
                    .send(Err(Error::Session("the tunnel is not connected yet".into())))
                    .await;
                return Ok(());
            };
            let channel = session.open_channel(ChannelKind::Echo, Vec::new()).await?;
            channel.send(payload.into_bytes()).await?;
            channel.close().await?;
            let mut echoed = Vec::new();
            while let Some(chunk) = channel.recv().await? {
                echoed.extend(chunk);
            }
            let _ = reply
                .send(Ok(ControlResponse::Echo {
                    payload: String::from_utf8_lossy(&echoed).into_owned(),
                }))
                .await;
        },
        RuntimeControlRequest::Pipe { mode, stream } => {
            let Some(session) = session else {
                return Err(Error::Session("the tunnel is not connected yet".into()));
            };
            match mode {
                PipeMode::Receive => {
                    let channel = session.open_channel(ChannelKind::Pipe, Vec::new()).await?;
                    task::spawn(attach_pipe_stream(PipeMode::Receive, stream, channel));
                },
                PipeMode::Send => {
                    let (maybe_sender, maybe_channel) = take_pending_pipe_pair(&pipe_broker);
                    match (maybe_sender, maybe_channel) {
                        (None, Some(channel)) => {
                            task::spawn(attach_pipe_stream(PipeMode::Send, stream, channel));
                        },
                        (None, None) => {
                            queue_pipe_sender(&pipe_broker, stream)?;
                        },
                        (Some(existing_sender), maybe_channel) => {
                            let _ = queue_pipe_sender(&pipe_broker, existing_sender);
                            if let Some(channel) = maybe_channel {
                                let _ = queue_pipe_channel(&pipe_broker, channel);
                            }
                            return Err(Error::Session(
                                "a pipe send command is already waiting for the peer".into(),
                            ));
                        },
                    }
                },
            }
        },
        RuntimeControlRequest::Shell { open, stream } => {
            let Some(session) = session else {
                let mut stream = stream;
                write_stream_packet(
                    &mut stream,
                    &ShellPacket::Error {
                        message: "the tunnel is not connected yet".into(),
                    },
                )
                .await?;
                return Ok(());
            };
            match session
                .open_channel(ChannelKind::Shell, serde_json::to_vec(&open)?)
                .await
            {
                Ok(channel) => {
                    task::spawn(async move {
                        let _ = bridge_local_shell_stream(stream, channel).await;
                    });
                },
                Err(error) => {
                    let mut stream = stream;
                    write_stream_packet(
                        &mut stream,
                        &ShellPacket::Error {
                            message: error.to_string(),
                        },
                    )
                    .await?;
                },
            }
        },
    }
    Ok(())
}

async fn drive_runtime_control_requests(
    requests: Receiver<RuntimeControlRequest>,
    live_session: Arc<Mutex<Option<MuxSession>>>,
    pipe_broker: Arc<PipeBroker>,
    state_path: PathBuf,
) {
    while let Ok(request) = requests.recv().await {
        let session = live_session
            .lock()
            .expect("live session mutex poisoned")
            .clone();
        let _ =
            handle_runtime_control_request(request, session, pipe_broker.clone(), &state_path).await;
    }
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
    let _lock = acquire_persistent_state_lock(&_state_path)?;
    let runtime_status = PersistentRuntimeStatus::new(&_state_path)?;
    let (control_tx, control_rx) = async_channel::unbounded::<RuntimeControlRequest>();
    let live_session = Arc::new(Mutex::new(None::<MuxSession>));
    let pipe_broker = Arc::new(PipeBroker::default());
    let _control = ControlServer::spawn(&_state_path, control_tx)?;
    task::spawn(drive_runtime_control_requests(
        control_rx,
        live_session.clone(),
        pipe_broker.clone(),
        _state_path.clone(),
    ));
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
    runtime_status.write(TunnelRuntimeStatus {
        phase: TunnelRuntimePhase::Starting,
        detail: Some("persistent worker is starting".into()),
    })?;

    loop {
        let result: Result<()> = async {
            let reconnect_role = reconnect_role(&state);
            let prepared = session::prepare_session(SessionOptions {
                mailbox: state.config.mailbox.clone(),
                code_length: 2,
                code: Some(state.config.code.clone()),
                allocate_on_connect: matches!(reconnect_role, PersistentRole::Allocate),
            })
            .await?;

            if let Some(welcome) = &prepared.welcome {
                eprintln!("{} {welcome}", style.label("Mailbox:"));
            }

            let mut connected = connect_with_progress(
                prepared,
                &style,
                &runtime_status,
                reconnect_role,
                &state.config.code,
            )
            .await?;
            eprintln!("{} peer connected", style.status("Status:"));
            eprintln!("{} {}", style.label("Verifier:"), connected.verifier);
            runtime_status.write(TunnelRuntimeStatus {
                phase: TunnelRuntimePhase::Up,
                detail: Some(format!("peer connected; verifier {}", connected.verifier)),
            })?;
            session::authenticate_persistent_peer(&mut connected, &mut state).await?;

            let peer_intent = forward::exchange_cli_intents(&mut connected.wormhole, &intent).await?;
            let plan = forward::build_cli_plan(&intent, &peer_intent)?;
            for target in &plan.targets {
                let detail = format!(
                    "peer {}:{} -> local {}:{}",
                    target.listen_host, target.listen_port, target.connect_host, target.connect_port
                );
                runtime_status.write(TunnelRuntimeStatus {
                    phase: TunnelRuntimePhase::Up,
                    detail: Some(detail.clone()),
                })?;
                eprintln!("{} {detail}", style.status("Forwarding:"));
            }
            let transport = MuxTransport::connect(connected, reconnect_role).await?;
            let mux_session = transport.session();
            {
                *live_session.lock().expect("live session mutex poisoned") = Some(mux_session.clone());
            }
            let incoming_task = task::spawn(drive_incoming_channels(
                mux_session.clone(),
                pipe_broker.clone(),
                runtime_status.clone(),
                style.clone(),
            ));

            let (listener_cancel_tx, listener_cancel_rx) = async_channel::bounded::<()>(1);
            let mut listener_tasks = Vec::new();
            for listener in plan.listeners {
                listener_tasks.push(task::spawn(drive_listener(
                    listener,
                    mux_session.clone(),
                    runtime_status.clone(),
                    style.clone(),
                    listener_cancel_rx.clone(),
                )));
            }

            let transport_result = transport.wait_for_close().await;
            let _ = listener_cancel_tx.send(()).await;
            for task in listener_tasks {
                let _ = task.await;
            }
            let _ = incoming_task.cancel().await;
            *live_session.lock().expect("live session mutex poisoned") = None;
            clear_pending_pipe_state(&pipe_broker);
            transport_result
        }
        .await;

        match result {
            Ok(()) => {
                retry_delay = 1;
                runtime_status.write(TunnelRuntimeStatus {
                    phase: TunnelRuntimePhase::Waiting,
                    detail: Some("session ended; reconnecting".into()),
                })?;
                eprintln!("{} session ended; reconnecting...", style.status("Status:"));
            },
            Err(error) if is_hard_persistent_failure(&error) => return Err(error),
            Err(error) => {
                sleep_with_retry_status(
                    &style,
                    &runtime_status,
                    &state.config.code,
                    &error,
                    retry_delay,
                )
                .await?;
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

fn reconnect_role(state: &crate::persistent::PersistentState) -> PersistentRole {
    match state.peer_public_key_hex.as_deref() {
        Some(peer_public_key_hex) => {
            if state.local_identity.public_key_hex.as_str() <= peer_public_key_hex {
                PersistentRole::Allocate
            } else {
                PersistentRole::Join
            }
        },
        None => state.config.role,
    }
}

fn acquire_persistent_state_lock(state_path: &Path) -> Result<File> {
    let lock_path = state_path.with_extension("lock");
    let mut lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)?;

    lock_file.try_lock_exclusive().map_err(|_| {
        Error::PersistentState(format!(
            "persistent worker is already running for {}; stop the existing process or wait for it to exit before starting this saved tunnel side again",
            state_path.display()
        ))
    })?;

    lock_file.set_len(0)?;
    writeln!(lock_file, "pid={}", std::process::id())?;
    Ok(lock_file)
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

async fn connect_with_progress(
    prepared: session::PreparedSession,
    style: &crate::cli::AnsiStyle,
    runtime_status: &PersistentRuntimeStatus,
    reconnect_role: PersistentRole,
    code: &str,
) -> Result<session::ConnectedSession> {
    let mut spinner = StatusLine::stderr();
    let connect_future = prepared.connect().fuse();
    futures::pin_mut!(connect_future);
    loop {
        let tick = task::sleep(std::time::Duration::from_millis(125)).fuse();
        futures::pin_mut!(tick);
        futures::select! {
            connected = connect_future => {
                spinner.clear()?;
                return connected;
            },
            () = tick => {
                let (phase, detail) = match reconnect_role {
                    PersistentRole::Allocate => (
                        TunnelRuntimePhase::Waiting,
                        format!("waiting for the peer to join code {code}..."),
                    ),
                    PersistentRole::Join => (
                        TunnelRuntimePhase::Starting,
                        "connecting to the peer...".to_string(),
                    ),
                };
                runtime_status.write(TunnelRuntimeStatus {
                    phase,
                    detail: Some(detail.clone()),
                })?;
                spinner.update(&style.status("Status:"), &detail)?;
            }
        }
    }
}

async fn sleep_with_retry_status(
    style: &crate::cli::AnsiStyle,
    runtime_status: &PersistentRuntimeStatus,
    code: &str,
    error: &Error,
    retry_delay: u64,
) -> Result<()> {
    let mut spinner = StatusLine::stderr();
    let phase = if is_expected_rendezvous_gap(error) {
        TunnelRuntimePhase::Waiting
    } else {
        TunnelRuntimePhase::Retrying
    };
    for remaining in (1..=retry_delay).rev() {
        let retry_hint = persistent_retry_message(code, error, remaining);
        runtime_status.write(TunnelRuntimeStatus {
            phase: phase.clone(),
            detail: Some(retry_hint.clone()),
        })?;
        for _ in 0..8 {
            spinner.update(&style.status("Status:"), &retry_hint)?;
            task::sleep(std::time::Duration::from_millis(125)).await;
        }
    }
    spinner.clear()?;
    Ok(())
}

#[derive(Clone)]
struct PersistentRuntimeStatus {
    path: PathBuf,
}

impl PersistentRuntimeStatus {
    fn new(state_path: &Path) -> Result<Self> {
        let path = runtime_status_path(state_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self { path })
    }

    fn write(&self, status: TunnelRuntimeStatus) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&status)?;
        fs::write(&self.path, bytes)?;
        Ok(())
    }
}

impl Drop for PersistentRuntimeStatus {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
