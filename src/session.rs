use async_std::task;
use futures::FutureExt;
use magic_wormhole::{
    Code, MailboxConnection, Wormhole, forwarding,
    transit::{self, RelayHint},
};
use serde_json::Value;
use std::borrow::Cow;
use std::time::Duration;

use crate::{
    cli::{TunnelConfig, stdout_style},
    error::{Error, Result},
    forward::{self, CliIntent, ForwardEvent},
    persistent::PersistentState,
    persistent_auth,
    status_line::StatusLine,
};

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub mailbox: Option<String>,
    pub code_length: usize,
    pub code: Option<String>,
    pub allocate_on_connect: bool,
}

pub struct PreparedSession {
    pub mailbox_connection: MailboxConnection<forwarding::AppVersion>,
    pub code: String,
    pub code_was_allocated: bool,
    pub welcome: Option<String>,
    pub relay_hints: Vec<RelayHint>,
}

#[derive(Debug)]
pub struct ConnectedSession {
    pub wormhole: Wormhole,
    pub code: String,
    pub code_was_allocated: bool,
    pub welcome: Option<String>,
    pub verifier: String,
    pub peer_version: Value,
    pub relay_hints: Vec<RelayHint>,
}

impl From<&TunnelConfig> for SessionOptions {
    fn from(value: &TunnelConfig) -> Self {
        Self {
            mailbox: value.mailbox.clone(),
            code_length: value.code_length,
            code: value.code.clone(),
            allocate_on_connect: false,
        }
    }
}

fn app_config(mailbox: Option<&str>) -> magic_wormhole::AppConfig<forwarding::AppVersion> {
    match mailbox {
        Some(mailbox) => forwarding::APP_CONFIG
            .clone()
            .rendezvous_url(Cow::Owned(mailbox.to_string())),
        None => forwarding::APP_CONFIG.clone(),
    }
}

fn default_relay_hints() -> Vec<RelayHint> {
    vec![
        transit::RelayHint::from_urls(
            None,
            [magic_wormhole::transit::DEFAULT_RELAY_SERVER
                .parse()
                .expect("default transit relay URL must parse")],
        )
        .expect("default relay hint must parse"),
    ]
}

pub async fn prepare_session(options: SessionOptions) -> Result<PreparedSession> {
    let config = app_config(options.mailbox.as_deref());
    let relay_hints = default_relay_hints();
    let mailbox_label = options
        .mailbox
        .clone()
        .unwrap_or_else(|| "the default rendezvous server".into());

    let (mailbox_connection, code_was_allocated) = match options.code {
        Some(code) => {
            let code = code
                .parse::<Code>()
                .map_err(|error| Error::Usage(format!("invalid wormhole code: {error}")))?;
            let code_string = code.to_string();
            let mailbox_connection = match MailboxConnection::connect(config, code.clone(), false).await {
                Ok(mailbox_connection) => mailbox_connection,
                Err(join_error) if options.allocate_on_connect => {
                    MailboxConnection::connect(
                        app_config(options.mailbox.as_deref()),
                        code,
                        true,
                    )
                    .await
                    .map_err(|retry_error| {
                        Error::Session(format!(
                            "could not reconnect creator wormhole code {:?} via {}. Join error: {join_error:?}. Retry error: {retry_error:?}",
                            code_string, mailbox_label
                        ))
                    })?
                },
                Err(error) => {
                    return Err(Error::Session(format!(
                        "could not join wormhole code {:?} via {}. Original error: {error:?}",
                        code_string, mailbox_label
                    )));
                },
            };
            (mailbox_connection, false)
        }
        None => {
            let mailbox_connection = MailboxConnection::create(config, options.code_length)
                .await
                .map_err(|error| {
                    Error::Session(format!(
                        "could not allocate a new wormhole code via {}. Original error: {error:?}",
                        mailbox_label
                    ))
                })?;
            (mailbox_connection, true)
        }
    };

    let welcome = mailbox_connection.welcome().map(ToOwned::to_owned);
    let code = mailbox_connection.code().to_string();

    Ok(PreparedSession {
        mailbox_connection,
        code,
        code_was_allocated,
        welcome,
        relay_hints,
    })
}

impl PreparedSession {
    pub async fn connect(self) -> Result<ConnectedSession> {
        let code = self.code.clone();
        let code_was_allocated = self.code_was_allocated;
        let welcome = self.welcome.clone();
        let relay_hints = self.relay_hints.clone();
        let wormhole = Wormhole::connect(self.mailbox_connection).await?;
        let verifier = hex::encode(wormhole.verifier().as_slice());
        let peer_version = wormhole.peer_version().clone();

        Ok(ConnectedSession {
            wormhole,
            code,
            code_was_allocated,
            welcome,
            verifier,
            peer_version,
            relay_hints,
        })
    }
}

async fn connect_with_progress(
    prepared: PreparedSession,
    style: &crate::cli::AnsiStyle,
) -> Result<ConnectedSession> {
    let waiting_message = if prepared.code_was_allocated {
        format!("waiting for the peer to join code {}...", prepared.code)
    } else {
        "connecting to the peer...".to_string()
    };

    let mut status_line = StatusLine::stdout();
    status_line.update(&style.status("Status:"), &waiting_message)?;

    let connect_future = prepared.connect().fuse();
    futures::pin_mut!(connect_future);

    loop {
        let tick = task::sleep(Duration::from_millis(125)).fuse();
        futures::pin_mut!(tick);

        futures::select! {
            connected = connect_future => {
                status_line.clear()?;
                return connected;
            },
            () = tick => {
                status_line.update(&style.status("Status:"), &waiting_message)?;
            }
        }
    }
}

pub async fn authenticate_persistent_peer(
    session: &mut ConnectedSession,
    state: &mut PersistentState,
) -> Result<()> {
    persistent_auth::authenticate(&mut session.wormhole, state).await
}

pub async fn run_one_off(config: TunnelConfig) -> Result<()> {
    let style = stdout_style();
    let prepared = prepare_session(SessionOptions::from(&config)).await?;
    if prepared.code_was_allocated || config.code.is_some() {
        let mode = if prepared.code_was_allocated {
            "One-off create:"
        } else {
            "One-off join:"
        };
        println!("{} {}", style.heading(mode), prepared.code);
    }
    println!("{} {}", style.heading("Local:"), config.local_summary());
    if let (Some(preferred), Some(ssh_style)) = (
        config.peer_preferred_command(&prepared.code, false),
        config.peer_ssh_command(&prepared.code),
    ) {
        println!();
        println!("{}", style.heading("Peer commands"));
        println!("  {} {}", style.label("preferred:"), preferred);
        println!("  {} {}", style.label("ssh-style:"), ssh_style);
    }
    println!();
    if let Some(welcome) = &prepared.welcome {
        println!("{} {welcome}", style.label("Mailbox:"));
    }
    let mut session = connect_with_progress(prepared, &style).await?;
    println!("{} peer connected", style.status("Status:"));
    println!("{} {}", style.label("Verifier:"), session.verifier);

    let intent = CliIntent::from(&config);
    let peer_intent = forward::exchange_cli_intents(&mut session.wormhole, &intent).await?;
    let plan = forward::build_cli_plan(&intent, &peer_intent)?;
    for target in &plan.targets {
        println!(
            "{} peer {}:{} -> local {}:{}",
            style.status("Forwarding:"),
            target.listen_host,
            target.listen_port,
            target.connect_host,
            target.connect_port
        );
    }
    let (_cancel_tx, cancel_rx) = async_channel::bounded(1);
    forward::run_forwarding(session, plan, cancel_rx, |event| match event {
        ForwardEvent::Listening {
            name: _,
            listen_host,
            listen_port,
            connect_host,
            connect_port,
        } => {
            println!(
                "{} local {}:{} -> peer {}:{}",
                style.status("Listening:"),
                listen_host,
                listen_port,
                connect_host,
                connect_port
            );
        }
    })
    .await
}

pub async fn run_daemon_placeholder() -> Result<()> {
    Err(Error::NotImplemented("internal tunnelworm daemon runtime"))
}
