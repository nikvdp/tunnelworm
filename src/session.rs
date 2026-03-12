use magic_wormhole::{
    Code, MailboxConnection, Wormhole,
    forwarding,
    transit::{self, RelayHint},
};
use serde_json::Value;
use std::borrow::Cow;

use crate::{
    cli::FowlConfig,
    error::{Error, Result},
};

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub mailbox: Option<String>,
    pub code_length: usize,
    pub code: Option<String>,
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

impl From<&FowlConfig> for SessionOptions {
    fn from(value: &FowlConfig) -> Self {
        Self {
            mailbox: value.mailbox.clone(),
            code_length: value.code_length,
            code: value.code.clone(),
        }
    }
}

fn app_config(mailbox: Option<&str>) -> magic_wormhole::AppConfig<forwarding::AppVersion> {
    match mailbox {
        Some(mailbox) => forwarding::APP_CONFIG.clone().rendezvous_url(Cow::Owned(mailbox.to_string())),
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

    let (mailbox_connection, code_was_allocated) = match options.code {
        Some(code) => {
            let code = code
                .parse::<Code>()
                .map_err(|error| Error::Usage(format!("invalid wormhole code: {error}")))?;
            (MailboxConnection::connect(config, code, true).await?, false)
        },
        None => (MailboxConnection::create(config, options.code_length).await?, true),
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

pub async fn run_fowl(config: FowlConfig) -> Result<()> {
    let prepared = prepare_session(SessionOptions::from(&config)).await?;
    if let Some(welcome) = &prepared.welcome {
        println!("welcome: {welcome}");
    }
    if prepared.code_was_allocated {
        println!("code: {}", prepared.code);
    }
    let session = prepared.connect().await?;
    println!("peer-connected: {}", session.verifier);
    println!("peer-versions: {}", session.peer_version);
    session.wormhole.close().await?;
    Ok(())
}

pub async fn run_fowld() -> Result<()> {
    Err(Error::NotImplemented("fowld runtime"))
}
