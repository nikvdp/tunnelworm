use std::{
    collections::BTreeSet,
    net::IpAddr,
};

use async_channel::Receiver;
use magic_wormhole::{Wormhole, forwarding};
use serde::{Deserialize, Serialize};

use crate::{
    cli::FowlConfig,
    error::{Error, Result},
    session::ConnectedSession,
    spec::{LocalSpec, RemoteSpec},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliIntent {
    pub locals: Vec<LocalSpec>,
    pub remotes: Vec<RemoteSpec>,
}

#[derive(Debug, Clone)]
pub struct ListenerPlan {
    pub name: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub connect_host: String,
    pub connect_port: u16,
}

#[derive(Debug, Clone)]
pub struct TargetPlan {
    pub name: String,
    pub connect_host: String,
    pub connect_port: u16,
}

#[derive(Debug, Clone)]
pub struct ForwardPlan {
    pub listeners: Vec<ListenerPlan>,
    pub targets: Vec<TargetPlan>,
}

#[derive(Debug, Clone)]
pub enum ForwardEvent {
    Listening {
        name: String,
        listen_host: String,
        listen_port: u16,
        connect_host: String,
        connect_port: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Here,
    There,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Self::Here => Self::There,
            Self::There => Self::Here,
        }
    }
}

impl From<&FowlConfig> for CliIntent {
    fn from(value: &FowlConfig) -> Self {
        Self {
            locals: value.locals.clone(),
            remotes: value.remotes.clone(),
        }
    }
}

fn choose_one<'a, T>(kind: &str, name: &str, values: Vec<(Side, &'a T)>) -> Result<Option<(Side, &'a T)>> {
    match values.as_slice() {
        [] => Ok(None),
        [single] => Ok(Some(*single)),
        _ => Err(Error::Usage(format!(
            "service {name:?} has multiple {kind} declarations; one per side is required"
        ))),
    }
}

pub async fn exchange_cli_intents(wormhole: &mut Wormhole, intent: &CliIntent) -> Result<CliIntent> {
    wormhole.send_json(intent).await?;
    let peer = wormhole.receive_json().await??;
    Ok(peer)
}

pub fn build_cli_plan(here: &CliIntent, there: &CliIntent) -> Result<ForwardPlan> {
    let names: BTreeSet<String> = here
        .locals
        .iter()
        .map(|spec| spec.name.clone())
        .chain(here.remotes.iter().map(|spec| spec.name.clone()))
        .chain(there.locals.iter().map(|spec| spec.name.clone()))
        .chain(there.remotes.iter().map(|spec| spec.name.clone()))
        .collect();

    let mut listeners = Vec::new();
    let mut targets = Vec::new();

    for name in names {
        let local = choose_one(
            "local",
            &name,
            here.locals
                .iter()
                .filter(|spec| spec.name == name)
                .map(|spec| (Side::Here, spec))
                .chain(
                    there
                        .locals
                        .iter()
                        .filter(|spec| spec.name == name)
                        .map(|spec| (Side::There, spec)),
                )
                .collect(),
        )?;
        let remote = choose_one(
            "remote",
            &name,
            here.remotes
                .iter()
                .filter(|spec| spec.name == name)
                .map(|spec| (Side::Here, spec))
                .chain(
                    there
                        .remotes
                        .iter()
                        .filter(|spec| spec.name == name)
                        .map(|spec| (Side::There, spec)),
                )
                .collect(),
        )?;

        if local.is_none() && remote.is_none() {
            continue;
        }

        let listener_side = match (local, remote) {
            (Some((local_side, _)), Some((remote_side, _))) if local_side == remote_side => {
                return Err(Error::Usage(format!(
                    "service {name:?} declares both local and remote on the same side, which is unsupported"
                )));
            },
            (Some((local_side, _)), Some(_)) => local_side,
            (Some((local_side, _)), None) => local_side,
            (None, Some((remote_side, _))) => remote_side.other(),
            (None, None) => unreachable!(),
        };
        let target_side = match remote {
            Some((side, _)) => side,
            None => listener_side.other(),
        };

        let local_spec = local.map(|(_, spec)| spec);
        let remote_spec = remote.map(|(_, spec)| spec);

        let listen_host = local_spec
            .and_then(|spec| spec.bind_interface.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let listen_port = local_spec
            .and_then(|spec| spec.local_listen_port)
            .or_else(|| remote_spec.and_then(|spec| spec.remote_listen_port))
            .unwrap_or(0);
        let connect_host = remote_spec
            .and_then(|spec| spec.connect_address.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let connect_port = remote_spec
            .and_then(|spec| spec.local_connect_port)
            .or_else(|| local_spec.and_then(|spec| spec.remote_connect_port))
            .or_else(|| local_spec.and_then(|spec| spec.local_listen_port))
            .ok_or_else(|| {
                Error::Usage(format!(
                    "service {name:?} does not specify a target port on either side"
                ))
            })?;

        if listener_side == Side::Here {
            listeners.push(ListenerPlan {
                name: name.clone(),
                listen_host: listen_host.clone(),
                listen_port,
                connect_host: connect_host.clone(),
                connect_port,
            });
        }
        if target_side == Side::Here {
            targets.push(TargetPlan {
                name,
                connect_host,
                connect_port,
            });
        }
    }

    if listeners.is_empty() && targets.is_empty() {
        return Err(Error::Usage(
            "no resolved forwarding rules were negotiated with the peer".into(),
        ));
    }
    if !listeners.is_empty() && !targets.is_empty() {
        return Err(Error::Usage(
            "bidirectional forwarding in one wormhole session is not supported yet".into(),
        ));
    }

    Ok(ForwardPlan { listeners, targets })
}

fn parse_bind_address(host: &str) -> Result<IpAddr> {
    match host {
        "localhost" => Ok(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        other => other
            .parse()
            .map_err(|_| Error::Usage(format!("unsupported listen host: {other}"))),
    }
}

fn target_host(host: &str) -> Result<Option<url::Host>> {
    Ok(Some(
        url::Host::parse(host)
            .map_err(|error| Error::Usage(format!("invalid connect host {host:?}: {error}")))?,
    ))
}

pub async fn run_forwarding<F>(
    session: ConnectedSession,
    plan: ForwardPlan,
    cancel: Receiver<()>,
    mut on_event: F,
) -> Result<()>
where
    F: FnMut(ForwardEvent),
{
    if !plan.targets.is_empty() {
        let targets = plan
            .targets
            .iter()
            .map(|target| Ok((target_host(&target.connect_host)?, target.connect_port)))
            .collect::<Result<Vec<_>>>()?;
        forwarding::serve(
            session.wormhole,
            |_| {},
            session.relay_hints,
            targets,
            async move {
                let _ = cancel.recv().await;
            },
        )
        .await?;
        return Ok(());
    }

    let bind_address = {
        let mut hosts = plan.listeners.iter().map(|listener| listener.listen_host.as_str());
        let first = hosts
            .next()
            .ok_or_else(|| Error::Usage("listener mode needs at least one listener".into()))?;
        if hosts.any(|host| host != first) {
            return Err(Error::Usage(
                "all local listeners in one session must use the same bind address".into(),
            ));
        }
        parse_bind_address(first)?
    };

    let custom_ports: Vec<u16> = plan.listeners.iter().map(|listener| listener.listen_port).collect();
    let offer = forwarding::connect(
        session.wormhole,
        |_| {},
        session.relay_hints,
        Some(bind_address),
        &custom_ports,
    )
    .await?;

    for ((actual_port, _), listener) in offer.mapping.iter().zip(plan.listeners.iter()) {
        on_event(ForwardEvent::Listening {
            name: listener.name.clone(),
            listen_host: listener.listen_host.clone(),
            listen_port: *actual_port,
            connect_host: listener.connect_host.clone(),
            connect_port: listener.connect_port,
        });
    }

    offer
        .accept(async move {
            let _ = cancel.recv().await;
        })
        .await?;
    Ok(())
}
