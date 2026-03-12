use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const IMPLICIT_FORWARD_PREFIX: &str = "implicit-forward";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSpec {
    pub name: String,
    pub local_listen_port: Option<u16>,
    pub remote_connect_port: Option<u16>,
    pub bind_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSpec {
    pub name: String,
    pub local_connect_port: Option<u16>,
    pub remote_listen_port: Option<u16>,
    pub connect_address: Option<String>,
}

fn parse_port(value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| Error::Usage(format!("invalid port: {value}")))?;
    if port == 0 {
        return Err(Error::Usage("ports must be between 1 and 65535".into()));
    }
    Ok(port)
}

fn is_candidate_port(value: &str) -> bool {
    value.parse::<u16>().map(|port| port > 0).unwrap_or(false)
}

fn canonical_host_token(value: &str) -> &str {
    match value {
        "localhost" => "127.0.0.1",
        other => other,
    }
}

fn ssh_service_name(
    bind_interface: Option<&str>,
    listen_port: u16,
    connect_host: &str,
    connect_port: u16,
) -> String {
    format!(
        "ssh:{}:{}:{}:{}",
        canonical_host_token(bind_interface.unwrap_or("127.0.0.1")),
        listen_port,
        canonical_host_token(connect_host),
        connect_port
    )
}

fn implicit_forward_name(index: usize) -> String {
    format!("{IMPLICIT_FORWARD_PREFIX}-{index}")
}

impl LocalSpec {
    fn looks_like_ssh(parts: &[&str]) -> bool {
        matches!(parts, [listen_port, _, _] if is_candidate_port(listen_port))
            || matches!(parts, [_, listen_port, _, _] if is_candidate_port(listen_port))
    }

    fn parse_ssh(parts: &[&str]) -> Result<Self> {
        match parts {
            [listen_port, connect_host, connect_port] => {
                let listen_port = parse_port(listen_port)?;
                let connect_port = parse_port(connect_port)?;
                Ok(Self {
                    name: ssh_service_name(None, listen_port, connect_host, connect_port),
                    local_listen_port: Some(listen_port),
                    remote_connect_port: Some(connect_port),
                    bind_interface: None,
                })
            },
            [bind_interface, listen_port, connect_host, connect_port] => {
                let listen_port = parse_port(listen_port)?;
                let connect_port = parse_port(connect_port)?;
                Ok(Self {
                    name: ssh_service_name(
                        Some(bind_interface),
                        listen_port,
                        connect_host,
                        connect_port,
                    ),
                    local_listen_port: Some(listen_port),
                    remote_connect_port: Some(connect_port),
                    bind_interface: Some((*bind_interface).to_string()),
                })
            },
            _ => Err(Error::Usage(
                "ssh-style local specs must be [bind_address:]port:host:hostport".into(),
            )),
        }
    }

    pub fn parse_listen(input: &str, index: usize) -> Result<Self> {
        if input.contains('[') || input.contains(']') {
            return Err(Error::Usage("IPv6 specifiers are not supported yet".into()));
        }

        let parts: Vec<_> = input.split(':').collect();
        match parts.as_slice() {
            [listen_port] => Ok(Self {
                name: implicit_forward_name(index),
                local_listen_port: Some(parse_port(listen_port)?),
                remote_connect_port: None,
                bind_interface: None,
            }),
            [bind_interface, listen_port] if !bind_interface.is_empty() => Ok(Self {
                name: implicit_forward_name(index),
                local_listen_port: Some(parse_port(listen_port)?),
                remote_connect_port: None,
                bind_interface: Some((*bind_interface).to_string()),
            }),
            _ => Err(Error::Usage(
                "listen specs must be port or bind_address:port".into(),
            )),
        }
    }

    pub fn parse(input: &str) -> Result<Self> {
        if input.contains('[') || input.contains(']') {
            return Err(Error::Usage("IPv6 specifiers are not supported yet".into()));
        }

        let parts: Vec<_> = input.split(':').collect();
        if parts.len() > 4 {
            return Err(Error::Usage(format!(
                "too many colon-separated segments in local spec: {input}"
            )));
        }
        if !input.contains('=') && Self::looks_like_ssh(&parts) {
            return Self::parse_ssh(&parts);
        }

        let mut parts = parts.into_iter();
        let name = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(|| Error::Usage("local spec must include a service name".into()))?
            .to_string();
        let rest: Vec<_> = parts.collect();

        match rest.len() {
            0 => Ok(Self {
                name,
                local_listen_port: None,
                remote_connect_port: None,
                bind_interface: None,
            }),
            1 => Ok(Self {
                name,
                local_listen_port: Some(parse_port(rest[0])?),
                remote_connect_port: None,
                bind_interface: None,
            }),
            _ => {
                let local_listen_port = Some(parse_port(rest[0])?);
                let mut remote_connect_port = None;
                let mut bind_interface = None;
                for item in &rest[1..] {
                    let (key, value) = item.split_once('=').ok_or_else(|| {
                        Error::Usage(format!(
                            "local spec item \"{item}\" must use key=value syntax"
                        ))
                    })?;
                    match key {
                        "remote-connect" => remote_connect_port = Some(parse_port(value)?),
                        "bind" => bind_interface = Some(value.to_string()),
                        _ => {
                            return Err(Error::Usage(
                                "local spec only accepts remote-connect= and bind=".into(),
                            ));
                        },
                    }
                }
                Ok(Self {
                    name,
                    local_listen_port,
                    remote_connect_port,
                    bind_interface,
                })
            },
        }
    }
}

impl RemoteSpec {
    fn looks_like_ssh(parts: &[&str]) -> bool {
        matches!(parts, [listen_port, _, _] if is_candidate_port(listen_port))
            || matches!(parts, [_, listen_port, _, _] if is_candidate_port(listen_port))
    }

    fn parse_ssh(parts: &[&str]) -> Result<Self> {
        match parts {
            [listen_port, connect_host, connect_port] => {
                let listen_port = parse_port(listen_port)?;
                let connect_port = parse_port(connect_port)?;
                Ok(Self {
                    name: ssh_service_name(None, listen_port, connect_host, connect_port),
                    local_connect_port: Some(connect_port),
                    remote_listen_port: Some(listen_port),
                    connect_address: Some((*connect_host).to_string()),
                })
            },
            [bind_interface, listen_port, connect_host, connect_port] => {
                let listen_port = parse_port(listen_port)?;
                let connect_port = parse_port(connect_port)?;
                Ok(Self {
                    name: ssh_service_name(
                        Some(bind_interface),
                        listen_port,
                        connect_host,
                        connect_port,
                    ),
                    local_connect_port: Some(connect_port),
                    remote_listen_port: Some(listen_port),
                    connect_address: Some((*connect_host).to_string()),
                })
            },
            _ => Err(Error::Usage(
                "ssh-style remote specs must be [bind_address:]port:host:hostport".into(),
            )),
        }
    }

    pub fn parse_connect(input: &str, index: usize) -> Result<Self> {
        if input.contains('[') || input.contains(']') {
            return Err(Error::Usage("IPv6 specifiers are not supported yet".into()));
        }

        let parts: Vec<_> = input.split(':').collect();
        match parts.as_slice() {
            [connect_host, connect_port] if !connect_host.is_empty() => Ok(Self {
                name: implicit_forward_name(index),
                local_connect_port: Some(parse_port(connect_port)?),
                remote_listen_port: None,
                connect_address: Some((*connect_host).to_string()),
            }),
            _ => Err(Error::Usage("connect specs must be host:port".into())),
        }
    }

    pub fn parse(input: &str) -> Result<Self> {
        if input.contains('[') || input.contains(']') {
            return Err(Error::Usage("IPv6 specifiers are not supported yet".into()));
        }

        let parts: Vec<_> = input.split(':').collect();
        if parts.len() > 4 {
            return Err(Error::Usage(format!(
                "too many colon-separated segments in remote spec: {input}"
            )));
        }
        if !input.contains('=') && Self::looks_like_ssh(&parts) {
            return Self::parse_ssh(&parts);
        }

        let mut parts = parts.into_iter();
        let name = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(|| Error::Usage("remote spec must include a service name".into()))?
            .to_string();
        let rest: Vec<_> = parts.collect();

        match rest.len() {
            0 => Ok(Self {
                name,
                local_connect_port: None,
                remote_listen_port: None,
                connect_address: None,
            }),
            1 => Ok(Self {
                name,
                local_connect_port: Some(parse_port(rest[0])?),
                remote_listen_port: None,
                connect_address: None,
            }),
            _ => {
                let local_connect_port = Some(parse_port(rest[0])?);
                let mut remote_listen_port = None;
                let mut connect_address = None;
                for item in &rest[1..] {
                    let (key, value) = item.split_once('=').ok_or_else(|| {
                        Error::Usage(format!(
                            "remote spec item \"{item}\" must use key=value syntax"
                        ))
                    })?;
                    match key {
                        "listen" => remote_listen_port = Some(parse_port(value)?),
                        "address" => connect_address = Some(value.to_string()),
                        _ => {
                            return Err(Error::Usage(
                                "remote spec only accepts listen= and address=".into(),
                            ));
                        },
                    }
                }
                Ok(Self {
                    name,
                    local_connect_port,
                    remote_listen_port,
                    connect_address,
                })
            },
        }
    }
}
