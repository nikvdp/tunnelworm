use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSpec {
    pub name: String,
    pub local_listen_port: Option<u16>,
    pub remote_connect_port: Option<u16>,
    pub bind_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl LocalSpec {
    pub fn parse(input: &str) -> Result<Self> {
        if input.contains('[') || input.contains(']') {
            return Err(Error::Usage("IPv6 specifiers are not supported yet".into()));
        }

        let mut parts = input.split(':');
        let name = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(|| Error::Usage("local spec must include a service name".into()))?
            .to_string();
        let rest: Vec<_> = parts.collect();
        if rest.len() > 3 {
            return Err(Error::Usage(format!("too many colon-separated segments in local spec: {input}")));
        }

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
                        }
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
    pub fn parse(input: &str) -> Result<Self> {
        if input.contains('[') || input.contains(']') {
            return Err(Error::Usage("IPv6 specifiers are not supported yet".into()));
        }

        let mut parts = input.split(':');
        let name = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(|| Error::Usage("remote spec must include a service name".into()))?
            .to_string();
        let rest: Vec<_> = parts.collect();
        if rest.len() > 3 {
            return Err(Error::Usage(format!("too many colon-separated segments in remote spec: {input}")));
        }

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
                        }
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
