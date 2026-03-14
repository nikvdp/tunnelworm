use async_channel::Sender;
use async_std::{io::prelude::*, task};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    file_transfer::FileTransferOpen,
    local_control,
    persistent::{
        ManagedPortDefinition, ManagedPortForward, TunnelRuntimePhase, TunnelRuntimeStatus,
        load_state, runtime_status_path,
    },
    pipe::PipeMode,
    shell::ShellOpen,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ControlRequest {
    Probe {},
    Echo { payload: String },
    Pipe { mode: PipeMode },
    Shell { open: ShellOpen },
    SendFile { open: FileTransferOpen },
    PortsAdd { definition: ManagedPortDefinition },
    PortsRemove { id: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ControlResponse {
    Probe {
        tunnel_name: String,
        code: String,
        runtime: TunnelRuntimeStatus,
        peer_policy_rules: Vec<crate::cli::TunnelPolicyRule>,
    },
    Echo {
        payload: String,
    },
    PortsAdded {
        forward: ManagedPortForward,
    },
    PortsRemoved {
        id: u32,
    },
    Error {
        message: String,
    },
}

#[derive(Debug)]
pub enum RuntimeControlRequest {
    Probe {
        reply: Sender<Result<ControlResponse>>,
    },
    Echo {
        payload: String,
        reply: Sender<Result<ControlResponse>>,
    },
    PortsAdd {
        definition: ManagedPortDefinition,
        reply: Sender<Result<ControlResponse>>,
    },
    PortsRemove {
        id: u32,
        reply: Sender<Result<ControlResponse>>,
    },
    Pipe {
        mode: PipeMode,
        stream: local_control::AsyncStream,
    },
    Shell {
        open: ShellOpen,
        stream: local_control::AsyncStream,
    },
    SendFile {
        open: FileTransferOpen,
        stream: local_control::AsyncStream,
    },
}

pub struct ControlServer {
    socket_path: PathBuf,
}

impl ControlServer {
    pub fn spawn(state_path: &Path, requests: Sender<RuntimeControlRequest>) -> Result<Self> {
        let socket_path = control_socket_path(state_path);
        let listener = local_control::bind_listener(state_path)?;
        let state_path = state_path.to_path_buf();
        task::spawn(async move {
            while let Ok(stream) = local_control::accept(&listener).await {
                let state_path = state_path.clone();
                let requests = requests.clone();
                task::spawn(async move {
                    let _ = handle_stream(stream, &state_path, requests).await;
                });
            }
        });

        Ok(Self { socket_path })
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

pub fn probe_runtime(state_path: &Path) -> Result<Option<ControlResponse>> {
    let socket_path = control_socket_path(state_path);
    if !socket_path.exists() {
        return Ok(None);
    }

    let stream = match local_control::connect_sync(state_path) {
        Ok(stream) => stream,
        Err(error) if is_stale_control_socket(&error) => return Ok(None),
        Err(error) => {
            return Err(Error::PersistentState(format!(
                "could not connect to the local tunnel control socket at {}: {error}",
                socket_path.display()
            )));
        }
    };
    let mut request = serde_json::to_vec(&ControlRequest::Probe {})?;
    request.push(b'\n');
    local_control::write_request_sync(&stream, &request)?;
    Ok(local_control::read_response_line_sync(stream)?
        .map(|line| serde_json::from_str(&line))
        .transpose()?)
}

pub async fn echo_runtime(state_path: &Path, payload: &str) -> Result<Option<String>> {
    let socket_path = control_socket_path(state_path);
    if !socket_path.exists() {
        return Ok(None);
    }

    let mut stream = match local_control::connect_async(state_path).await {
        Ok(stream) => stream,
        Err(error) if is_stale_control_socket(&error) => return Ok(None),
        Err(error) => {
            return Err(Error::PersistentState(format!(
                "could not connect to the local tunnel control socket at {}: {error}",
                socket_path.display()
            )));
        }
    };
    let mut request = serde_json::to_vec(&ControlRequest::Echo {
        payload: payload.to_string(),
    })?;
    request.push(b'\n');
    local_control::write_request_async(&mut stream, &request).await?;

    let line = read_request_line(&mut stream).await?;
    if line.trim().is_empty() {
        return Ok(None);
    }

    match serde_json::from_str::<ControlResponse>(&line)? {
        ControlResponse::Echo { payload } => Ok(Some(payload)),
        ControlResponse::Error { message } => Err(Error::Session(message)),
        ControlResponse::Probe { .. }
        | ControlResponse::PortsAdded { .. }
        | ControlResponse::PortsRemoved { .. } => Err(Error::Session(
            "received an unexpected probe response while checking tunnel readiness".into(),
        )),
    }
}

pub async fn add_port_forward_runtime(
    state_path: &Path,
    definition: &ManagedPortDefinition,
) -> Result<Option<ManagedPortForward>> {
    let socket_path = control_socket_path(state_path);
    if !socket_path.exists() {
        return Ok(None);
    }

    let mut stream = match local_control::connect_async(state_path).await {
        Ok(stream) => stream,
        Err(error) if is_stale_control_socket(&error) => return Ok(None),
        Err(error) => {
            return Err(Error::PersistentState(format!(
                "could not connect to the local tunnel control socket at {}: {error}",
                socket_path.display()
            )));
        }
    };
    let mut request = serde_json::to_vec(&ControlRequest::PortsAdd {
        definition: definition.clone(),
    })?;
    request.push(b'\n');
    local_control::write_request_async(&mut stream, &request).await?;

    let line = read_request_line(&mut stream).await?;
    if line.trim().is_empty() {
        return Ok(None);
    }

    match serde_json::from_str::<ControlResponse>(&line)? {
        ControlResponse::PortsAdded { forward } => Ok(Some(forward)),
        ControlResponse::Error { message } => Err(Error::Session(message)),
        other => Err(Error::Session(format!(
            "received an unexpected control response while adding a port forward: {:?}",
            other
        ))),
    }
}

pub async fn remove_port_forward_runtime(state_path: &Path, id: u32) -> Result<Option<()>> {
    let socket_path = control_socket_path(state_path);
    if !socket_path.exists() {
        return Ok(None);
    }

    let mut stream = match local_control::connect_async(state_path).await {
        Ok(stream) => stream,
        Err(error) if is_stale_control_socket(&error) => return Ok(None),
        Err(error) => {
            return Err(Error::PersistentState(format!(
                "could not connect to the local tunnel control socket at {}: {error}",
                socket_path.display()
            )));
        }
    };
    let mut request = serde_json::to_vec(&ControlRequest::PortsRemove { id })?;
    request.push(b'\n');
    local_control::write_request_async(&mut stream, &request).await?;

    let line = read_request_line(&mut stream).await?;
    if line.trim().is_empty() {
        return Ok(None);
    }

    match serde_json::from_str::<ControlResponse>(&line)? {
        ControlResponse::PortsRemoved { .. } => Ok(Some(())),
        ControlResponse::Error { message } => Err(Error::Session(message)),
        other => Err(Error::Session(format!(
            "received an unexpected control response while removing a port forward: {:?}",
            other
        ))),
    }
}

fn is_stale_control_socket(error: &std::io::Error) -> bool {
    local_control::stale_connect_error(error)
}

pub fn control_socket_path(state_path: &Path) -> PathBuf {
    local_control::endpoint_path(state_path)
}

async fn handle_stream(
    mut stream: local_control::AsyncStream,
    state_path: &Path,
    requests: Sender<RuntimeControlRequest>,
) -> Result<()> {
    let line = read_request_line(&mut stream).await?;
    if line.trim().is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<ControlRequest>(&line) {
        Ok(ControlRequest::Probe {}) => {
            round_trip_runtime_request(
                requests,
                |reply| RuntimeControlRequest::Probe { reply },
                || {
                    let state = load_state(state_path)?;
                    Ok(ControlResponse::Probe {
                        tunnel_name: state.config.name,
                        code: state.config.code,
                        runtime: current_runtime(state_path)?,
                        peer_policy_rules: Vec::new(),
                    })
                },
            )
            .await
        }
        Ok(ControlRequest::Echo { payload }) => {
            round_trip_runtime_request(
                requests,
                move |reply| RuntimeControlRequest::Echo { payload, reply },
                || {
                    Err(Error::PersistentState(
                        "the local tunnel runtime is not accepting live control requests yet"
                            .into(),
                    ))
                },
            )
            .await
        }
        Ok(ControlRequest::PortsAdd { definition }) => {
            round_trip_runtime_request(
                requests,
                move |reply| RuntimeControlRequest::PortsAdd { definition, reply },
                || {
                    Err(Error::PersistentState(
                        "the local tunnel runtime is not accepting port-management requests yet"
                            .into(),
                    ))
                },
            )
            .await
        }
        Ok(ControlRequest::PortsRemove { id }) => {
            round_trip_runtime_request(
                requests,
                move |reply| RuntimeControlRequest::PortsRemove { id, reply },
                || {
                    Err(Error::PersistentState(
                        "the local tunnel runtime is not accepting port-management requests yet"
                            .into(),
                    ))
                },
            )
            .await
        }
        Ok(ControlRequest::Pipe { mode }) => {
            requests
                .send(RuntimeControlRequest::Pipe { mode, stream })
                .await
                .map_err(|_| {
                    Error::Session("the local tunnel runtime is not accepting pipe requests".into())
                })?;
            return Ok(());
        }
        Ok(ControlRequest::Shell { open }) => {
            requests
                .send(RuntimeControlRequest::Shell { open, stream })
                .await
                .map_err(|_| {
                    Error::Session(
                        "the local tunnel runtime is not accepting shell requests".into(),
                    )
                })?;
            return Ok(());
        }
        Ok(ControlRequest::SendFile { open }) => {
            requests
                .send(RuntimeControlRequest::SendFile { open, stream })
                .await
                .map_err(|_| {
                    Error::Session(
                        "the local tunnel runtime is not accepting file transfer requests".into(),
                    )
                })?;
            return Ok(());
        }
        Err(error) => ControlResponse::Error {
            message: format!("invalid control request: {error}"),
        },
    };

    let mut writer = &stream;
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_request_line<S>(stream: &mut S) -> Result<String>
where
    S: async_std::io::Read + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    String::from_utf8(line)
        .map_err(|error| Error::Session(format!("control request was not valid UTF-8: {error}")))
}

async fn round_trip_runtime_request<Fallback, Build>(
    requests: Sender<RuntimeControlRequest>,
    build: Build,
    fallback: Fallback,
) -> ControlResponse
where
    Fallback: FnOnce() -> Result<ControlResponse>,
    Build: FnOnce(Sender<Result<ControlResponse>>) -> RuntimeControlRequest,
{
    let (reply_tx, reply_rx) = async_channel::bounded(1);
    if requests.send(build(reply_tx)).await.is_err() {
        return fallback().unwrap_or_else(error_response);
    }
    match reply_rx.recv().await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => error_response(error),
        Err(_) => fallback().unwrap_or_else(error_response),
    }
}

fn error_response(error: Error) -> ControlResponse {
    ControlResponse::Error {
        message: error.to_string(),
    }
}

fn current_runtime(state_path: &Path) -> Result<TunnelRuntimeStatus> {
    let runtime_path = runtime_status_path(state_path);
    if !runtime_path.exists() {
        return Ok(TunnelRuntimeStatus {
            phase: TunnelRuntimePhase::Starting,
            detail: Some("persistent worker is starting".into()),
        });
    }
    let bytes = fs::read(&runtime_path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::read_request_line;
    use async_std::{
        io::{ReadExt, WriteExt},
        os::unix::net::UnixStream,
        task,
    };

    #[test]
    fn read_request_line_leaves_following_bytes_intact() {
        task::block_on(async {
            let (mut client, mut server) = UnixStream::pair().expect("unix pair should open");
            let writer = task::spawn(async move {
                client
                    .write_all(b"{\"kind\":\"send-file\"}\n\x00\x00\x00\x04ping")
                    .await
                    .expect("request should write");
            });
            let line = read_request_line(&mut server)
                .await
                .expect("request line should parse");
            assert_eq!(line, "{\"kind\":\"send-file\"}\n");
            let mut trailing = [0u8; 8];
            server
                .read_exact(&mut trailing)
                .await
                .expect("binary payload should remain readable");
            assert_eq!(&trailing, b"\x00\x00\x00\x04ping");
            writer.await;
        });
    }
}
