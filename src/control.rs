use async_std::{
    io::prelude::*,
    os::unix::net::UnixListener,
    task,
};
use async_channel::Sender;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    file_transfer::FileTransferOpen,
    pipe::PipeMode,
    persistent::{ManagedPortDefinition, ManagedPortForward, TunnelRuntimePhase, TunnelRuntimeStatus, load_state, runtime_status_path},
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
        stream: async_std::os::unix::net::UnixStream,
    },
    Shell {
        open: ShellOpen,
        stream: async_std::os::unix::net::UnixStream,
    },
    SendFile {
        open: FileTransferOpen,
        stream: async_std::os::unix::net::UnixStream,
    },
}

pub struct ControlServer {
    socket_path: PathBuf,
}

impl ControlServer {
    pub fn spawn(state_path: &Path, requests: Sender<RuntimeControlRequest>) -> Result<Self> {
        let socket_path = control_socket_path(state_path);
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if socket_path.exists() {
            let _ = fs::remove_file(&socket_path);
        }

        let listener = task::block_on(UnixListener::bind(&socket_path))?;
        let state_path = state_path.to_path_buf();
        task::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
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

    let stream = match std::os::unix::net::UnixStream::connect(&socket_path) {
        Ok(stream) => stream,
        Err(error) if is_stale_control_socket(&error) => return Ok(None),
        Err(error) => {
            return Err(Error::PersistentState(format!(
                "could not connect to the local tunnel control socket at {}: {error}",
                socket_path.display()
            )))
        },
    };
    let mut request = serde_json::to_vec(&ControlRequest::Probe {})?;
    request.push(b'\n');
    {
        use std::io::Write;
        let mut writer = &stream;
        writer.write_all(&request)?;
        writer.flush()?;
    }

    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    use std::io::BufRead;
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Ok(None);
    }

    Ok(Some(serde_json::from_str(&line)?))
}

pub async fn echo_runtime(state_path: &Path, payload: &str) -> Result<Option<String>> {
    let socket_path = control_socket_path(state_path);
    if !socket_path.exists() {
        return Ok(None);
    }

    let mut stream = match async_std::os::unix::net::UnixStream::connect(&socket_path).await {
        Ok(stream) => stream,
        Err(error) if is_stale_control_socket(&error) => return Ok(None),
        Err(error) => {
            return Err(Error::PersistentState(format!(
                "could not connect to the local tunnel control socket at {}: {error}",
                socket_path.display()
            )))
        },
    };
    let mut request = serde_json::to_vec(&ControlRequest::Echo {
        payload: payload.to_string(),
    })?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    stream.flush().await?;

    let line = read_request_line(&mut stream).await?;
    if line.trim().is_empty() {
        return Ok(None);
    }

    match serde_json::from_str::<ControlResponse>(&line)? {
        ControlResponse::Echo { payload } => Ok(Some(payload)),
        ControlResponse::Error { message } => Err(Error::Session(message)),
        ControlResponse::Probe { .. } | ControlResponse::PortsAdded { .. } | ControlResponse::PortsRemoved { .. } => Err(Error::Session(
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

    let mut stream = match async_std::os::unix::net::UnixStream::connect(&socket_path).await {
        Ok(stream) => stream,
        Err(error) if is_stale_control_socket(&error) => return Ok(None),
        Err(error) => {
            return Err(Error::PersistentState(format!(
                "could not connect to the local tunnel control socket at {}: {error}",
                socket_path.display()
            )))
        },
    };
    let mut request = serde_json::to_vec(&ControlRequest::PortsAdd {
        definition: definition.clone(),
    })?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    stream.flush().await?;

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

    let mut stream = match async_std::os::unix::net::UnixStream::connect(&socket_path).await {
        Ok(stream) => stream,
        Err(error) if is_stale_control_socket(&error) => return Ok(None),
        Err(error) => {
            return Err(Error::PersistentState(format!(
                "could not connect to the local tunnel control socket at {}: {error}",
                socket_path.display()
            )))
        },
    };
    let mut request = serde_json::to_vec(&ControlRequest::PortsRemove { id })?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    stream.flush().await?;

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
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    )
}

pub fn control_socket_path(state_path: &Path) -> PathBuf {
    std::env::temp_dir()
        .join("tunnelworm-control")
        .join(format!("{:016x}.sock", fnv1a64(state_path.to_string_lossy().as_bytes())))
}

async fn handle_stream(
    mut stream: async_std::os::unix::net::UnixStream,
    state_path: &Path,
    requests: Sender<RuntimeControlRequest>,
) -> Result<()> {
    let line = read_request_line(&mut stream).await?;
    if line.trim().is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<ControlRequest>(&line) {
        Ok(ControlRequest::Probe {}) => round_trip_runtime_request(
            requests,
            |reply| RuntimeControlRequest::Probe { reply },
            || {
                let state = load_state(state_path)?;
                Ok(ControlResponse::Probe {
                    tunnel_name: state.config.name,
                    code: state.config.code,
                    runtime: current_runtime(state_path)?,
                })
            },
        )
        .await,
        Ok(ControlRequest::Echo { payload }) => round_trip_runtime_request(
            requests,
            move |reply| RuntimeControlRequest::Echo { payload, reply },
            || {
                Err(Error::PersistentState(
                    "the local tunnel runtime is not accepting live control requests yet".into(),
                ))
            },
        )
        .await,
        Ok(ControlRequest::PortsAdd { definition }) => round_trip_runtime_request(
            requests,
            move |reply| RuntimeControlRequest::PortsAdd { definition, reply },
            || {
                Err(Error::PersistentState(
                    "the local tunnel runtime is not accepting port-management requests yet".into(),
                ))
            },
        )
        .await,
        Ok(ControlRequest::PortsRemove { id }) => round_trip_runtime_request(
            requests,
            move |reply| RuntimeControlRequest::PortsRemove { id, reply },
            || {
                Err(Error::PersistentState(
                    "the local tunnel runtime is not accepting port-management requests yet".into(),
                ))
            },
        )
        .await,
        Ok(ControlRequest::Pipe { mode }) => {
            requests
                .send(RuntimeControlRequest::Pipe { mode, stream })
                .await
                .map_err(|_| {
                    Error::Session("the local tunnel runtime is not accepting pipe requests".into())
                })?;
            return Ok(());
        },
        Ok(ControlRequest::Shell { open }) => {
            requests
                .send(RuntimeControlRequest::Shell { open, stream })
                .await
                .map_err(|_| {
                    Error::Session("the local tunnel runtime is not accepting shell requests".into())
                })?;
            return Ok(());
        },
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
        },
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

async fn read_request_line(
    stream: &mut async_std::os::unix::net::UnixStream,
) -> Result<String> {
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
    Ok(String::from_utf8(line).map_err(|error| {
        Error::Session(format!("control request was not valid UTF-8: {error}"))
    })?)
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

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::read_request_line;
    use async_std::{io::{ReadExt, WriteExt}, os::unix::net::UnixStream, task};

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
