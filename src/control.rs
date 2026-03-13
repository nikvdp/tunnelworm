use async_std::{
    io::{BufReader, prelude::*},
    os::unix::net::UnixListener,
    task,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    persistent::{TunnelRuntimePhase, TunnelRuntimeStatus, load_state, runtime_status_path},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ControlRequest {
    Probe {},
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ControlResponse {
    Probe {
        tunnel_name: String,
        code: String,
        runtime: TunnelRuntimeStatus,
    },
    Error {
        message: String,
    },
}

pub struct ControlServer {
    socket_path: PathBuf,
}

impl ControlServer {
    pub fn spawn(state_path: &Path) -> Result<Self> {
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
                task::spawn(async move {
                    let _ = handle_stream(stream, &state_path).await;
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

fn is_stale_control_socket(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    )
}

pub fn control_socket_path(state_path: &Path) -> PathBuf {
    state_path.with_extension("control.sock")
}

async fn handle_stream(stream: async_std::os::unix::net::UnixStream, state_path: &Path) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    if line.trim().is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<ControlRequest>(&line) {
        Ok(ControlRequest::Probe {}) => {
            let state = load_state(state_path)?;
            let runtime = current_runtime(state_path)?;
            ControlResponse::Probe {
                tunnel_name: state.config.name,
                code: state.config.code,
                runtime,
            }
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
