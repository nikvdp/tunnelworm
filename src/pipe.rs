use std::io::IsTerminal;

use async_std::{io, os::unix::net::UnixStream, prelude::*};
use serde::{Deserialize, Serialize};

use crate::{
    cli::stderr_style,
    control::{ControlRequest, control_socket_path},
    error::{Error, Result},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PipeMode {
    Send,
    Receive,
}

pub fn infer_pipe_mode(explicit: Option<PipeMode>) -> Result<PipeMode> {
    if let Some(mode) = explicit {
        return Ok(mode);
    }

    let stdin_tty = std::io::stdin().is_terminal();
    let stdout_tty = std::io::stdout().is_terminal();
    match (stdin_tty, stdout_tty) {
        (false, true) => Ok(PipeMode::Send),
        (true, false) => Ok(PipeMode::Receive),
        (true, true) => Ok(PipeMode::Receive),
        (false, false) => Err(Error::Usage(
            "pipe mode is ambiguous when both stdin and stdout are redirected; rerun with --send or --receive"
                .into(),
        )),
    }
}

pub async fn run_pipe(state_path: &std::path::Path, mode: PipeMode) -> Result<()> {
    let mut stream = UnixStream::connect(control_socket_path(state_path))
        .await
        .map_err(|error| {
            Error::Session(format!(
                "could not connect to the local tunnel control socket: {error}"
            ))
        })?;
    let request = serde_json::to_string(&ControlRequest::Pipe { mode })?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    let mut reader = stream.clone();
    let mut writer = stream;
    let mut stdout = io::stdout();
    let style = stderr_style();

    eprintln!(
        "{} {} mode over the named tunnel...",
        style.status("Status:"),
        match mode {
            PipeMode::Send => "starting pipe send",
            PipeMode::Receive => "starting pipe receive",
        }
    );

    match mode {
        PipeMode::Send => {
            let mut stdin = io::stdin();
            let send_task = async_std::task::spawn(async move {
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    let read = stdin.read(&mut buffer).await?;
                    if read == 0 {
                        writer.shutdown(std::net::Shutdown::Write)?;
                        return Ok::<(), Error>(());
                    }
                    writer.write_all(&buffer[..read]).await?;
                    writer.flush().await?;
                }
            });
            let recv_task = async_std::task::spawn(async move {
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    let read = reader.read(&mut buffer).await?;
                    if read == 0 {
                        return Ok::<(), Error>(());
                    }
                    stdout.write_all(&buffer[..read]).await?;
                    stdout.flush().await?;
                }
            });
            send_task.await?;
            recv_task.await?;
        },
        PipeMode::Receive => loop {
            let mut buffer = vec![0u8; 16 * 1024];
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            stdout.write_all(&buffer[..read]).await?;
            stdout.flush().await?;
        },
    }
    Ok(())
}
