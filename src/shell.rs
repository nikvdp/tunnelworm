use std::{
    sync::mpsc,
    thread,
};

use async_channel::Sender;
use async_std::{
    io::{ReadExt, WriteExt},
    os::unix::net::UnixStream,
    task,
};
use futures::{FutureExt, select};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    mux::MuxChannel,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellOpen {
    pub command: Option<String>,
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShellPacket {
    Started { pid: Option<u32> },
    Input { data: Vec<u8> },
    Output { data: Vec<u8> },
    Resize { rows: u16, cols: u16 },
    Exit { code: u32, signal: Option<String> },
    Error { message: String },
}

pub async fn bridge_local_shell_stream(
    stream: UnixStream,
    channel: MuxChannel,
) -> Result<()> {
    let mut reader = stream.clone();
    let mut writer = stream;
    let send_channel = channel.clone();

    let send_task = task::spawn(async move {
        loop {
            let Some(packet) = read_stream_packet(&mut reader).await? else {
                send_channel.close().await?;
                return Ok::<(), Error>(());
            };
            send_channel_packet(&send_channel, &packet).await?;
            if matches!(packet, ShellPacket::Exit { .. }) {
                send_channel.close().await?;
                return Ok(());
            }
        }
    });

    let recv_task = task::spawn(async move {
        while let Some(packet) = recv_channel_packet(&channel).await? {
            let is_exit = matches!(packet, ShellPacket::Exit { .. });
            write_stream_packet(&mut writer, &packet).await?;
            if is_exit {
                return Ok::<(), Error>(());
            }
        }
        Ok::<(), Error>(())
    });

    send_task.await?;
    recv_task.await?;
    Ok(())
}

pub async fn run_remote_shell(channel: MuxChannel, open: ShellOpen) -> Result<()> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: open.rows,
            cols: open.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| Error::Session(format!("could not allocate a remote PTY: {error}")))?;
    let mut cmd = shell_command(&open.command)?;
    if let Ok(cwd) = std::env::current_dir() {
        cmd.cwd(cwd.as_os_str());
    }
    cmd.env("TERM", "xterm-256color");

    let child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|error| Error::Session(format!("could not spawn the remote shell: {error}")))?;
    let pid = child.process_id();
    let mut killer = child.clone_killer();
    let master = pair.master;
    let pty_reader = master
        .try_clone_reader()
        .map_err(|error| Error::Session(format!("could not read from the remote PTY: {error}")))?;
    let pty_writer = master
        .take_writer()
        .map_err(|error| Error::Session(format!("could not write to the remote PTY: {error}")))?;

    let (writer_tx, writer_rx) = mpsc::channel::<WriterCommand>();
    let (event_tx, event_rx) = async_channel::unbounded::<ShellRuntimeEvent>();

    spawn_shell_writer(writer_rx, pty_writer);
    spawn_shell_reader(pty_reader, event_tx.clone());
    spawn_shell_waiter(child, event_tx.clone());

    send_channel_packet(&channel, &ShellPacket::Started { pid }).await?;

    loop {
        let event_fut = event_rx.recv().fuse();
        let packet_fut = recv_channel_packet(&channel).fuse();
        futures::pin_mut!(event_fut, packet_fut);

        select! {
            event = event_fut => match event {
                Ok(ShellRuntimeEvent::Output(data)) => {
                    send_channel_packet(&channel, &ShellPacket::Output { data }).await?;
                },
                Ok(ShellRuntimeEvent::Exit { code, signal }) => {
                    send_channel_packet(&channel, &ShellPacket::Exit { code, signal }).await?;
                    channel.close().await?;
                    return Ok(());
                },
                Ok(ShellRuntimeEvent::Error(message)) => {
                    send_channel_packet(&channel, &ShellPacket::Error { message }).await?;
                    channel.close().await?;
                    return Ok(());
                },
                Err(_) => {
                    channel.close().await?;
                    return Ok(());
                },
            },
            packet = packet_fut => match packet? {
                Some(ShellPacket::Input { data }) => {
                    writer_tx
                        .send(WriterCommand::Input(data))
                        .map_err(|_| Error::Session("remote shell input writer has stopped".into()))?;
                },
                Some(ShellPacket::Resize { rows, cols }) => {
                    master
                        .resize(PtySize {
                            rows,
                            cols,
                            pixel_width: 0,
                            pixel_height: 0,
                        })
                        .map_err(|error| Error::Session(format!("could not resize the remote PTY: {error}")))?;
                },
                Some(ShellPacket::Exit { .. }) | None => {
                    let _ = writer_tx.send(WriterCommand::Close);
                    let _ = killer.kill();
                    channel.close().await?;
                    return Ok(());
                },
                Some(ShellPacket::Started { .. }) | Some(ShellPacket::Output { .. }) => {},
                Some(ShellPacket::Error { message }) => {
                    let _ = writer_tx.send(WriterCommand::Close);
                    let _ = killer.kill();
                    return Err(Error::Session(message));
                },
            }
        }
    }
}

pub async fn send_channel_packet(channel: &MuxChannel, packet: &ShellPacket) -> Result<()> {
    let bytes = bincode::serialize(packet)
        .map_err(|error| Error::Session(format!("could not encode a shell packet: {error}")))?;
    channel.send(bytes).await
}

pub async fn recv_channel_packet(channel: &MuxChannel) -> Result<Option<ShellPacket>> {
    let Some(bytes) = channel.recv().await? else {
        return Ok(None);
    };
    let packet = bincode::deserialize(&bytes)
        .map_err(|error| Error::Session(format!("could not decode a shell packet: {error}")))?;
    Ok(Some(packet))
}

pub async fn write_stream_packet<W>(writer: &mut W, packet: &ShellPacket) -> Result<()>
where
    W: WriteExt + Unpin,
{
    let bytes = bincode::serialize(packet)
        .map_err(|error| Error::Session(format!("could not encode a shell packet: {error}")))?;
    let len = (bytes.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_stream_packet<R>(reader: &mut R) -> Result<Option<ShellPacket>>
where
    R: ReadExt + Unpin,
{
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes).await?;
    let packet = bincode::deserialize(&bytes)
        .map_err(|error| Error::Session(format!("could not decode a shell packet: {error}")))?;
    Ok(Some(packet))
}

fn shell_command(command: &Option<String>) -> Result<CommandBuilder> {
    let shell = CommandBuilder::new_default_prog();
    if let Some(command) = command {
        let program = shell
            .get_env("SHELL")
            .and_then(|value| value.to_str())
            .unwrap_or("/bin/sh")
            .to_string();
        let mut cmd = CommandBuilder::new(program);
        cmd.arg("-lc");
        cmd.arg(command);
        Ok(cmd)
    } else {
        Ok(shell)
    }
}

enum WriterCommand {
    Input(Vec<u8>),
    Close,
}

enum ShellRuntimeEvent {
    Output(Vec<u8>),
    Exit { code: u32, signal: Option<String> },
    Error(String),
}

fn spawn_shell_writer(
    writer_rx: mpsc::Receiver<WriterCommand>,
    mut pty_writer: Box<dyn std::io::Write + Send>,
) {
    thread::spawn(move || {
        while let Ok(command) = writer_rx.recv() {
            match command {
                WriterCommand::Input(data) => {
                    if pty_writer.write_all(&data).is_err() || pty_writer.flush().is_err() {
                        break;
                    }
                },
                WriterCommand::Close => break,
            }
        }
    });
}

fn spawn_shell_reader(
    mut reader: Box<dyn std::io::Read + Send>,
    event_tx: Sender<ShellRuntimeEvent>,
) {
    thread::spawn(move || {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let _ = event_tx.send_blocking(ShellRuntimeEvent::Output(buffer[..read].to_vec()));
                },
                Err(error) => {
                    let _ = event_tx.send_blocking(ShellRuntimeEvent::Error(format!(
                        "could not read from the remote PTY: {error}"
                    )));
                    break;
                },
            }
        }
    });
}

fn spawn_shell_waiter(
    mut child: Box<dyn portable_pty::Child + Send + Sync>,
    event_tx: Sender<ShellRuntimeEvent>,
) {
    thread::spawn(move || match child.wait() {
        Ok(status) => {
            let _ = event_tx.send_blocking(ShellRuntimeEvent::Exit {
                code: status.exit_code(),
                signal: status.signal().map(ToOwned::to_owned),
            });
        },
        Err(error) => {
            let _ = event_tx.send_blocking(ShellRuntimeEvent::Error(format!(
                "could not wait for the remote shell: {error}"
            )));
        },
    });
}
