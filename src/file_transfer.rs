use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use async_std::{
    io::{ReadExt, WriteExt},
    task,
};
use serde::{Deserialize, Serialize};

use crate::{
    control::ControlRequest,
    error::{Error, Result},
    local_control::AsyncStream,
    mux::MuxChannel,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileTransferOpen {
    pub source_name: String,
    pub destination_path: Option<String>,
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileTransferPacket {
    Chunk { data: Vec<u8> },
    Done,
    Success { path: String, bytes: u64 },
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTransferResult {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFileTransferSource {
    pub open: FileTransferOpen,
    pub bytes: u64,
}

pub async fn bridge_local_file_stream(stream: AsyncStream, channel: MuxChannel) -> Result<()> {
    let mut reader = stream.clone();
    let mut writer = stream;
    let send_channel = channel.clone();

    let send_task = task::spawn(async move {
        loop {
            let Some(packet) = read_stream_packet(&mut reader).await? else {
                send_channel.close().await?;
                return Ok::<(), Error>(());
            };
            let is_done = matches!(packet, FileTransferPacket::Done);
            send_channel_packet(&send_channel, &packet).await?;
            if is_done {
                return Ok(());
            }
        }
    });

    let recv_task = task::spawn(async move {
        while let Some(packet) = recv_channel_packet(&channel).await? {
            let terminal = matches!(
                packet,
                FileTransferPacket::Success { .. } | FileTransferPacket::Error { .. }
            );
            write_stream_packet(&mut writer, &packet).await?;
            if terminal {
                return Ok::<(), Error>(());
            }
        }
        Ok::<(), Error>(())
    });

    send_task.await?;
    recv_task.await?;
    Ok(())
}

pub async fn run_remote_receive(
    channel: MuxChannel,
    open: FileTransferOpen,
    base_dir: PathBuf,
) -> Result<()> {
    let destination = resolve_destination_path(&base_dir, &open)?;
    ensure_destination_parent(&destination)?;
    let mut file = open_destination_file(&destination, open.overwrite)?;
    let mut bytes_written = 0u64;

    loop {
        match recv_channel_packet(&channel).await? {
            Some(FileTransferPacket::Chunk { data }) => {
                file.write_all(&data)?;
                bytes_written += data.len() as u64;
            }
            Some(FileTransferPacket::Done) => {
                file.flush()?;
                send_channel_packet(
                    &channel,
                    &FileTransferPacket::Success {
                        path: destination.display().to_string(),
                        bytes: bytes_written,
                    },
                )
                .await?;
                channel.close().await?;
                return Ok(());
            }
            Some(FileTransferPacket::Error { message }) => {
                let _ = fs::remove_file(&destination);
                return Err(Error::Session(message));
            }
            Some(FileTransferPacket::Success { .. }) => {
                return Err(Error::Session(
                    "received a file transfer success packet before the transfer finished".into(),
                ));
            }
            None => {
                let _ = fs::remove_file(&destination);
                return Err(Error::Session(
                    "the file transfer ended before the sender finished streaming bytes".into(),
                ));
            }
        }
    }
}

pub async fn run_local_send(
    mut stream: AsyncStream,
    source_path: &Path,
    open: FileTransferOpen,
    total_bytes: u64,
    mut on_progress: impl FnMut(u64, u64) -> Result<()>,
) -> Result<FileTransferResult> {
    let request = serde_json::to_string(&ControlRequest::SendFile { open })?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    let mut source_file = async_std::fs::File::open(source_path).await?;
    let mut buffer = vec![0u8; 16 * 1024];
    let mut sent_bytes = 0u64;
    loop {
        let read = source_file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        write_stream_packet(
            &mut stream,
            &FileTransferPacket::Chunk {
                data: buffer[..read].to_vec(),
            },
        )
        .await?;
        sent_bytes += read as u64;
        on_progress(sent_bytes, total_bytes)?;
    }
    write_stream_packet(&mut stream, &FileTransferPacket::Done).await?;
    on_progress(total_bytes, total_bytes)?;

    match read_stream_packet(&mut stream).await? {
        Some(FileTransferPacket::Success { path, bytes }) => Ok(FileTransferResult { path, bytes }),
        Some(FileTransferPacket::Error { message }) => Err(Error::Session(message)),
        Some(FileTransferPacket::Chunk { .. }) | Some(FileTransferPacket::Done) => {
            Err(Error::Session(
                "received unexpected file transfer data after the local send finished".into(),
            ))
        }
        None => Err(Error::Session(
            "the file transfer ended before the peer confirmed the write".into(),
        )),
    }
}

pub fn prepare_local_source(
    path: &Path,
    destination_path: Option<String>,
    overwrite: bool,
) -> Result<LocalFileTransferSource> {
    let metadata = fs::metadata(path).map_err(|error| {
        Error::Session(format!(
            "could not read the local source file at {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::Usage(format!(
            "source path {} is not a regular file",
            path.display()
        )));
    }
    let source_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Error::Usage(format!("source path {} has no basename", path.display())))?;

    Ok(LocalFileTransferSource {
        open: FileTransferOpen {
            source_name: source_name.to_string(),
            destination_path,
            overwrite,
        },
        bytes: metadata.len(),
    })
}

fn resolve_destination_path(base_dir: &Path, open: &FileTransferOpen) -> Result<PathBuf> {
    let source_name = Path::new(&open.source_name)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Error::Usage("source file name must have a basename".into()))?;

    let destination = match &open.destination_path {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(source_name),
    };

    let resolved = if destination.is_absolute() {
        destination
    } else {
        base_dir.join(destination)
    };

    Ok(resolved)
}

fn ensure_destination_parent(destination: &Path) -> Result<()> {
    let parent = destination.parent().ok_or_else(|| {
        Error::Session(format!(
            "could not determine the destination parent for {}",
            destination.display()
        ))
    })?;
    fs::create_dir_all(parent)?;
    Ok(())
}

fn open_destination_file(destination: &Path, overwrite: bool) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if overwrite {
        options.truncate(true);
    } else {
        options.create_new(true);
    }

    options.open(destination).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Session(format!(
                "destination already exists at {}; rerun with --overwrite to replace it",
                destination.display()
            ))
        } else {
            Error::Io(error)
        }
    })
}

pub async fn send_channel_packet(channel: &MuxChannel, packet: &FileTransferPacket) -> Result<()> {
    let bytes = bincode::serialize(packet).map_err(|error| {
        Error::Session(format!("could not encode a file transfer packet: {error}"))
    })?;
    channel.send(bytes).await
}

pub async fn recv_channel_packet(channel: &MuxChannel) -> Result<Option<FileTransferPacket>> {
    let Some(bytes) = channel.recv().await? else {
        return Ok(None);
    };
    let packet = bincode::deserialize(&bytes).map_err(|error| {
        Error::Session(format!("could not decode a file transfer packet: {error}"))
    })?;
    Ok(Some(packet))
}

pub async fn write_stream_packet<W>(writer: &mut W, packet: &FileTransferPacket) -> Result<()>
where
    W: WriteExt + Unpin,
{
    let bytes = bincode::serialize(packet).map_err(|error| {
        Error::Session(format!("could not encode a file transfer packet: {error}"))
    })?;
    let len = (bytes.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_stream_packet<R>(reader: &mut R) -> Result<Option<FileTransferPacket>>
where
    R: ReadExt + Unpin,
{
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes).await?;
    let packet = bincode::deserialize(&bytes).map_err(|error| {
        Error::Session(format!("could not decode a file transfer packet: {error}"))
    })?;
    Ok(Some(packet))
}
