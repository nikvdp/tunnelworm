use async_std::prelude::*;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use crate::error::Result;

#[cfg(unix)]
pub type AsyncStream = async_std::os::unix::net::UnixStream;
#[cfg(unix)]
pub type AsyncListener = async_std::os::unix::net::UnixListener;
#[cfg(unix)]
pub type StdStream = std::os::unix::net::UnixStream;

#[cfg(windows)]
pub type AsyncStream = async_std::net::TcpStream;
#[cfg(windows)]
pub type AsyncListener = async_std::net::TcpListener;
#[cfg(windows)]
pub type StdStream = std::net::TcpStream;

pub fn endpoint_path(state_path: &Path) -> PathBuf {
    let base = std::env::temp_dir().join("tunnelworm-control");
    let hash = fnv1a64(state_path.to_string_lossy().as_bytes());
    #[cfg(unix)]
    {
        base.join(format!("{hash:016x}.sock"))
    }
    #[cfg(windows)]
    {
        base.join(format!("{hash:016x}.addr"))
    }
}

pub fn cleanup_endpoint(state_path: &Path) {
    let _ = fs::remove_file(endpoint_path(state_path));
}

pub fn bind_listener(state_path: &Path) -> Result<AsyncListener> {
    let endpoint = endpoint_path(state_path);
    if let Some(parent) = endpoint.parent() {
        fs::create_dir_all(parent)?;
    }
    if endpoint.exists() {
        let _ = fs::remove_file(&endpoint);
    }

    #[cfg(unix)]
    {
        Ok(async_std::task::block_on(AsyncListener::bind(&endpoint))?)
    }
    #[cfg(windows)]
    {
        let listener = async_std::task::block_on(AsyncListener::bind(("127.0.0.1", 0)))?;
        let addr = listener.local_addr()?;
        fs::write(&endpoint, format!("127.0.0.1:{}", addr.port()))?;
        Ok(listener)
    }
}

pub async fn accept(listener: &AsyncListener) -> std::io::Result<AsyncStream> {
    #[cfg(unix)]
    {
        let (stream, _) = listener.accept().await?;
        Ok(stream)
    }
    #[cfg(windows)]
    {
        let (stream, _) = listener.accept().await?;
        Ok(stream)
    }
}

pub fn connect_sync(state_path: &Path) -> std::io::Result<StdStream> {
    #[cfg(unix)]
    {
        StdStream::connect(endpoint_path(state_path))
    }
    #[cfg(windows)]
    {
        Ok(StdStream::connect(read_endpoint_addr(&endpoint_path(
            state_path,
        ))?)?)
    }
}

pub async fn connect_async(state_path: &Path) -> std::io::Result<AsyncStream> {
    #[cfg(unix)]
    {
        AsyncStream::connect(endpoint_path(state_path)).await
    }
    #[cfg(windows)]
    {
        Ok(AsyncStream::connect(read_endpoint_addr(&endpoint_path(state_path))?).await?)
    }
}

pub fn write_request_sync(stream: &StdStream, request: &[u8]) -> Result<()> {
    let mut writer = stream;
    writer.write_all(request)?;
    writer.flush()?;
    Ok(())
}

pub fn read_response_line_sync(stream: StdStream) -> Result<Option<String>> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(line))
}

pub async fn write_request_async(stream: &mut AsyncStream, request: &[u8]) -> Result<()> {
    stream.write_all(request).await?;
    stream.flush().await?;
    Ok(())
}

pub fn stale_connect_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    )
}

#[cfg(windows)]
fn read_endpoint_addr(endpoint: &Path) -> std::io::Result<String> {
    let addr = fs::read_to_string(endpoint)?;
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "local tunnel control endpoint file at {} was empty",
                endpoint.display()
            ),
        ));
    }
    Ok(addr.to_string())
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
