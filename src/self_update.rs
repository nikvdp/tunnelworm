use std::{env, fs, io::Write, path::PathBuf};

use reqwest::blocking::Client;
use serde::Deserialize;
use tempfile::NamedTempFile;

use crate::{
    cli::stdout_style,
    error::{Error, Result},
};

const DEFAULT_UPDATE_API_ROOT: &str = "https://api.github.com";
const DEFAULT_UPDATE_REPO: &str = "nikvdp/tunnelworm";

#[derive(Debug, Deserialize)]
struct ReleaseResponse {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

pub fn run_self_update() -> Result<()> {
    let style = stdout_style();
    let asset_name = release_asset_name()?;
    let api_root = env::var("TUNNELWORM_UPDATE_API_ROOT")
        .unwrap_or_else(|_| DEFAULT_UPDATE_API_ROOT.to_string());
    let repo =
        env::var("TUNNELWORM_UPDATE_REPO").unwrap_or_else(|_| DEFAULT_UPDATE_REPO.to_string());
    let current_exe = env::current_exe()?;

    println!("{} checking for updates...", style.status("Status:"));
    let release = fetch_latest_release(&api_root, &repo)?;
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| {
            Error::Update(format!(
                "release {} does not contain the expected asset {:?}",
                release.tag_name, asset_name
            ))
        })?;

    println!(
        "{} downloading {} from {}...",
        style.status("Status:"),
        asset.name,
        release.tag_name
    );
    let downloaded_binary = download_asset(&asset.browser_download_url)?;
    let new_tunnelworm = write_download_to_temp_binary(&downloaded_binary)?;

    self_replace::self_replace(&new_tunnelworm).map_err(|error| {
        Error::Update(format!(
            "could not replace {}: {error}",
            current_exe.display()
        ))
    })?;

    println!(
        "{} updated {} to {}",
        style.heading("Updated:"),
        binary_file_name("tunnelworm"),
        release.tag_name
    );
    Ok(())
}

fn fetch_latest_release(api_root: &str, repo: &str) -> Result<ReleaseResponse> {
    let client = Client::builder().build()?;
    let url = format!("{api_root}/repos/{repo}/releases/latest");
    let response = client
        .get(&url)
        .header(
            "User-Agent",
            format!("tunnelworm/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()?
        .error_for_status()?;
    Ok(response.json()?)
}

fn download_asset(url: &str) -> Result<Vec<u8>> {
    let client = Client::builder().build()?;
    let response = client
        .get(url)
        .header(
            "User-Agent",
            format!("tunnelworm/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()?
        .error_for_status()?;
    Ok(response.bytes()?.to_vec())
}

fn write_download_to_temp_binary(bytes: &[u8]) -> Result<PathBuf> {
    let mut temp = NamedTempFile::new()?;
    temp.write_all(bytes)?;
    temp.flush()?;
    let path = temp.into_temp_path();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }

    path.keep()
        .map_err(|error| Error::Update(format!("could not persist the downloaded update: {error}")))
}

fn release_asset_name() -> Result<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Ok("tunnelworm-linux-x86_64-musl"),
        ("linux", "aarch64") => Ok("tunnelworm-linux-aarch64-musl"),
        ("macos", "x86_64") => Ok("tunnelworm-macos-x86_64"),
        ("macos", "aarch64") => Ok("tunnelworm-macos-aarch64"),
        ("windows", "x86_64") => Ok("tunnelworm-windows-x86_64.exe"),
        (os, arch) => Err(Error::Update(format!(
            "self-update is not configured for {os}/{arch}"
        ))),
    }
}

fn binary_file_name(base: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        return match base {
            "tunnelworm" => "tunnelworm.exe".to_string(),
            _ => base.to_string(),
        };
    }

    #[cfg(not(target_os = "windows"))]
    {
        base.to_string()
    }
}
