use std::{
    env,
    fs,
    io::{self, Cursor, Write},
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use serde::Deserialize;
use tempfile::TempDir;

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
    let repo = env::var("TUNNELWORM_UPDATE_REPO").unwrap_or_else(|_| DEFAULT_UPDATE_REPO.to_string());
    let current_exe = env::current_exe()?;
    let current_dir = current_exe.parent().ok_or_else(|| {
        Error::Update(format!(
            "could not determine the parent directory for {}",
            current_exe.display()
        ))
    })?;
    let sibling_daemon_path = current_dir.join(binary_file_name("tunnelwormd"));

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
    let archive = download_asset(&asset.browser_download_url)?;
    let extracted = unpack_release_asset(asset, &archive)?;

    let new_tunnelworm = find_extracted_binary(extracted.path(), &binary_file_name("tunnelworm"))?;
    let new_tunnelwormd =
        find_extracted_optional_binary(extracted.path(), &binary_file_name("tunnelwormd"))?;

    if sibling_daemon_path.exists() {
        if let Some(new_tunnelwormd) = new_tunnelwormd.as_deref() {
            replace_sibling_binary(&sibling_daemon_path, new_tunnelwormd)?;
            println!(
                "{} updated sibling daemon at {}",
                style.status("Status:"),
                sibling_daemon_path.display()
            );
        } else {
            println!(
                "{} release archive did not contain {}; leaving the sibling daemon alone",
                style.status("Status:"),
                binary_file_name("tunnelwormd")
            );
        }
    }

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
        .header("User-Agent", format!("tunnelworm/{}", env!("CARGO_PKG_VERSION")))
        .send()?
        .error_for_status()?;
    Ok(response.json()?)
}

fn download_asset(url: &str) -> Result<Vec<u8>> {
    let client = Client::builder().build()?;
    let response = client
        .get(url)
        .header("User-Agent", format!("tunnelworm/{}", env!("CARGO_PKG_VERSION")))
        .send()?
        .error_for_status()?;
    Ok(response.bytes()?.to_vec())
}

fn unpack_release_asset(asset: &ReleaseAsset, bytes: &[u8]) -> Result<TempDir> {
    let temp_dir = tempfile::tempdir()?;
    if asset.name.ends_with(".tar.gz") {
        let decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(temp_dir.path())?;
        return Ok(temp_dir);
    }

    if asset.name.ends_with(".zip") {
        let reader = Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)?;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index)?;
            let Some(relative_path) = file.enclosed_name().map(PathBuf::from) else {
                continue;
            };
            let destination = temp_dir.path().join(relative_path);
            if file.is_dir() {
                fs::create_dir_all(&destination)?;
                continue;
            }
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut output = fs::File::create(&destination)?;
            io::copy(&mut file, &mut output)?;
        }
        return Ok(temp_dir);
    }

    Err(Error::Update(format!(
        "unsupported release archive format for {:?}",
        asset.name
    )))
}

fn find_extracted_binary(root: &Path, file_name: &str) -> Result<PathBuf> {
    find_extracted_optional_binary(root, file_name)?.ok_or_else(|| {
        Error::Update(format!(
            "release archive did not contain {:?}",
            file_name
        ))
    })
}

fn find_extracted_optional_binary(root: &Path, file_name: &str) -> Result<Option<PathBuf>> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let child = entry.path();
            if child.is_dir() {
                stack.push(child);
                continue;
            }
            if child.file_name().and_then(|name| name.to_str()) == Some(file_name) {
                return Ok(Some(child));
            }
        }
    }
    Ok(None)
}

fn replace_sibling_binary(target: &Path, source: &Path) -> Result<()> {
    let parent = target.parent().ok_or_else(|| {
        Error::Update(format!(
            "could not determine the parent directory for {}",
            target.display()
        ))
    })?;
    let temp_target = parent.join(format!(
        ".{}.update",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("tunnelwormd")
    ));

    let mut input = fs::File::open(source)?;
    let mut output = fs::File::create(&temp_target)?;
    io::copy(&mut input, &mut output)?;
    output.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = fs::metadata(source)?.permissions();
        fs::set_permissions(&temp_target, fs::Permissions::from_mode(permissions.mode()))?;
    }

    match fs::rename(&temp_target, target) {
        Ok(()) => Ok(()),
        Err(_) => {
            if target.exists() {
                fs::remove_file(target)?;
            }
            fs::rename(&temp_target, target)?;
            Ok(())
        },
    }
}

fn release_asset_name() -> Result<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Ok("tunnelworm-linux-x86_64-musl.tar.gz"),
        ("linux", "aarch64") => Ok("tunnelworm-linux-aarch64-musl.tar.gz"),
        ("macos", "x86_64") => Ok("tunnelworm-macos-x86_64.tar.gz"),
        ("macos", "aarch64") => Ok("tunnelworm-macos-aarch64.tar.gz"),
        ("windows", "x86_64") => Ok("tunnelworm-windows-x86_64.zip"),
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
            "tunnelwormd" => "tunnelwormd.exe".to_string(),
            _ => base.to_string(),
        };
    }

    #[cfg(not(target_os = "windows"))]
    {
        base.to_string()
    }
}
