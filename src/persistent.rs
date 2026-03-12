use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};

use crate::{
    cli::FowlConfig,
    error::{Error, Result},
    persistent_auth,
    session::{self, SessionOptions},
    spec::{LocalSpec, RemoteSpec},
};

const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PersistentRole {
    Allocate,
    Join,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentKeyMaterial {
    pub public_key_hex: String,
    pub secret_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentConfig {
    pub code: String,
    pub mailbox: Option<String>,
    pub role: PersistentRole,
    pub locals: Vec<LocalSpec>,
    pub remotes: Vec<RemoteSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentState {
    pub version: u32,
    pub config: PersistentConfig,
    pub local_identity: PersistentKeyMaterial,
    pub peer_public_key_hex: Option<String>,
}

impl PersistentState {
    pub fn new(config: PersistentConfig, local_identity: PersistentKeyMaterial) -> Self {
        Self {
            version: STATE_VERSION,
            config,
            local_identity,
            peer_public_key_hex: None,
        }
    }

    pub fn ensure_matches(&self, expected: &PersistentConfig) -> Result<()> {
        if self.version != STATE_VERSION {
            return Err(Error::PersistentState(format!(
                "unsupported state version {}; expected {}",
                self.version, STATE_VERSION
            )));
        }
        if self.config.code != expected.code {
            return Err(Error::PersistentState(format!(
                "state file is bound to code {:?}, not {:?}",
                self.config.code, expected.code
            )));
        }
        if self.config.role != expected.role {
            return Err(Error::PersistentState(format!(
                "state file is bound to role {:?}, not {:?}",
                self.config.role, expected.role
            )));
        }
        if self.config.mailbox != expected.mailbox {
            return Err(Error::PersistentState(
                "state file mailbox does not match the requested mailbox".into(),
            ));
        }
        if self.config.locals != expected.locals || self.config.remotes != expected.remotes {
            return Err(Error::PersistentState(
                "state file forwarding rules do not match the requested command".into(),
            ));
        }
        Ok(())
    }
}

impl PersistentConfig {
    pub fn from_fowl_config(config: &FowlConfig) -> Result<Self> {
        let code = config.code.clone().ok_or_else(|| {
            Error::Usage("persistent mode requires an explicit wormhole code".into())
        })?;
        let role = match (config.locals.is_empty(), config.remotes.is_empty()) {
            (false, true) => PersistentRole::Join,
            (true, false) => PersistentRole::Allocate,
            _ => {
                return Err(Error::Usage(
                    "persistent mode currently requires exactly one of --local/-L or --remote/-R".into(),
                ));
            },
        };
        Ok(Self {
            code,
            mailbox: config.mailbox.clone(),
            role,
            locals: config.locals.clone(),
            remotes: config.remotes.clone(),
        })
    }
}

pub async fn initialize_or_exec(config: &FowlConfig) -> Result<()> {
    let expected = config.persistent_config()?;
    let cwd = env::current_dir()?;
    let state_path = resolve_state_path(config.state.as_deref(), &cwd, &expected)?;

    if state_path.exists() {
        let state = load_matching_state(&state_path, &expected)?;
        if state.peer_public_key_hex.is_none() {
            return Err(Error::PersistentState(
                "existing persistent state is missing the trusted peer identity".into(),
            ));
        }
        return exec_persistent_daemon(&state_path);
    }

    let mut state = PersistentState::new(expected, persistent_auth::generate_identity());
    let prepared = session::prepare_session(SessionOptions::from(config)).await?;
    let mut connected = prepared.connect().await?;
    session::authenticate_persistent_peer(&mut connected, &mut state).await?;
    save_state(&state_path, &state)?;
    exec_persistent_daemon(&state_path)
}

pub fn resolve_state_path(
    explicit: Option<&Path>,
    cwd: &Path,
    config: &PersistentConfig,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }

    let file_name = state_file_name(config)?;
    let project_path = project_state_dir(cwd).join(&file_name);
    if project_path.exists() {
        return Ok(project_path);
    }

    let user_path = user_state_dir()?.join(file_name);
    if user_path.exists() {
        return Ok(user_path);
    }

    if dir_is_writable(cwd) {
        return Ok(project_path);
    }

    Ok(user_path)
}

pub fn load_matching_state(path: &Path, expected: &PersistentConfig) -> Result<PersistentState> {
    let state = load_state(path)?;
    state.ensure_matches(expected)?;
    Ok(state)
}

pub fn load_state(path: &Path) -> Result<PersistentState> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn save_state(path: &Path, state: &PersistentState) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::PersistentState(format!("state path {:?} has no parent directory", path))
    })?;
    fs::create_dir_all(parent)?;
    write_with_restrictive_permissions(path, serde_json::to_vec_pretty(state)?)
}

pub fn state_file_name(config: &PersistentConfig) -> Result<String> {
    let slug = config
        .code
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch.to_ascii_lowercase(),
            '-' | '_' => '-',
            _ => '-',
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let slug = if slug.is_empty() { "code".into() } else { slug };
    let fingerprint = serde_json::to_vec(config)
        .map_err(|error| Error::PersistentState(format!("could not fingerprint state config: {error}")))?;
    Ok(format!("{slug}--{:016x}.json", fnv1a64(&fingerprint)))
}

pub fn project_state_dir(cwd: &Path) -> PathBuf {
    cwd.join(".fowl")
}

pub fn user_state_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let base = env::var_os("APPDATA").ok_or_else(|| {
            Error::PersistentState("APPDATA is not set; cannot resolve the user state directory".into())
        })?;
        return Ok(PathBuf::from(base).join("fowl"));
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME").ok_or_else(|| {
            Error::PersistentState("HOME is not set; cannot resolve the user state directory".into())
        })?;
        return Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("fowl"));
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(xdg_state_home) = env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(xdg_state_home).join("fowl"));
        }
        let home = env::var_os("HOME").ok_or_else(|| {
            Error::PersistentState("HOME is not set; cannot resolve the user state directory".into())
        })?;
        Ok(PathBuf::from(home).join(".local").join("state").join("fowl"))
    }
}

fn dir_is_writable(path: &Path) -> bool {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    !metadata.permissions().readonly()
}

fn write_with_restrictive_permissions(path: &Path, bytes: Vec<u8>) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn exec_persistent_daemon(state_path: &Path) -> Result<()> {
    let daemon_path = persistent_daemon_path()?;
    let mut command = Command::new(&daemon_path);
    command.arg("--persistent-state").arg(state_path);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        return Err(Error::Io(command.exec()));
    }

    #[cfg(not(unix))]
    {
        let status = command.status()?;
        if status.success() {
            return Ok(());
        }
        Err(Error::PersistentState(format!(
            "persistent daemon {:?} exited with status {}",
            daemon_path, status
        )))
    }
}

fn persistent_daemon_path() -> Result<PathBuf> {
    let current_exe = env::current_exe()?;
    let sibling = current_exe.with_file_name("fowld");
    if sibling.exists() {
        return Ok(sibling);
    }
    Ok(PathBuf::from("fowld"))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
