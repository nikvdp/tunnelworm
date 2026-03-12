use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};

use crate::{
    cli::{stdout_style, FowlConfig, TunnelStatusConfig, TunnelUpConfig},
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
    pub name: String,
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
        if self.config.name != expected.name {
            return Err(Error::PersistentState(format!(
                "state file is bound to tunnel {:?}, not {:?}",
                self.config.name, expected.name
            )));
        }
        if self.config.code != expected.code {
            return Err(Error::PersistentState(format!(
                "state file is bound to code {:?}, not {:?}",
                self.config.code, expected.code
            )));
        }
        if self.config.mailbox != expected.mailbox {
            return Err(Error::PersistentState(
                "state file mailbox does not match the requested mailbox".into(),
            ));
        }
        if self.config.role != expected.role {
            return Err(Error::PersistentState(format!(
                "state file role is {:?}, not {:?}",
                self.config.role, expected.role
            )));
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
            Error::Usage("persistent mode requires an explicit wormhole code on the joining side".into())
        })?;
        Ok(Self::from_fowl_join_config(config, code))
    }

    pub fn from_fowl_join_config(config: &FowlConfig, code: String) -> Self {
        Self {
            name: persistent_name(config, &code),
            code,
            mailbox: config.mailbox.clone(),
            role: PersistentRole::Join,
            locals: config.locals.clone(),
            remotes: config.remotes.clone(),
        }
    }

    pub fn from_fowl_allocate_config(config: &FowlConfig, code: String) -> Self {
        Self {
            name: persistent_name(config, &code),
            code,
            mailbox: config.mailbox.clone(),
            role: PersistentRole::Allocate,
            locals: config.locals.clone(),
            remotes: config.remotes.clone(),
        }
    }
}

pub async fn create_named_tunnel(config: &FowlConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let tunnel_name = config
        .tunnel_name
        .as_deref()
        .ok_or_else(|| Error::Usage("tunnel create needs a local tunnel name".into()))?;

    if let Some((existing_path, _)) = find_state_by_name(&cwd, tunnel_name)? {
        if !config.overwrite {
            return Err(Error::PersistentState(format!(
                "a saved tunnel named {:?} already exists at {}. Use `fowl tunnel up {}` to start it, `fowl tunnel delete {}` to remove it later, or rerun `fowl tunnel create {}` with --overwrite to replace it.",
                tunnel_name,
                existing_path.display(),
                tunnel_name,
                tunnel_name,
                tunnel_name
            )));
        }
        println!("Overwriting existing persistent state at {}.", existing_path.display());
        fs::remove_file(existing_path)?;
    }

    if let Some(code) = &config.code {
        let expected = PersistentConfig::from_fowl_join_config(config, code.clone());
        let state_path = resolve_state_path(config.state.as_deref(), &cwd, &expected)?;
        print_tunnel_intro(&style, "Tunnel create:", &expected.code, config);
        print_state_block(&style, config, &state_path, &expected.code);
        println!();
        println!("{} waiting for the persistent peer...", style.status("Status:"));
        let mut state = PersistentState::new(expected, persistent_auth::generate_identity());
        let prepared = session::prepare_session(SessionOptions::from(config)).await?;
        let mut connected = prepared.connect().await?;
        session::authenticate_persistent_peer(&mut connected, &mut state).await?;
        save_state(&state_path, &state)?;
        return exec_persistent_daemon(&state_path);
    }

    if let Some(path) = config.state.as_deref() {
        if path.exists() {
            let state = load_state(path)?;
            if matches_creator_config(&state, config) && !config.overwrite {
                print_tunnel_intro(&style, "Persistent reuse:", &state.config.code, config);
                print_state_block(&style, config, path, &state.config.code);
                println!();
                println!("{} handing off to the persistent worker...", style.status("Status:"));
                return exec_persistent_daemon(path);
            }
            if !matches_creator_config(&state, config) && !config.overwrite {
                return Err(conflicting_state_error(
                    path,
                    "explicit persistent state does not match this creator command",
                ));
            }
            println!("Overwriting existing persistent state at {}.", path.display());
            fs::remove_file(path)?;
        }
    } else if let Some((state_path, state)) = find_existing_creator_state(&cwd, config)? {
        if !config.overwrite {
            print_tunnel_intro(&style, "Persistent reuse:", &state.config.code, config);
            print_state_block(&style, config, &state_path, &state.config.code);
            println!();
            println!("{} handing off to the persistent worker...", style.status("Status:"));
            return exec_persistent_daemon(&state_path);
        }
        println!("Overwriting existing persistent state at {}.", state_path.display());
        fs::remove_file(&state_path)?;
    }

    let prepared = session::prepare_session(SessionOptions::from(config)).await?;
    let expected = PersistentConfig::from_fowl_allocate_config(config, prepared.code.clone());
    let state_path = resolve_state_path(config.state.as_deref(), &cwd, &expected)?;
    print_tunnel_intro(&style, "Tunnel create:", &prepared.code, config);
    print_state_block(&style, config, &state_path, &prepared.code);
    println!();
    println!("{} waiting for the persistent peer...", style.status("Status:"));
    let mut state = PersistentState::new(expected, persistent_auth::generate_identity());
    let mut connected = prepared.connect().await?;
    session::authenticate_persistent_peer(&mut connected, &mut state).await?;
    save_state(&state_path, &state)?;
    exec_persistent_daemon(&state_path)
}

pub fn up_named_tunnel(config: &TunnelUpConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let (state_path, state) = resolve_named_state(config.state.as_deref(), config.name.as_deref(), &cwd)?;
    let replay_config = FowlConfig {
        tunnel_name: Some(state.config.name.clone()),
        mailbox: state.config.mailbox.clone(),
        code_length: 2,
        code: Some(state.config.code.clone()),
        locals: state.config.locals.clone(),
        remotes: state.config.remotes.clone(),
        state: Some(state_path.clone()),
        overwrite: false,
    };
    print_tunnel_intro(&style, "Persistent reuse:", &state.config.code, &replay_config);
    print_state_block(&style, &replay_config, &state_path, &state.config.code);
    println!();
    println!("{} handing off to the persistent worker...", style.status("Status:"));
    exec_persistent_daemon(&state_path)
}

pub fn print_status(config: &TunnelStatusConfig) -> Result<()> {
    let style = stdout_style();
    let cwd = env::current_dir()?;
    let (state_path, state) = resolve_status_state(config.state.as_deref(), config.code.as_deref(), &cwd)?;

    println!("{} {}", style.heading("Persistent state:"), state.config.name);
    println!("{} {}", style.heading("Local:"), local_forward_role_label(&state.config));
    println!();
    println!("{}", style.heading("State"));
    println!("  {} {}", style.label("name:"), state.config.name);
    println!("  {}", style.label("file:"));
    println!("    {}", state_path.display());
    println!("  {} {}", style.label("reuse:"), FowlConfig::persistent_reuse_command(&state_path));
    println!("  {} {}", style.label("bootstrap:"), bootstrap_role_label(state.config.role));
    println!("  {} {}", style.label("endpoint:"), local_endpoint_label(&state.config));
    println!(
        "  {} {}",
        style.label("mailbox:"),
        state
            .config
            .mailbox
            .as_deref()
            .unwrap_or("the default rendezvous server")
    );
    println!(
        "  {} {}",
        style.label("peer key:"),
        peer_key_fingerprint(state.peer_public_key_hex.as_deref())
    );

    Ok(())
}

fn find_existing_creator_state(cwd: &Path, config: &FowlConfig) -> Result<Option<(PathBuf, PersistentState)>> {
    let mut matches = Vec::new();
    for dir in [project_state_dir(cwd), user_state_dir()?] {
        if !dir.exists() {
            continue;
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(state) = load_state(&path) else {
                continue;
            };
            if matches_creator_config(&state, config) {
                matches.push((path, state));
            }
        }
    }

    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.into_iter().next()),
        _ => Err(Error::PersistentState(
            "multiple persistent creator states match this command; use --state to pick one or --overwrite with --state to replace a specific file"
                .into(),
        )),
    }
}

fn find_state_by_name(cwd: &Path, name: &str) -> Result<Option<(PathBuf, PersistentState)>> {
    let mut matches = Vec::new();
    for dir in [project_state_dir(cwd), user_state_dir()?] {
        if !dir.exists() {
            continue;
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(state) = load_state(&path) else {
                continue;
            };
            if state.config.name == name {
                matches.push((path, state));
            }
        }
    }

    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.into_iter().next()),
        _ => Err(Error::PersistentState(format!(
            "multiple saved tunnel endpoints use the local name {:?}; use --state to select one specific file",
            name
        ))),
    }
}

fn matches_creator_config(state: &PersistentState, config: &FowlConfig) -> bool {
    state.version == STATE_VERSION
        && state.config.role == PersistentRole::Allocate
        && state.config.mailbox == config.mailbox
        && state.config.locals == config.locals
        && state.config.remotes == config.remotes
}

fn matches_local_participant(state: &PersistentState, config: &FowlConfig, code: &str) -> bool {
    state.version == STATE_VERSION
        && state.config.code == code
        && state.config.mailbox == config.mailbox
        && state.config.locals == config.locals
        && state.config.remotes == config.remotes
}

fn resolve_status_state(
    explicit: Option<&Path>,
    code: Option<&str>,
    cwd: &Path,
) -> Result<(PathBuf, PersistentState)> {
    if let Some(path) = explicit {
        if !path.exists() {
            return Err(Error::PersistentState(format!(
                "persistent state file not found at {}",
                path.display()
            )));
        }
        let state = load_state(path).map_err(|error| match error {
            Error::SerdeJson(_) | Error::PersistentState(_) => Error::PersistentState(format!(
                "could not read persistent state at {}: {error}",
                path.display()
            )),
            other => other,
        })?;
        return Ok((path.to_path_buf(), state));
    }

    let code = code.ok_or_else(|| {
        Error::PersistentState("tunnel status needs either --state or --code".into())
    })?;
    let mut matches = Vec::new();

    for dir in [project_state_dir(cwd), user_state_dir()?] {
        if !dir.exists() {
            continue;
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(state) = load_state(&path) else {
                continue;
            };
            if state.config.name == code || state.config.code == code {
                matches.push((path, state));
            }
        }
    }

    match matches.len() {
        0 => Err(Error::PersistentState(format!(
            "no persistent state was found for tunnel {:?}; rerun `fowl tunnel up` or point `fowl tunnel status` at a specific file with --state",
            code
        ))),
        1 => Ok(matches.into_iter().next().expect("one match must exist")),
        _ => {
            let paths = matches
                .iter()
                .map(|(path, _)| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            Err(Error::PersistentState(format!(
                "multiple persistent state files use tunnel {:?}: {}. Rerun with --state to inspect one specific local participant.",
                code, paths
            )))
        },
    }
}

fn resolve_named_state(
    explicit: Option<&Path>,
    name: Option<&str>,
    cwd: &Path,
) -> Result<(PathBuf, PersistentState)> {
    if let Some(path) = explicit {
        if !path.exists() {
            return Err(Error::PersistentState(format!(
                "persistent state file not found at {}",
                path.display()
            )));
        }
        let state = load_state(path).map_err(|error| match error {
            Error::SerdeJson(_) | Error::PersistentState(_) => Error::PersistentState(format!(
                "could not read persistent state at {}: {error}",
                path.display()
            )),
            other => other,
        })?;
        return Ok((path.to_path_buf(), state));
    }

    let name = name.ok_or_else(|| {
        Error::PersistentState("tunnel up needs either a tunnel name or --state".into())
    })?;
    find_state_by_name(cwd, name)?.ok_or_else(|| {
        Error::PersistentState(format!(
            "no saved tunnel endpoint named {:?} was found; create it first with `fowl tunnel create {}` or point `fowl tunnel up` at a specific file with --state",
            name, name
        ))
    })
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

fn load_matching_join_state(path: &Path, expected: &PersistentConfig) -> Result<PersistentState> {
    let state = load_matching_state(path, expected).map_err(|error| match error {
        Error::PersistentState(message) => conflicting_state_error(path, &message),
        other => other,
    })?;
    if state.peer_public_key_hex.is_none() {
        return Err(conflicting_state_error(
            path,
            "existing persistent state is missing the trusted peer identity",
        ));
    }
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
    let slug = slugify_tunnel_name(&config.name);
    let fingerprint = serde_json::to_vec(&(&config.name, &config.mailbox, &config.locals, &config.remotes))
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

fn conflicting_state_error(path: &Path, detail: &str) -> Error {
    Error::PersistentState(format!(
        "{detail} at {}. Rerun with --overwrite to replace this local state, or use --state to select a different file.",
        path.display()
    ))
}

fn bootstrap_role_label(role: PersistentRole) -> &'static str {
    match role {
        PersistentRole::Allocate => "creator",
        PersistentRole::Join => "joiner",
    }
}

fn local_forward_role_label(config: &PersistentConfig) -> &'static str {
    match (!config.locals.is_empty(), !config.remotes.is_empty()) {
        (true, false) => "listen",
        (false, true) => "connect",
        (true, true) => "mixed",
        (false, false) => "none",
    }
}

fn local_endpoint_label(config: &PersistentConfig) -> String {
    if let Some(local) = config.locals.first() {
        let host = local
            .bind_interface
            .as_deref()
            .unwrap_or("127.0.0.1");
        let port = local
            .local_listen_port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "<auto>".into());
        return format!("{host}:{port}");
    }

    if let Some(remote) = config.remotes.first() {
        let host = remote
            .connect_address
            .as_deref()
            .unwrap_or("127.0.0.1");
        let port = remote
            .local_connect_port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "<auto>".into());
        return format!("{host}:{port}");
    }

    "<none>".into()
}

fn peer_key_fingerprint(peer_public_key_hex: Option<&str>) -> String {
    match peer_public_key_hex {
        Some(peer_public_key_hex) => peer_public_key_hex.chars().take(16).collect(),
        None => "<unpaired>".into(),
    }
}

fn print_tunnel_intro(
    style: &crate::cli::AnsiStyle,
    heading: &str,
    code: &str,
    config: &FowlConfig,
) {
    println!("{} {}", style.heading(heading), code);
    if let Some(tunnel_name) = &config.tunnel_name {
        println!("{} {}", style.heading("Tunnel:"), tunnel_name);
    }
    println!("{} {}", style.heading("Local:"), config.local_summary());
    if let (Some(preferred), Some(ssh_style)) = (
        config.peer_preferred_command(code, true),
        config.peer_ssh_command(code),
    ) {
        println!();
        println!("{}", style.heading("Peer commands"));
        println!("  {} {}", style.label("preferred:"), preferred);
        println!("  {} {}", style.label("ssh-style:"), ssh_style);
    }
}

fn persistent_name(config: &FowlConfig, code: &str) -> String {
    config
        .tunnel_name
        .clone()
        .unwrap_or_else(|| code.to_string())
}

fn slugify_tunnel_name(name: &str) -> String {
    let slug = name
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch.to_ascii_lowercase(),
            '-' | '_' => '-',
            _ => '-',
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();

    if slug.is_empty() {
        "tunnel".into()
    } else {
        slug
    }
}

fn print_state_block(
    style: &crate::cli::AnsiStyle,
    config: &FowlConfig,
    state_path: &Path,
    code: &str,
) {
    println!();
    println!("{}", style.heading("State"));
    println!("  {}", style.label("file:"));
    println!("    {}", state_path.display());
    if let Some(tunnel_name) = &config.tunnel_name {
        println!(
            "  {} fowl tunnel up {}",
            style.label("reuse:"),
            tunnel_name
        );
    } else {
        println!(
            "  {} {}",
            style.label("reuse:"),
            FowlConfig::persistent_reuse_command(state_path)
        );
    }
    if let Some(reset_command) = config.persistent_reset_command(code) {
        println!("  {} {}", style.label("reset:"), reset_command);
    }
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
