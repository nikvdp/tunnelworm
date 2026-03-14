use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use async_std::io::WriteExt;
use futures::FutureExt;
use serde::{Deserialize, Serialize};

use crate::{
    cli::{
        TunnelCapability, TunnelConfig, TunnelDeleteConfig, TunnelPipeConfig, TunnelPolicyEffect,
        TunnelPolicyRule, TunnelPortsAddConfig, TunnelPortsListConfig, TunnelPortsRemoveConfig,
        TunnelSendFileConfig, TunnelShellConfig, TunnelStatusConfig, TunnelUpConfig, stdout_style,
    },
    control::{
        ControlResponse, add_port_forward_runtime, control_socket_path, echo_runtime,
        probe_runtime, remove_port_forward_runtime,
    },
    error::{Error, Result},
    file_transfer, persistent_auth, pipe,
    session::{self, SessionOptions},
    shell::{self, ShellOpen},
    spec::{LocalSpec, RemoteSpec},
    status_line::StatusLine,
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
    #[serde(default)]
    pub temporary: bool,
    pub role: PersistentRole,
    pub locals: Vec<LocalSpec>,
    pub remotes: Vec<RemoteSpec>,
    #[serde(default)]
    pub ports: Vec<ManagedPortForward>,
    #[serde(default)]
    pub policy_rules: Vec<TunnelPolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedPortForward {
    pub id: u32,
    pub local_listen_host: Option<String>,
    pub local_listen_port: Option<u16>,
    pub local_connect_host: Option<String>,
    pub local_connect_port: Option<u16>,
    pub remote_listen_host: Option<String>,
    pub remote_listen_port: Option<u16>,
    pub remote_connect_host: Option<String>,
    pub remote_connect_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedPortDefinition {
    pub local_listen_host: Option<String>,
    pub local_listen_port: Option<u16>,
    pub local_connect_host: Option<String>,
    pub local_connect_port: Option<u16>,
    pub remote_listen_host: Option<String>,
    pub remote_listen_port: Option<u16>,
    pub remote_connect_host: Option<String>,
    pub remote_connect_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentState {
    pub version: u32,
    pub config: PersistentConfig,
    pub local_identity: PersistentKeyMaterial,
    pub peer_public_key_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelRuntimePhase {
    Starting,
    Waiting,
    Up,
    Retrying,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelRuntimeStatus {
    pub phase: TunnelRuntimePhase,
    pub detail: Option<String>,
}

impl ManagedPortDefinition {
    pub fn validate(&self) -> Result<()> {
        let local_listen = self.local_listen_port.is_some();
        let local_connect = self.local_connect_port.is_some();
        let remote_listen = self.remote_listen_port.is_some();
        let remote_connect = self.remote_connect_port.is_some();

        if local_listen == local_connect {
            return Err(Error::Usage(
                "ports add needs exactly one local half: --local-listen or --local-connect".into(),
            ));
        }
        if remote_listen == remote_connect {
            return Err(Error::Usage(
                "ports add needs exactly one remote half: --remote-listen or --remote-connect"
                    .into(),
            ));
        }

        match (local_listen, remote_connect, remote_listen, local_connect) {
            (true, true, false, false) | (false, false, true, true) => Ok(()),
            _ => Err(Error::Usage(
                "ports add only supports `--local-listen` with `--remote-connect` or `--remote-listen` with `--local-connect`".into(),
            )),
        }
    }

    pub fn into_forward(self, id: u32) -> ManagedPortForward {
        ManagedPortForward {
            id,
            local_listen_host: self.local_listen_host,
            local_listen_port: self.local_listen_port,
            local_connect_host: self.local_connect_host,
            local_connect_port: self.local_connect_port,
            remote_listen_host: self.remote_listen_host,
            remote_listen_port: self.remote_listen_port,
            remote_connect_host: self.remote_connect_host,
            remote_connect_port: self.remote_connect_port,
        }
    }

    pub fn mirrored(&self) -> Self {
        Self {
            local_listen_host: self.remote_listen_host.clone(),
            local_listen_port: self.remote_listen_port,
            local_connect_host: self.remote_connect_host.clone(),
            local_connect_port: self.remote_connect_port,
            remote_listen_host: self.local_listen_host.clone(),
            remote_listen_port: self.local_listen_port,
            remote_connect_host: self.local_connect_host.clone(),
            remote_connect_port: self.local_connect_port,
        }
    }
}

impl ManagedPortForward {
    pub fn mirrored(&self) -> Self {
        Self {
            id: self.id,
            local_listen_host: self.remote_listen_host.clone(),
            local_listen_port: self.remote_listen_port,
            local_connect_host: self.remote_connect_host.clone(),
            local_connect_port: self.remote_connect_port,
            remote_listen_host: self.local_listen_host.clone(),
            remote_listen_port: self.local_listen_port,
            remote_connect_host: self.local_connect_host.clone(),
            remote_connect_port: self.local_connect_port,
        }
    }

    pub fn summary(&self) -> String {
        if let (Some(listen_host), Some(listen_port), Some(connect_host), Some(connect_port)) = (
            self.local_listen_host.as_deref(),
            self.local_listen_port,
            self.remote_connect_host.as_deref(),
            self.remote_connect_port,
        ) {
            return format!(
                "local listen {}:{} <-> remote connect {}:{}",
                listen_host, listen_port, connect_host, connect_port
            );
        }

        if let (Some(connect_host), Some(connect_port), Some(listen_host), Some(listen_port)) = (
            self.local_connect_host.as_deref(),
            self.local_connect_port,
            self.remote_listen_host.as_deref(),
            self.remote_listen_port,
        ) {
            return format!(
                "local connect {}:{} <-> remote listen {}:{}",
                connect_host, connect_port, listen_host, listen_port
            );
        }

        "invalid managed port forward".into()
    }

    pub fn next_id(forwards: &[ManagedPortForward]) -> u32 {
        forwards
            .iter()
            .map(|forward| forward.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }
}

fn policy_rule_applies(rule: TunnelCapability, capability: TunnelCapability) -> bool {
    match rule {
        TunnelCapability::All => true,
        TunnelCapability::Ports => {
            matches!(
                capability,
                TunnelCapability::Ports | TunnelCapability::RemotePortMgmt
            )
        }
        other => other == capability,
    }
}

pub fn capability_allowed(rules: &[TunnelPolicyRule], capability: TunnelCapability) -> bool {
    let mut allowed = true;
    for rule in rules {
        if policy_rule_applies(rule.capability, capability) {
            allowed = matches!(rule.effect, TunnelPolicyEffect::Allow);
        }
    }
    allowed
}

fn capability_label(capability: TunnelCapability) -> &'static str {
    match capability {
        TunnelCapability::All => "all",
        TunnelCapability::Ports => "ports",
        TunnelCapability::RemotePortMgmt => "remote-port-mgmt",
        TunnelCapability::Shell => "shell",
        TunnelCapability::Pipe => "pipe",
        TunnelCapability::SendFile => "send-file",
    }
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
        if self.config.temporary != expected.temporary {
            return Err(Error::PersistentState(
                "state file lifecycle does not match the requested command".into(),
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
    pub fn from_tunnel_config(config: &TunnelConfig) -> Result<Self> {
        let code = config.code.clone().ok_or_else(|| {
            Error::Usage(
                "persistent mode requires an explicit wormhole code on the joining side".into(),
            )
        })?;
        Ok(Self::from_join_config(config, code))
    }

    pub fn from_join_config(config: &TunnelConfig, code: String) -> Self {
        Self {
            name: persistent_name(config, &code),
            code,
            mailbox: config.mailbox.clone(),
            temporary: false,
            role: PersistentRole::Join,
            locals: config.locals.clone(),
            remotes: config.remotes.clone(),
            ports: Vec::new(),
            policy_rules: config.policy_rules.clone(),
        }
    }

    pub fn from_allocate_config(config: &TunnelConfig, code: String) -> Self {
        Self {
            name: persistent_name(config, &code),
            code,
            mailbox: config.mailbox.clone(),
            temporary: false,
            role: PersistentRole::Allocate,
            locals: config.locals.clone(),
            remotes: config.remotes.clone(),
            ports: Vec::new(),
            policy_rules: config.policy_rules.clone(),
        }
    }
}

fn temporary_config(config: &TunnelConfig, code: String, role: PersistentRole) -> PersistentConfig {
    PersistentConfig {
        name: temporary_tunnel_name(config, &code),
        code,
        mailbox: config.mailbox.clone(),
        temporary: true,
        role,
        locals: config.locals.clone(),
        remotes: config.remotes.clone(),
        ports: Vec::new(),
        policy_rules: config.policy_rules.clone(),
    }
}

pub async fn create_one_off_tunnel(config: &TunnelConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let (code, role) = match &config.code {
        Some(code) => (code.clone(), PersistentRole::Join),
        None => (String::new(), PersistentRole::Allocate),
    };
    let persistent = temporary_config(config, code.clone(), role);
    let state_path = resolve_state_path(None, &cwd, &persistent)?;
    prepare_temporary_state_path(&state_path)?;
    let interrupt = install_frontend_interrupt_notifier()?;
    let mut state = PersistentState::new(persistent.clone(), persistent_auth::generate_identity());
    state.peer_public_key_hex = None;
    save_state(&state_path, &state)?;
    run_temporary_daemon(&state_path, interrupt)
}

pub async fn create_named_tunnel(config: &TunnelConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let tunnel_name = config
        .tunnel_name
        .as_deref()
        .ok_or_else(|| Error::Usage("tunnel create needs a local tunnel name".into()))?;

    if let Some((existing_path, _)) = find_state_by_name(&cwd, tunnel_name)? {
        if !config.overwrite {
            return Err(Error::PersistentState(format!(
                "a saved tunnel named {:?} already exists at {}. Use `tunnelworm tunnel up {}` to start it, `tunnelworm tunnel delete {}` to remove it later, or rerun `tunnelworm tunnel create {}` with --overwrite to replace it.",
                tunnel_name,
                existing_path.display(),
                tunnel_name,
                tunnel_name,
                tunnel_name
            )));
        }
        println!(
            "Overwriting existing persistent state at {}.",
            existing_path.display()
        );
        fs::remove_file(existing_path)?;
    }

    if let Some(code) = &config.code {
        let expected = PersistentConfig::from_join_config(config, code.clone());
        let state_path = resolve_state_path(config.state.as_deref(), &cwd, &expected)?;
        print_tunnel_intro(&style, "Tunnel create:", &expected.code, config);
        print_state_block(&style, config, &state_path, &expected.code);
        println!();
        let mut state = PersistentState::new(expected, persistent_auth::generate_identity());
        let prepared = session::prepare_session(SessionOptions::from(config)).await?;
        let mut connected =
            connect_with_spinner(prepared, "waiting for the persistent peer...").await?;
        session::authenticate_persistent_peer(&mut connected, &mut state).await?;
        save_state(&state_path, &state)?;
        println!("{} starting tunnel...", style.status("Status:"));
        return exec_persistent_daemon(&state_path);
    }

    if let Some(path) = config.state.as_deref() {
        if path.exists() {
            let state = load_state(path)?;
            if matches_creator_config(&state, config) && !config.overwrite {
                print_tunnel_intro(&style, "Persistent reuse:", &state.config.code, config);
                print_state_block(&style, config, path, &state.config.code);
                println!();
                println!("{} starting tunnel...", style.status("Status:"));
                return exec_persistent_daemon(path);
            }
            if !matches_creator_config(&state, config) && !config.overwrite {
                return Err(conflicting_state_error(
                    path,
                    "explicit persistent state does not match this creator command",
                ));
            }
            println!(
                "Overwriting existing persistent state at {}.",
                path.display()
            );
            fs::remove_file(path)?;
        }
    } else if let Some((state_path, state)) = find_existing_creator_state(&cwd, config)? {
        if !config.overwrite {
            print_tunnel_intro(&style, "Persistent reuse:", &state.config.code, config);
            print_state_block(&style, config, &state_path, &state.config.code);
            println!();
            println!("{} starting tunnel...", style.status("Status:"));
            return exec_persistent_daemon(&state_path);
        }
        println!(
            "Overwriting existing persistent state at {}.",
            state_path.display()
        );
        fs::remove_file(&state_path)?;
    }

    let prepared = session::prepare_session(SessionOptions::from(config)).await?;
    let expected = PersistentConfig::from_allocate_config(config, prepared.code.clone());
    let state_path = resolve_state_path(config.state.as_deref(), &cwd, &expected)?;
    print_tunnel_intro(&style, "Tunnel create:", &prepared.code, config);
    print_state_block(&style, config, &state_path, &prepared.code);
    println!();
    let mut state = PersistentState::new(expected, persistent_auth::generate_identity());
    let mut connected =
        connect_with_spinner(prepared, "waiting for the persistent peer...").await?;
    session::authenticate_persistent_peer(&mut connected, &mut state).await?;
    save_state(&state_path, &state)?;
    println!("{} starting tunnel...", style.status("Status:"));
    exec_persistent_daemon(&state_path)
}

async fn connect_with_spinner(
    prepared: session::PreparedSession,
    message: &str,
) -> Result<session::ConnectedSession> {
    let style = stdout_style();
    let mut spinner = StatusLine::stdout();
    let connect_future = prepared.connect().fuse();
    futures::pin_mut!(connect_future);
    loop {
        let tick = async_std::task::sleep(std::time::Duration::from_millis(125)).fuse();
        futures::pin_mut!(tick);
        futures::select! {
            connected = connect_future => {
                spinner.clear()?;
                return connected;
            },
            () = tick => spinner.update(&style.status("Status:"), message)?,
        }
    }
}

pub fn up_named_tunnel(config: &TunnelUpConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let (state_path, state) =
        resolve_named_state(config.state.as_deref(), config.name.as_deref(), &cwd)?;
    let replay_config = TunnelConfig {
        tunnel_name: Some(state.config.name.clone()),
        mailbox: state.config.mailbox.clone(),
        code_length: 2,
        code: Some(state.config.code.clone()),
        policy_rules: state.config.policy_rules.clone(),
        locals: state.config.locals.clone(),
        remotes: state.config.remotes.clone(),
        state: Some(state_path.clone()),
        overwrite: false,
    };
    print_tunnel_intro(
        &style,
        "Persistent reuse:",
        &state.config.code,
        &replay_config,
    );
    print_state_block(&style, &replay_config, &state_path, &state.config.code);
    println!();
    println!("{} starting tunnel...", style.status("Status:"));
    exec_persistent_daemon(&state_path)
}

pub fn list_named_tunnels() -> Result<()> {
    let style = stdout_style();
    let cwd = env::current_dir()?;
    let entries = list_saved_tunnels(&cwd)?;

    println!("{}", style.heading("Saved tunnels"));
    if entries.is_empty() {
        println!("  none");
        return Ok(());
    }

    for (state_path, state) in entries {
        let runtime = current_tunnel_runtime(&state_path)?;
        println!();
        println!("  {}", style.label(&state.config.name));
        println!(
            "    {} {}",
            style.label("role:"),
            local_forward_role_label(&state.config)
        );
        println!(
            "    {} {}",
            style.label("endpoint:"),
            local_endpoint_label(&state.config)
        );
        println!("    {} {}", style.label("state:"), runtime.label());
        if let Some(detail) = runtime.detail() {
            println!("    {} {}", style.label("detail:"), detail);
        }
        println!("    {} {}", style.label("file:"), state_path.display());
    }

    Ok(())
}

pub fn print_status(config: &TunnelStatusConfig) -> Result<()> {
    let style = stdout_style();
    let cwd = env::current_dir()?;
    let (state_path, state) =
        resolve_status_state(config.state.as_deref(), config.name.as_deref(), &cwd)?;

    println!(
        "{} {}",
        style.heading("Persistent state:"),
        state.config.name
    );
    println!(
        "{} {}",
        style.heading("Local:"),
        local_forward_role_label(&state.config)
    );
    println!();
    println!("{}", style.heading("State"));
    println!("  {} {}", style.label("name:"), state.config.name);
    println!("  {}", style.label("file:"));
    println!("    {}", state_path.display());
    println!(
        "  {} tunnelworm tunnel up {}",
        style.label("reuse:"),
        state.config.name
    );
    println!(
        "  {} tunnelworm tunnel delete {}",
        style.label("delete:"),
        state.config.name
    );
    println!(
        "  {} {}",
        style.label("bootstrap:"),
        bootstrap_role_label(state.config.role)
    );
    println!(
        "  {} {}",
        style.label("endpoint:"),
        local_endpoint_label(&state.config)
    );
    let runtime = current_tunnel_runtime(&state_path)?;
    println!("  {} {}", style.label("state:"), runtime.label());
    if let Some(detail) = runtime.detail() {
        println!("  {} {}", style.label("detail:"), detail);
    }
    println!(
        "  {} {}",
        style.label("control:"),
        control_socket_path(&state_path).display()
    );
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
    println!("  {}", style.label("permissions:"));
    for capability in [
        TunnelCapability::Ports,
        TunnelCapability::RemotePortMgmt,
        TunnelCapability::Shell,
        TunnelCapability::Pipe,
        TunnelCapability::SendFile,
    ] {
        let label = if capability_allowed(&state.config.policy_rules, capability) {
            "allowed"
        } else {
            "denied"
        };
        println!("    {}: {}", capability_label(capability), label);
    }

    Ok(())
}

pub fn delete_named_tunnel(config: &TunnelDeleteConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let (state_path, state) =
        resolve_named_state(config.state.as_deref(), config.name.as_deref(), &cwd)?;
    let lock_path = state_path.with_extension("lock");

    fs::remove_file(&state_path)?;
    if lock_path.exists() {
        let _ = fs::remove_file(&lock_path);
    }

    let style = stdout_style();
    println!("{} {}", style.heading("Deleted:"), state.config.name);
    println!("  {} {}", style.label("file:"), state_path.display());

    Ok(())
}

pub async fn run_named_pipe(config: &TunnelPipeConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let (state_path, _state, correction) =
        resolve_live_tunnel_handle(config.state.as_deref(), config.name.as_deref(), &cwd)?;
    if let Some(correction) = correction {
        eprintln!("{} {correction}", style.label("Resolved:"));
    }
    wait_for_live_tunnel_ready(&state_path, config.name.as_deref()).await?;
    if let Some(ControlResponse::Probe {
        peer_policy_rules, ..
    }) = probe_runtime(&state_path)?
        && !capability_allowed(&peer_policy_rules, TunnelCapability::Pipe)
    {
        return Err(Error::Session(
            "the remote tunnel policy denies pipe".into(),
        ));
    }
    let mode = pipe::infer_pipe_mode(config.mode)?;
    pipe::run_pipe(&state_path, mode).await
}

pub async fn run_named_shell(config: &TunnelShellConfig) -> Result<u32> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let (state_path, _state, correction) =
        resolve_live_tunnel_handle(config.state.as_deref(), config.name.as_deref(), &cwd)?;
    if let Some(correction) = correction {
        eprintln!("{} {correction}", style.label("Resolved:"));
    }
    wait_for_live_tunnel_ready(&state_path, config.name.as_deref()).await?;
    let mut stream =
        async_std::os::unix::net::UnixStream::connect(control_socket_path(&state_path))
            .await
            .map_err(|error| {
                Error::Session(format!(
                    "could not connect to the local tunnel control socket: {error}"
                ))
            })?;
    let (rows, cols) = shell::current_terminal_size();
    let request = serde_json::to_string(&crate::control::ControlRequest::Shell {
        open: ShellOpen {
            command: config.command.clone(),
            rows,
            cols,
        },
    })?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    shell::run_local_shell_client(stream).await
}

pub async fn run_named_send_file(config: &TunnelSendFileConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let (state_path, state, correction) =
        resolve_live_tunnel_handle(None, Some(&config.name), &cwd)?;
    if let Some(correction) = correction {
        eprintln!("{} {correction}", style.label("Resolved:"));
    }
    wait_for_live_tunnel_ready(&state_path, Some(&config.name)).await?;
    let source_path = if config.source.is_absolute() {
        config.source.clone()
    } else {
        cwd.join(&config.source)
    };
    let prepared = file_transfer::prepare_local_source(
        &source_path,
        config
            .destination
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        config.overwrite,
    )?;
    let stream = async_std::os::unix::net::UnixStream::connect(control_socket_path(&state_path))
        .await
        .map_err(|error| {
            Error::Session(format!(
                "could not connect to the local tunnel control socket: {error}"
            ))
        })?;
    let mut status = StatusLine::stdout();
    let source_label = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file")
        .to_string();
    let result = file_transfer::run_local_send(
        stream,
        &source_path,
        prepared.open,
        prepared.bytes,
        |sent, total| {
            let percent = if total == 0 {
                100usize
            } else {
                ((sent.saturating_mul(100)) / total) as usize
            };
            let filled = if total == 0 {
                24usize
            } else {
                ((sent.saturating_mul(24)) / total) as usize
            };
            let bar = format!(
                "{}{}",
                "█".repeat(filled.min(24)),
                "·".repeat(24usize.saturating_sub(filled.min(24)))
            );
            let message = format!(
                "sending {source_label} [{}] {:>3}% ({}/{})",
                bar,
                percent.min(100),
                human_bytes(sent),
                human_bytes(total)
            );
            status.update(&style.status("Status:"), &message)?;
            Ok(())
        },
    )
    .await;
    status.clear()?;
    let result = result?;
    println!(
        "{} {} -> {} ({})",
        style.heading("Sent:"),
        source_path.display(),
        result.path,
        human_bytes(result.bytes)
    );
    println!("{} {}", style.label("Tunnel:"), state.config.name);
    Ok(())
}

fn parse_port_endpoint(input: &str, flag: &str) -> Result<(String, u16)> {
    if let Ok(port) = input.parse::<u16>() {
        if port == 0 {
            return Err(Error::Usage(format!("{flag} must be between 1 and 65535")));
        }
        return Ok(("127.0.0.1".into(), port));
    }

    let (host, port) = input.split_once(':').ok_or_else(|| {
        Error::Usage(format!("{flag} must be a port or host:port, got {input:?}"))
    })?;
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::Usage(format!("{flag} must end with a valid port, got {input:?}")))?;
    if port == 0 {
        return Err(Error::Usage(format!("{flag} must be between 1 and 65535")));
    }
    let host = match host {
        "localhost" => "127.0.0.1".into(),
        other => other.to_string(),
    };
    Ok((host, port))
}

fn build_managed_port_definition(config: &TunnelPortsAddConfig) -> Result<ManagedPortDefinition> {
    let (local_listen_host, local_listen_port) = match config.local_listen.as_deref() {
        Some(value) => {
            let (host, port) = parse_port_endpoint(value, "--local-listen")?;
            (Some(host), Some(port))
        }
        None => (None, None),
    };
    let (local_connect_host, local_connect_port) = match config.local_connect.as_deref() {
        Some(value) => {
            let (host, port) = parse_port_endpoint(value, "--local-connect")?;
            (Some(host), Some(port))
        }
        None => (None, None),
    };
    let (remote_listen_host, remote_listen_port) = match config.remote_listen.as_deref() {
        Some(value) => {
            let (host, port) = parse_port_endpoint(value, "--remote-listen")?;
            (Some(host), Some(port))
        }
        None => (None, None),
    };
    let (remote_connect_host, remote_connect_port) = match config.remote_connect.as_deref() {
        Some(value) => {
            let (host, port) = parse_port_endpoint(value, "--remote-connect")?;
            (Some(host), Some(port))
        }
        None => (None, None),
    };
    let definition = ManagedPortDefinition {
        local_listen_host,
        local_listen_port,
        local_connect_host,
        local_connect_port,
        remote_listen_host,
        remote_listen_port,
        remote_connect_host,
        remote_connect_port,
    };
    definition.validate()?;
    Ok(definition)
}

pub fn list_tunnel_ports(config: &TunnelPortsListConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let (state_path, state, correction) =
        resolve_live_tunnel_handle(config.state.as_deref(), config.name.as_deref(), &cwd)?;
    if let Some(correction) = correction {
        eprintln!("{} {correction}", style.label("Resolved:"));
    }
    let runtime = current_tunnel_runtime(&state_path)?;
    println!("{}", style.heading("Ports"));
    println!("  {} {}", style.label("tunnel:"), state.config.name);
    println!("  {} {}", style.label("runtime:"), runtime.label());
    if state.config.ports.is_empty() {
        println!("  none");
        return Ok(());
    }
    let state_label = if matches!(
        runtime,
        ResolvedTunnelRuntime::Live(TunnelRuntimeStatus {
            phase: TunnelRuntimePhase::Up,
            ..
        })
    ) {
        "active"
    } else {
        "pending"
    };
    for forward in &state.config.ports {
        println!("  - {}: {} ({state_label})", forward.id, forward.summary());
    }
    Ok(())
}

pub async fn add_tunnel_port(config: &TunnelPortsAddConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let (state_path, _state, correction) =
        resolve_live_tunnel_handle(config.state.as_deref(), config.name.as_deref(), &cwd)?;
    if let Some(correction) = correction {
        eprintln!("{} {correction}", style.label("Resolved:"));
    }
    wait_for_live_tunnel_ready(&state_path, config.name.as_deref()).await?;
    let definition = build_managed_port_definition(config)?;
    let forward = add_port_forward_runtime(&state_path, &definition)
        .await?
        .ok_or_else(|| {
            Error::Session("the local tunnel runtime stopped before the port was added".into())
        })?;
    println!("{} {}", style.heading("Added:"), forward.id);
    println!("  {} {}", style.label("mapping:"), forward.summary());
    Ok(())
}

pub async fn remove_tunnel_port(config: &TunnelPortsRemoveConfig) -> Result<()> {
    let cwd = env::current_dir()?;
    let style = stdout_style();
    let (state_path, _state, correction) =
        resolve_live_tunnel_handle(config.state.as_deref(), config.name.as_deref(), &cwd)?;
    if let Some(correction) = correction {
        eprintln!("{} {correction}", style.label("Resolved:"));
    }
    wait_for_live_tunnel_ready(&state_path, config.name.as_deref()).await?;
    remove_port_forward_runtime(&state_path, config.id)
        .await?
        .ok_or_else(|| {
            Error::Session("the local tunnel runtime stopped before the port was removed".into())
        })?;
    println!("{} {}", style.heading("Removed:"), config.id);
    Ok(())
}

fn find_existing_creator_state(
    cwd: &Path,
    config: &TunnelConfig,
) -> Result<Option<(PathBuf, PersistentState)>> {
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
    let matches = list_saved_tunnels(cwd)?
        .into_iter()
        .filter(|(_, state)| state.config.name == name)
        .collect::<Vec<_>>();

    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.into_iter().next()),
        _ => Err(Error::PersistentState(format!(
            "multiple saved tunnel endpoints use the local name {:?}; use --state to select one specific file",
            name
        ))),
    }
}

fn matches_creator_config(state: &PersistentState, config: &TunnelConfig) -> bool {
    state.version == STATE_VERSION
        && state.config.role == PersistentRole::Allocate
        && state.config.mailbox == config.mailbox
        && state.config.locals == config.locals
        && state.config.remotes == config.remotes
}

fn resolve_status_state(
    explicit: Option<&Path>,
    name: Option<&str>,
    cwd: &Path,
) -> Result<(PathBuf, PersistentState)> {
    resolve_named_state(explicit, name, cwd).map_err(|error| match error {
        Error::PersistentState(message) if message.contains("tunnel up needs either") => {
            Error::PersistentState("tunnel status needs either a tunnel name or --state".into())
        }
        other => other,
    })
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
            "no saved tunnel endpoint named {:?} was found; create it first with `tunnelworm tunnel create {}` or point `tunnelworm tunnel up` at a specific file with --state",
            name, name
        ))
    })
}

fn resolve_live_tunnel_handle(
    explicit: Option<&Path>,
    handle: Option<&str>,
    cwd: &Path,
) -> Result<(PathBuf, PersistentState, Option<String>)> {
    if let Some(path) = explicit {
        let (state_path, state) = resolve_named_state(Some(path), None, cwd)?;
        return Ok((state_path, state, None));
    }

    let handle = handle.ok_or_else(|| {
        Error::PersistentState("a live tunnel command needs either a tunnel name or --state".into())
    })?;

    if let Some((state_path, state)) = find_state_by_name(cwd, handle)?
        && matches!(
            current_tunnel_runtime(&state_path)?,
            ResolvedTunnelRuntime::Live(_)
        )
    {
        return Ok((state_path, state, None));
    }

    if let Some((state_path, state)) = find_live_temporary_state_by_code(cwd, handle)? {
        return Ok((
            state_path,
            state.clone(),
            Some(format!(
                "code {} matched local tunnel {}.",
                handle, state.config.name
            )),
        ));
    }

    Err(Error::PersistentState(format!(
        "no live tunnel matched local name or shared code {:?}; start the one-off tunnel first, use `tunnelworm tunnel up <name>`, or pass --state",
        handle
    )))
}

async fn wait_for_live_tunnel_ready(state_path: &Path, handle: Option<&str>) -> Result<()> {
    let style = stdout_style();
    let mut spinner = StatusLine::stdout();
    let probe_payload = "__tunnelworm_ready_probe__";
    loop {
        match current_tunnel_runtime(state_path)? {
            ResolvedTunnelRuntime::Stopped => {
                spinner.clear()?;
                let target = handle.unwrap_or_else(|| {
                    state_path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("tunnel")
                });
                return Err(Error::Session(format!("tunnel {target:?} is not running")));
            }
            ResolvedTunnelRuntime::Live(status) => {
                match echo_runtime(state_path, probe_payload).await {
                    Ok(Some(payload)) if payload == probe_payload => {
                        spinner.clear()?;
                        return Ok(());
                    }
                    Ok(Some(_)) | Ok(None) | Err(Error::Session(_)) => {}
                    Err(error) => {
                        spinner.clear()?;
                        return Err(error);
                    }
                }
                let detail = status
                    .detail
                    .unwrap_or_else(|| "waiting for the tunnel to become ready...".into());
                spinner.update(&style.status("Status:"), &detail)?;
                async_std::task::sleep(std::time::Duration::from_millis(125)).await;
            }
        }
    }
}

fn find_live_temporary_state_by_code(
    cwd: &Path,
    code: &str,
) -> Result<Option<(PathBuf, PersistentState)>> {
    let mut matches = Vec::new();
    for (state_path, state) in list_saved_tunnels(cwd)? {
        if !state.config.temporary || state.config.code != code {
            continue;
        }
        if matches!(
            current_tunnel_runtime(&state_path)?,
            ResolvedTunnelRuntime::Stopped
        ) {
            continue;
        }
        matches.push((state_path, state));
    }

    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.into_iter().next()),
        _ => Err(Error::PersistentState(format!(
            "multiple live temporary tunnels match shared code {:?}; rerun with the local tunnel name instead",
            code
        ))),
    }
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

fn list_saved_tunnels(cwd: &Path) -> Result<Vec<(PathBuf, PersistentState)>> {
    let mut entries = Vec::new();
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
            entries.push((path, state));
        }
    }
    entries.sort_by(|left, right| left.1.config.name.cmp(&right.1.config.name));
    Ok(entries)
}

pub fn runtime_status_path(state_path: &Path) -> PathBuf {
    state_path.with_extension("runtime.json")
}

fn current_tunnel_runtime(state_path: &Path) -> Result<ResolvedTunnelRuntime> {
    if let Some(ControlResponse::Probe { runtime, .. }) = probe_runtime(state_path)? {
        return Ok(ResolvedTunnelRuntime::Live(runtime));
    }
    Ok(ResolvedTunnelRuntime::Stopped)
}

#[derive(Debug, Clone)]
enum ResolvedTunnelRuntime {
    Stopped,
    Live(TunnelRuntimeStatus),
}

impl ResolvedTunnelRuntime {
    fn label(&self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Live(TunnelRuntimeStatus {
                phase: TunnelRuntimePhase::Starting,
                ..
            }) => "starting",
            Self::Live(TunnelRuntimeStatus {
                phase: TunnelRuntimePhase::Waiting,
                ..
            }) => "waiting",
            Self::Live(TunnelRuntimeStatus {
                phase: TunnelRuntimePhase::Up,
                ..
            }) => "up",
            Self::Live(TunnelRuntimeStatus {
                phase: TunnelRuntimePhase::Retrying,
                ..
            }) => "retrying",
        }
    }

    fn detail(&self) -> Option<&str> {
        match self {
            Self::Stopped => None,
            Self::Live(status) => status.detail.as_deref(),
        }
    }
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
    let fingerprint = serde_json::to_vec(&(
        &config.name,
        &config.mailbox,
        &config.locals,
        &config.remotes,
    ))
    .map_err(|error| {
        Error::PersistentState(format!("could not fingerprint state config: {error}"))
    })?;
    Ok(format!("{slug}--{:016x}.json", fnv1a64(&fingerprint)))
}

pub fn project_state_dir(cwd: &Path) -> PathBuf {
    cwd.join(".tunnelworm")
}

pub fn user_state_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let base = env::var_os("APPDATA").ok_or_else(|| {
            Error::PersistentState(
                "APPDATA is not set; cannot resolve the user state directory".into(),
            )
        })?;
        return Ok(PathBuf::from(base).join("tunnelworm"));
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME").ok_or_else(|| {
            Error::PersistentState(
                "HOME is not set; cannot resolve the user state directory".into(),
            )
        })?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("tunnelworm"))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(xdg_state_home) = env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(xdg_state_home).join("tunnelworm"));
        }
        let home = env::var_os("HOME").ok_or_else(|| {
            Error::PersistentState(
                "HOME is not set; cannot resolve the user state directory".into(),
            )
        })?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("tunnelworm"))
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

fn prepare_temporary_state_path(state_path: &Path) -> Result<()> {
    if state_path.exists() {
        if matches!(
            current_tunnel_runtime(state_path)?,
            ResolvedTunnelRuntime::Live(_)
        ) {
            return Err(Error::PersistentState(format!(
                "a tunnel worker is already running for {}; stop it before starting the same temporary tunnel again",
                state_path.display()
            )));
        }
        remove_state_artifacts(state_path);
    }
    Ok(())
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
        let host = local.bind_interface.as_deref().unwrap_or("127.0.0.1");
        let port = local
            .local_listen_port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "<auto>".into());
        return format!("{host}:{port}");
    }

    if let Some(remote) = config.remotes.first() {
        let host = remote.connect_address.as_deref().unwrap_or("127.0.0.1");
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
    config: &TunnelConfig,
) {
    println!("{} {}", style.heading(heading), code);
    if let Some(tunnel_name) = &config.tunnel_name {
        println!("{} {}", style.heading("Tunnel:"), tunnel_name);
    }
    println!("{} {}", style.heading("Local:"), config.local_summary());
    if heading == "Tunnel create:" {
        println!();
        println!("{}", style.heading("Peer commands"));
        if let Some(preferred) = config.peer_preferred_command(code, true) {
            println!("  {} {}", style.label("preferred:"), preferred);
        }
        if let Some(ssh_style) = config.peer_ssh_command(code) {
            println!("  {} {}", style.label("ssh-style:"), ssh_style);
        }
    }
}

fn persistent_name(config: &TunnelConfig, code: &str) -> String {
    config
        .tunnel_name
        .clone()
        .unwrap_or_else(|| code.to_string())
}

fn temporary_tunnel_name(config: &TunnelConfig, code: &str) -> String {
    let half = match config.local_half() {
        crate::cli::ForwardHalf::Listen => "listen",
        crate::cli::ForwardHalf::Connect => "connect",
        crate::cli::ForwardHalf::None => "open",
        crate::cli::ForwardHalf::Mixed => "mixed",
    };
    format!("tmp-{half}-{}", slugify_tunnel_name(code))
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
    config: &TunnelConfig,
    state_path: &Path,
    code: &str,
) {
    println!();
    println!("{}", style.heading("State"));
    println!("  {}", style.label("file:"));
    println!("    {}", state_path.display());
    if let Some(tunnel_name) = &config.tunnel_name {
        println!(
            "  {} tunnelworm tunnel up {}",
            style.label("reuse:"),
            tunnel_name
        );
        println!(
            "  {} tunnelworm tunnel status {}",
            style.label("status:"),
            tunnel_name
        );
        println!(
            "  {} tunnelworm tunnel delete {}",
            style.label("delete:"),
            tunnel_name
        );
    } else {
        println!(
            "  {} {}",
            style.label("reuse:"),
            TunnelConfig::persistent_reuse_command(state_path)
        );
    }
    if let Some(reset_command) = config.persistent_reset_command(code) {
        println!("  {} {}", style.label("replace:"), reset_command);
    }
}

fn exec_persistent_daemon(state_path: &Path) -> Result<()> {
    let daemon_path = persistent_daemon_path()?;
    let mut command = Command::new(&daemon_path);
    command.arg("--persistent-state").arg(state_path);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        Err(Error::Io(command.exec()))
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

fn run_temporary_daemon(state_path: &Path, interrupt: async_channel::Receiver<()>) -> Result<()> {
    if interrupt.try_recv().is_ok() {
        remove_state_artifacts(state_path);
        return Ok(());
    }

    let daemon_path = persistent_daemon_path()?;
    let mut child = Command::new(&daemon_path)
        .arg("--persistent-state")
        .arg(state_path)
        .spawn()?;
    let mut interrupted_at: Option<Instant> = None;
    let mut forwarded_kill = false;

    loop {
        if interrupted_at.is_none() && interrupt.try_recv().is_ok() {
            interrupted_at = Some(Instant::now());
        }

        if let Some(status) = child.try_wait()? {
            remove_state_artifacts(state_path);
            if status.success() || interrupted_at.is_some() {
                return Ok(());
            }
            return Err(Error::PersistentState(format!(
                "temporary daemon {:?} exited with status {}",
                daemon_path, status
            )));
        }

        if let Some(interrupted_at) = interrupted_at
            && !forwarded_kill
            && interrupted_at.elapsed() >= Duration::from_millis(500)
        {
            let _ = child.kill();
            forwarded_kill = true;
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn persistent_daemon_path() -> Result<PathBuf> {
    let current_exe = env::current_exe()?;
    let sibling = current_exe.with_file_name("tunnelwormd");
    if sibling.exists() {
        return Ok(sibling);
    }
    Ok(PathBuf::from("tunnelwormd"))
}

fn install_frontend_interrupt_notifier() -> Result<async_channel::Receiver<()>> {
    let (tx, rx) = async_channel::bounded(1);
    ctrlc::set_handler(move || {
        let _ = tx.try_send(());
    })
    .map_err(|error| Error::Session(format!("could not install interrupt handler: {error}")))?;
    Ok(rx)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit_index = 0usize;
    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }
    if unit_index == 0 {
        format!("{bytes} {}", UNITS[unit_index])
    } else {
        format!("{value:.1} {}", UNITS[unit_index])
    }
}

pub fn remove_state_artifacts(state_path: &Path) {
    let _ = fs::remove_file(state_path);
    let _ = fs::remove_file(state_path.with_extension("lock"));
    let _ = fs::remove_file(runtime_status_path(state_path));
    let _ = fs::remove_file(control_socket_path(state_path));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ControlRequest, ControlResponse, control_socket_path};
    use crate::persistent_auth;
    use async_std::{
        io::{ReadExt, WriteExt},
        os::unix::net::UnixListener,
        task,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn resolves_a_live_temporary_tunnel_by_shared_code() {
        let mut fixture = Fixture::new("resolve-by-code");
        let first = fixture.write_live_state("tmp-connect-one", "9-regression-parsnip");

        let (resolved_path, resolved_state, correction) =
            resolve_live_tunnel_handle(None, Some("9-regression-parsnip"), fixture.cwd())
                .expect("shared code should resolve");

        assert_eq!(resolved_path, first.path);
        assert_eq!(resolved_state.config.name, "tmp-connect-one");
        assert_eq!(
            correction.as_deref(),
            Some("code 9-regression-parsnip matched local tunnel tmp-connect-one.")
        );
    }

    #[test]
    fn rejects_ambiguous_live_temporary_code_matches() {
        let mut fixture = Fixture::new("resolve-ambiguous");
        fixture.write_live_state("tmp-connect-one", "9-regression-ambiguous");
        fixture.write_live_state("tmp-listen-two", "9-regression-ambiguous");

        let error = resolve_live_tunnel_handle(None, Some("9-regression-ambiguous"), fixture.cwd())
            .expect_err("ambiguous code should fail");

        assert!(
            error
                .to_string()
                .contains("multiple live temporary tunnels match shared code"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn ports_rule_implies_remote_port_management_until_it_is_denied() {
        let rules = vec![
            TunnelPolicyRule {
                effect: TunnelPolicyEffect::Deny,
                capability: TunnelCapability::All,
            },
            TunnelPolicyRule {
                effect: TunnelPolicyEffect::Allow,
                capability: TunnelCapability::Ports,
            },
            TunnelPolicyRule {
                effect: TunnelPolicyEffect::Deny,
                capability: TunnelCapability::RemotePortMgmt,
            },
        ];

        assert!(capability_allowed(&rules, TunnelCapability::Ports));
        assert!(!capability_allowed(
            &rules,
            TunnelCapability::RemotePortMgmt
        ));
        assert!(!capability_allowed(&rules, TunnelCapability::Shell));
    }

    struct Fixture {
        root: PathBuf,
        cwd: PathBuf,
        socket_paths: Vec<PathBuf>,
    }

    struct StateHandle {
        path: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos();
            let root =
                std::env::temp_dir().join(format!("tunnelworm-persistent-test-{label}-{unique}"));
            let cwd = root.join("cwd");
            fs::create_dir_all(project_state_dir(&cwd)).expect("project state dir should exist");
            Self {
                root,
                cwd,
                socket_paths: Vec::new(),
            }
        }

        fn cwd(&self) -> &Path {
            &self.cwd
        }

        fn write_live_state(&mut self, name: &str, code: &str) -> StateHandle {
            let config = PersistentConfig {
                name: name.into(),
                code: code.into(),
                mailbox: None,
                temporary: true,
                role: PersistentRole::Allocate,
                locals: Vec::new(),
                remotes: vec![RemoteSpec {
                    name: "tmp-rule".into(),
                    remote_listen_port: Some(22),
                    local_connect_port: Some(22),
                    connect_address: Some("127.0.0.1".into()),
                }],
                ports: Vec::new(),
                policy_rules: Vec::new(),
            };
            let state = PersistentState::new(config.clone(), persistent_auth::generate_identity());
            let path = project_state_dir(&self.cwd)
                .join(state_file_name(&config).expect("state file name should render"));
            save_state(&path, &state).expect("state should save");
            fs::write(
                runtime_status_path(&path),
                serde_json::to_vec(&TunnelRuntimeStatus {
                    phase: TunnelRuntimePhase::Up,
                    detail: Some("peer connected; live tunnel ready".into()),
                })
                .expect("runtime status should encode"),
            )
            .expect("runtime status should save");
            let socket_path = control_socket_path(&path);
            if let Some(parent) = socket_path.parent() {
                fs::create_dir_all(parent).expect("control socket dir should exist");
            }
            if socket_path.exists() {
                let _ = fs::remove_file(&socket_path);
            }
            let listener = task::block_on(UnixListener::bind(&socket_path))
                .expect("control socket should bind");
            let tunnel_name = state.config.name.clone();
            let tunnel_code = state.config.code.clone();
            task::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let mut line = Vec::new();
                    loop {
                        let mut byte = [0u8; 1];
                        let read = stream
                            .read(&mut byte)
                            .await
                            .expect("control socket should read");
                        if read == 0 {
                            break;
                        }
                        line.push(byte[0]);
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    let response = match serde_json::from_slice::<ControlRequest>(&line)
                        .expect("control request should decode")
                    {
                        ControlRequest::Probe {} => ControlResponse::Probe {
                            tunnel_name: tunnel_name.clone(),
                            code: tunnel_code.clone(),
                            runtime: TunnelRuntimeStatus {
                                phase: TunnelRuntimePhase::Up,
                                detail: Some("peer connected; live tunnel ready".into()),
                            },
                            peer_policy_rules: Vec::new(),
                        },
                        _ => ControlResponse::Error {
                            message: "unexpected control request in test fixture".into(),
                        },
                    };
                    let mut bytes =
                        serde_json::to_vec(&response).expect("control response should encode");
                    bytes.push(b'\n');
                    stream
                        .write_all(&bytes)
                        .await
                        .expect("control response should write");
                    stream.flush().await.expect("control response should flush");
                }
            });
            self.socket_paths.push(socket_path);
            StateHandle { path }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for socket_path in &self.socket_paths {
                let _ = fs::remove_file(socket_path);
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
