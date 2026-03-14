use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::tempdir;

fn wait_for_temp_state(dir: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state_dir = dir.join(".tunnelworm");
        let has_state = fs::read_dir(&state_dir)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .any(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
            })
            .unwrap_or(false);
        if has_state {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "temporary tunnel state did not appear under {}",
            state_dir.display()
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_child_exit(child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child
            .try_wait()
            .expect("child status should be readable")
            .is_some()
        {
            return;
        }
        assert!(Instant::now() < deadline, "temporary tunnel did not exit");
        thread::sleep(Duration::from_millis(100));
    }
}

fn send_signal(child: &std::process::Child, signal: &str) {
    let status = Command::new("kill")
        .args([signal, &child.id().to_string()])
        .status()
        .expect("kill should run");
    assert!(status.success(), "kill {signal} failed with {status}");
}

fn wait_for_temp_cleanup_via_list(dir: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = Command::new(env!("CARGO_BIN_EXE_tunnelworm"))
            .args(["tunnel", "list"])
            .current_dir(dir)
            .output()
            .expect("tunnel list should run");
        assert!(
            output.status.success(),
            "tunnel list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let leftovers: Vec<String> = fs::read_dir(dir.join(".tunnelworm"))
            .ok()
            .into_iter()
            .flat_map(|entries| entries.filter_map(Result::ok))
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        if stdout.contains("Saved tunnels\n  none") && leftovers.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "temporary tunnel cleanup did not converge; list output was {:?}, leftover files were {:?}",
            stdout,
            leftovers
        );
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn temporary_open_cleans_up_state_after_sigint() {
    let workspace = tempdir().expect("tempdir should create");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tunnelworm"))
        .arg("open")
        .current_dir(workspace.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("tunnelworm open should spawn");

    wait_for_temp_state(workspace.path());

    send_signal(&child, "-INT");
    wait_for_child_exit(&mut child);
    wait_for_temp_cleanup_via_list(workspace.path());
}

#[test]
fn temporary_open_cleans_up_state_after_frontend_sigkill() {
    let workspace = tempdir().expect("tempdir should create");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tunnelworm"))
        .arg("open")
        .current_dir(workspace.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("tunnelworm open should spawn");

    wait_for_temp_state(workspace.path());

    send_signal(&child, "-KILL");
    wait_for_child_exit(&mut child);
    wait_for_temp_cleanup_via_list(workspace.path());
}
