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

    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("kill should run");
    assert!(status.success(), "kill -INT failed with {status}");

    wait_for_child_exit(&mut child);

    let state_dir = workspace.path().join(".tunnelworm");
    let leftovers: Vec<String> = fs::read_dir(&state_dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();

    assert!(
        leftovers.is_empty(),
        "temporary tunnel state should be cleaned up, found {leftovers:?}"
    );
}
