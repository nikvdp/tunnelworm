use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use tunnelworm::daemon::protocol::InputCommand;

struct DaemonHarness {
    child: Child,
    stdin: ChildStdin,
    events: Receiver<Value>,
}

impl DaemonHarness {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tunnelwormd"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("tunnelwormd should spawn");

        let stdin = child.stdin.take().expect("stdin should be piped");
        let stdout = child.stdout.take().expect("stdout should be piped");
        let stderr = child.stderr.take().expect("stderr should be piped");
        let (event_tx, event_rx) = mpsc::channel();

        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let line = line.expect("daemon stdout should be readable");
                let event: Value = serde_json::from_str(&line).expect("daemon event should parse");
                if event_tx.send(event).is_err() {
                    break;
                }
            }
        });

        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for _ in reader.lines() {}
        });

        Self {
            child,
            stdin,
            events: event_rx,
        }
    }

    fn send_json(&mut self, command: Value) {
        let line = serde_json::to_string(&command).expect("daemon command should serialize");
        writeln!(self.stdin, "{line}").expect("daemon stdin should accept a command");
        self.stdin.flush().expect("daemon stdin should flush");
    }

    fn wait_for<F>(&self, mut predicate: F) -> Value
    where
        F: FnMut(&Value) -> bool,
    {
        let deadline = Duration::from_secs(20);
        loop {
            let event = self
                .events
                .recv_timeout(deadline)
                .expect("daemon event should arrive before timeout");
            if predicate(&event) {
                return event;
            }
        }
    }

    fn close(mut self) {
        let _ = writeln!(self.stdin, "{}", json!({"kind":"session-close"}));
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

impl Drop for DaemonHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn next_free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("ephemeral port bind should work")
        .local_addr()
        .expect("local addr should exist")
        .port()
}

fn start_echo_server(port: u16) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener =
            TcpListener::bind(("127.0.0.1", port)).expect("echo server should bind locally");
        let (mut stream, _) = listener
            .accept()
            .expect("echo server should accept one client");
        let mut reader = BufReader::new(
            stream
                .try_clone()
                .expect("echo server stream should clone successfully"),
        );
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("echo server should read one line");
        stream
            .write_all(line.as_bytes())
            .expect("echo server should echo the payload");
        stream.flush().expect("echo server should flush");
    })
}

#[test]
fn input_commands_round_trip_through_json() {
    let decoded: InputCommand = serde_json::from_str(r#"{"kind":"allocate-code","code_length":3}"#)
        .expect("allocate-code should deserialize");
    match decoded {
        InputCommand::AllocateCode { code_length } => assert_eq!(code_length, Some(3)),
        other => panic!("decoded the wrong input command: {other:?}"),
    }
}

#[test]
fn peer_connected_event_shape_serializes_as_expected() {
    let encoded = serde_json::to_string(&json!({
        "kind": "peer-connected",
        "verifier": "abc123",
        "versions": {"app_versions": {"tunnelworm": "0.0.2"}}
    }))
    .expect("peer-connected should serialize");
    let decoded: Value = serde_json::from_str(&encoded).expect("event should deserialize");
    assert_eq!(decoded["kind"], "peer-connected");
    assert_eq!(decoded["verifier"], "abc123");
    assert_eq!(decoded["versions"]["app_versions"]["tunnelworm"], "0.0.2");
}

#[test]
fn tunnelwormd_forwards_bytes_end_to_end() {
    let listen_port = next_free_port();
    let target_port = next_free_port();
    let echo_server = start_echo_server(target_port);

    let mut allocator = DaemonHarness::spawn();
    let mut joiner = DaemonHarness::spawn();

    allocator.send_json(json!({
        "kind": "remote",
        "listen": format!("tcp:{listen_port}:interface=127.0.0.1"),
        "connect": format!("tcp:127.0.0.1:{target_port}")
    }));
    joiner.send_json(json!({
        "kind": "local",
        "listen": format!("tcp:{listen_port}"),
        "connect": format!("tcp:127.0.0.1:{target_port}")
    }));

    allocator.send_json(json!({"kind": "allocate-code", "code_length": 2}));
    let code = allocator
        .wait_for(|event| event["kind"] == "code-allocated")
        .get("code")
        .and_then(Value::as_str)
        .expect("code-allocated event should include a code")
        .to_string();

    joiner.send_json(json!({"kind": "set-code", "code": code}));

    let _ = allocator.wait_for(|event| event["kind"] == "peer-connected");
    let _ = joiner.wait_for(|event| event["kind"] == "peer-connected");
    let _ = joiner.wait_for(|event| event["kind"] == "listening");

    let mut client =
        TcpStream::connect(("127.0.0.1", listen_port)).expect("forwarded port should accept");
    client
        .write_all(b"hello through tunnelwormd\n")
        .expect("client should write through the forward");
    client.flush().expect("client should flush");

    let mut echoed = String::new();
    let mut reader = BufReader::new(client);
    reader
        .read_line(&mut echoed)
        .expect("client should read echoed data");
    assert_eq!(echoed, "hello through tunnelwormd\n");

    allocator.close();
    joiner.close();
    echo_server
        .join()
        .expect("echo server should shut down cleanly");
}
