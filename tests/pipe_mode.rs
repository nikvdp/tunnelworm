use tunnelworm::{
    control::ControlRequest,
    pipe::{PipeMode, infer_pipe_mode_from_terminals},
};

#[test]
fn prefers_explicit_pipe_mode() {
    assert!(matches!(
        infer_pipe_mode_from_terminals(false, false, Some(PipeMode::Send)),
        Ok(PipeMode::Send)
    ));
    assert!(matches!(
        infer_pipe_mode_from_terminals(true, true, Some(PipeMode::Receive)),
        Ok(PipeMode::Receive)
    ));
}

#[test]
fn infers_send_when_only_stdin_is_redirected() {
    assert!(matches!(
        infer_pipe_mode_from_terminals(false, true, None),
        Ok(PipeMode::Send)
    ));
}

#[test]
fn infers_receive_when_only_stdout_is_redirected() {
    assert!(matches!(
        infer_pipe_mode_from_terminals(true, false, None),
        Ok(PipeMode::Receive)
    ));
}

#[test]
fn defaults_tty_tty_to_receive() {
    assert!(matches!(
        infer_pipe_mode_from_terminals(true, true, None),
        Ok(PipeMode::Receive)
    ));
}

#[test]
fn rejects_fully_redirected_pipe_without_an_explicit_mode() {
    let error = infer_pipe_mode_from_terminals(false, false, None)
        .expect_err("fully redirected stdio should require an explicit mode");
    assert!(
        error
            .to_string()
            .contains("pipe mode is ambiguous when both stdin and stdout are redirected")
    );
}

#[test]
fn pipe_control_requests_round_trip_through_json() {
    let encoded = serde_json::to_string(&ControlRequest::Pipe {
        mode: PipeMode::Send,
    })
    .expect("pipe request should serialize");
    assert_eq!(encoded, r#"{"kind":"pipe","mode":"send"}"#);

    let decoded: ControlRequest =
        serde_json::from_str(&encoded).expect("pipe request should deserialize");
    match decoded {
        ControlRequest::Pipe { mode } => assert_eq!(mode, PipeMode::Send),
        other => panic!("decoded the wrong control request: {other:?}"),
    }
}
