use clap::Parser;
use tunnelworm::cli::{
    TunnelPipeConfig, TunnelSendFileConfig, TunnelShellConfig, TunnelwormCli, TunnelwormInvocation,
    tunnelworm_command,
};

fn render_long_help() -> String {
    let mut command = tunnelworm_command();
    let mut output = Vec::new();
    command
        .write_long_help(&mut output)
        .expect("long help should render");
    String::from_utf8(output).expect("help should be utf8")
}

#[test]
fn top_level_help_mentions_pipe_and_shell_rules() {
    let help = render_long_help();
    assert!(help.contains("echo hello | tunnelworm pipe office-ssh"));
    assert!(help.contains("tunnelworm send-file office-ssh ./report.txt"));
    assert!(help.contains("tunnelworm shell office-ssh"));
    assert!(help.contains(
        "tunnelworm pipe` infers send or receive from stdio unless both ends are redirected"
    ));
    assert!(help.contains(
        "tunnelworm send-file` writes into the peer's working directory unless you pass a remote path"
    ));
    assert!(help.contains("Without `--command`, `tunnelworm shell` starts the remote login shell"));
}

#[test]
fn pipe_help_mentions_explicit_mode_for_fully_redirected_stdio() {
    let mut command = tunnelworm_command();
    let pipe_help = command
        .find_subcommand_mut("pipe")
        .expect("pipe subcommand should exist")
        .render_long_help()
        .to_string();
    assert!(pipe_help.contains("tunnelworm pipe office-ssh --send < input.txt > /dev/null"));
    assert!(pipe_help.contains("pass `--send` or `--receive` explicitly"));
}

#[test]
fn shell_help_mentions_remote_login_shell() {
    let mut command = tunnelworm_command();
    let shell_help = command
        .find_subcommand_mut("shell")
        .expect("shell subcommand should exist")
        .render_long_help()
        .to_string();
    assert!(shell_help.contains("tunnelworm shell office-ssh --command 'pwd'"));
    assert!(shell_help.contains("Without `--command`, tunnelworm starts the remote login shell."));
}

#[test]
fn send_file_help_mentions_default_destination_and_alias() {
    let mut command = tunnelworm_command();
    let send_file_help = command
        .find_subcommand_mut("send-file")
        .expect("send-file subcommand should exist")
        .render_long_help()
        .to_string();
    assert!(send_file_help.contains("tunnelworm send-file office-ssh ./report.txt"));
    assert!(send_file_help.contains(
        "The peer writes into its tunnel process working directory unless you pass a remote path."
    ));
    assert!(send_file_help.contains("`send` is a shorthand alias for `send-file`."));
}

#[test]
fn parses_pipe_send_mode_and_name() {
    let cli = TunnelwormCli::parse_from(["tunnelworm", "pipe", "office-ssh", "--send"]);
    let invocation = TunnelwormInvocation::try_from(cli).expect("pipe invocation should parse");
    match invocation {
        TunnelwormInvocation::Pipe(TunnelPipeConfig { name, mode, .. }) => {
            assert_eq!(name.as_deref(), Some("office-ssh"));
            assert!(matches!(mode, Some(tunnelworm::pipe::PipeMode::Send)));
        }
        other => panic!("expected pipe invocation, got {other:?}"),
    }
}

#[test]
fn parses_send_file_alias_name_and_destination() {
    let cli = TunnelwormCli::parse_from([
        "tunnelworm",
        "send",
        "office-ssh",
        "./report.txt",
        "/tmp/inbox/report.txt",
        "--overwrite",
    ]);
    let invocation =
        TunnelwormInvocation::try_from(cli).expect("send-file invocation should parse");
    match invocation {
        TunnelwormInvocation::SendFile(TunnelSendFileConfig {
            name,
            source,
            destination,
            overwrite,
        }) => {
            assert_eq!(name.as_deref(), Some("office-ssh"));
            assert_eq!(source, Some(std::path::PathBuf::from("./report.txt")));
            assert_eq!(
                destination,
                Some(std::path::PathBuf::from("/tmp/inbox/report.txt"))
            );
            assert!(overwrite);
        }
        other => panic!("expected send-file invocation, got {other:?}"),
    }
}

#[test]
fn parses_shell_command_and_name() {
    let cli = TunnelwormCli::parse_from(["tunnelworm", "shell", "office-ssh", "--command", "pwd"]);
    let invocation = TunnelwormInvocation::try_from(cli).expect("shell invocation should parse");
    match invocation {
        TunnelwormInvocation::Shell(TunnelShellConfig { name, command, .. }) => {
            assert_eq!(name.as_deref(), Some("office-ssh"));
            assert_eq!(command.as_deref(), Some("pwd"));
        }
        other => panic!("expected shell invocation, got {other:?}"),
    }
}
