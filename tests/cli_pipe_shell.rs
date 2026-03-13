use clap::Parser;
use tunnelworm::cli::{
    tunnelworm_command, TunnelPipeConfig, TunnelShellConfig, TunnelwormCli, TunnelwormInvocation,
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
    assert!(help.contains("tunnelworm shell office-ssh"));
    assert!(help.contains(
        "tunnelworm pipe` infers send or receive from stdio unless both ends are redirected"
    ));
    assert!(help.contains(
        "Without `--command`, `tunnelworm shell` starts the remote login shell"
    ));
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
fn parses_pipe_send_mode_and_name() {
    let cli = TunnelwormCli::parse_from(["tunnelworm", "pipe", "office-ssh", "--send"]);
    let invocation = TunnelwormInvocation::try_from(cli).expect("pipe invocation should parse");
    match invocation {
        TunnelwormInvocation::Pipe(TunnelPipeConfig { name, mode, .. }) => {
            assert_eq!(name.as_deref(), Some("office-ssh"));
            assert!(matches!(mode, Some(tunnelworm::pipe::PipeMode::Send)));
        },
        other => panic!("expected pipe invocation, got {other:?}"),
    }
}

#[test]
fn parses_shell_command_and_name() {
    let cli = TunnelwormCli::parse_from([
        "tunnelworm",
        "shell",
        "office-ssh",
        "--command",
        "pwd",
    ]);
    let invocation = TunnelwormInvocation::try_from(cli).expect("shell invocation should parse");
    match invocation {
        TunnelwormInvocation::Shell(TunnelShellConfig { name, command, .. }) => {
            assert_eq!(name.as_deref(), Some("office-ssh"));
            assert_eq!(command.as_deref(), Some("pwd"));
        },
        other => panic!("expected shell invocation, got {other:?}"),
    }
}
