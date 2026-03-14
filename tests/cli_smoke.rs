use clap::Parser;
use std::process::Command;
use tempfile::tempdir;
use tunnelworm::cli::{
    ForwardHalf, TunnelCapability, TunnelPolicyEffect, TunnelPolicyRule, TunnelwormCli,
    TunnelwormInvocation, try_parse_tunnelworm_cli_from,
};

#[test]
fn parses_ssh_style_local_flag_into_the_listen_half() {
    let cli =
        TunnelwormCli::parse_from(["tunnelworm", "-L", "9000:localhost:22", "7-cobalt-signal"]);
    let invocation =
        TunnelwormInvocation::try_from(cli).expect("ssh-style -L invocation should parse");
    match invocation {
        TunnelwormInvocation::Run(config) => {
            assert_eq!(config.code.as_deref(), Some("7-cobalt-signal"));
            assert_eq!(config.local_half(), ForwardHalf::Listen);
            assert_eq!(config.locals.len(), 1);
            let local = &config.locals[0];
            assert_eq!(local.local_listen_port, Some(9000));
            assert_eq!(local.remote_connect_port, Some(22));
            assert_eq!(local.bind_interface.as_deref(), None);
        }
        other => panic!("expected a run invocation, got {other:?}"),
    }
}

#[test]
fn parses_ssh_style_remote_flag_into_the_connect_half() {
    let cli =
        TunnelwormCli::parse_from(["tunnelworm", "-R", "9000:localhost:22", "7-cobalt-signal"]);
    let invocation =
        TunnelwormInvocation::try_from(cli).expect("ssh-style -R invocation should parse");
    match invocation {
        TunnelwormInvocation::Run(config) => {
            assert_eq!(config.code.as_deref(), Some("7-cobalt-signal"));
            assert_eq!(config.local_half(), ForwardHalf::Connect);
            assert_eq!(config.remotes.len(), 1);
            let remote = &config.remotes[0];
            assert_eq!(remote.remote_listen_port, Some(9000));
            assert_eq!(remote.local_connect_port, Some(22));
            assert_eq!(remote.connect_address.as_deref(), Some("127.0.0.1"));
        }
        other => panic!("expected a run invocation, got {other:?}"),
    }
}

#[test]
fn one_off_without_a_code_stays_in_allocate_flow() {
    let cli = TunnelwormCli::parse_from(["tunnelworm", "--connect", "22"]);
    let invocation = TunnelwormInvocation::try_from(cli).expect("one-off create should parse");
    match invocation {
        TunnelwormInvocation::Run(config) => {
            assert_eq!(config.code, None);
            assert_eq!(config.local_half(), ForwardHalf::Connect);
            assert_eq!(config.remotes.len(), 1);
            assert_eq!(
                config.remotes[0].connect_address.as_deref(),
                Some("127.0.0.1")
            );
            assert_eq!(config.remotes[0].local_connect_port, Some(22));
        }
        other => panic!("expected a run invocation, got {other:?}"),
    }
}

#[test]
fn one_off_with_an_explicit_code_stays_in_join_flow() {
    let cli = TunnelwormCli::parse_from(["tunnelworm", "--listen", "9000", "7-cobalt-signal"]);
    let invocation = TunnelwormInvocation::try_from(cli).expect("one-off join should parse");
    match invocation {
        TunnelwormInvocation::Run(config) => {
            assert_eq!(config.code.as_deref(), Some("7-cobalt-signal"));
            assert_eq!(config.local_half(), ForwardHalf::Listen);
            assert_eq!(config.locals.len(), 1);
            assert_eq!(config.locals[0].local_listen_port, Some(9000));
            assert_eq!(config.locals[0].bind_interface, None);
        }
        other => panic!("expected a run invocation, got {other:?}"),
    }
}

#[test]
fn top_level_policy_flags_preserve_their_original_order() {
    let cli = try_parse_tunnelworm_cli_from([
        "tunnelworm",
        "--connect",
        "22",
        "--deny",
        "all",
        "--allow",
        "ports",
        "--deny",
        "remote-port-mgmt",
    ])
    .expect("top-level policy flags should parse");
    let invocation =
        TunnelwormInvocation::try_from(cli).expect("top-level invocation should parse");
    match invocation {
        TunnelwormInvocation::Run(config) => {
            assert_eq!(
                config.policy_rules,
                vec![
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
                ]
            );
        }
        other => panic!("expected a run invocation, got {other:?}"),
    }
}

#[test]
fn ports_list_subcommand_maps_to_the_existing_list_invocation() {
    let cli = TunnelwormCli::parse_from(["tunnelworm", "ports", "list", "office-ssh"]);
    let invocation =
        TunnelwormInvocation::try_from(cli).expect("ports list invocation should parse");
    match invocation {
        TunnelwormInvocation::PortsList(config) => {
            assert_eq!(config.name.as_deref(), Some("office-ssh"));
            assert_eq!(config.state, None);
        }
        other => panic!("expected a ports list invocation, got {other:?}"),
    }
}

#[test]
fn ports_ls_alias_maps_to_the_existing_list_invocation() {
    let cli = TunnelwormCli::parse_from(["tunnelworm", "ports", "ls", "office-ssh"]);
    let invocation = TunnelwormInvocation::try_from(cli).expect("ports ls invocation should parse");
    match invocation {
        TunnelwormInvocation::PortsList(config) => {
            assert_eq!(config.name.as_deref(), Some("office-ssh"));
            assert_eq!(config.state, None);
        }
        other => panic!("expected a ports list invocation, got {other:?}"),
    }
}

#[test]
fn bare_ports_command_still_maps_to_the_list_invocation() {
    let cli = TunnelwormCli::parse_from(["tunnelworm", "ports", "office-ssh"]);
    let invocation =
        TunnelwormInvocation::try_from(cli).expect("bare ports invocation should parse");
    match invocation {
        TunnelwormInvocation::PortsList(config) => {
            assert_eq!(config.name.as_deref(), Some("office-ssh"));
            assert_eq!(config.state, None);
        }
        other => panic!("expected a ports list invocation, got {other:?}"),
    }
}

#[test]
fn tunnel_ls_alias_maps_to_the_existing_tunnel_list_invocation() {
    let cli = TunnelwormCli::parse_from(["tunnelworm", "tunnel", "ls"]);
    let invocation = TunnelwormInvocation::try_from(cli).expect("tunnel ls should parse");
    match invocation {
        TunnelwormInvocation::TunnelList => {}
        other => panic!("expected a tunnel list invocation, got {other:?}"),
    }
}

#[test]
fn ports_list_without_a_live_tunnel_reports_the_runtime_problem() {
    let cwd = tempdir().expect("temp dir should exist");
    let output = Command::new(env!("CARGO_BIN_EXE_tunnelworm"))
        .current_dir(cwd.path())
        .args(["ports", "list"])
        .output()
        .expect("binary should run");

    assert!(!output.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "no live tunnels are running locally, so there is no tunnel to list ports on"
        )
    );
    assert!(stderr.contains("List the current live port forwards on one tunnel"));
}
