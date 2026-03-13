use clap::Parser;
use tunnelworm::cli::{ForwardHalf, TunnelwormCli, TunnelwormInvocation};

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
        },
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
        },
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
            assert_eq!(config.remotes[0].connect_address.as_deref(), Some("127.0.0.1"));
            assert_eq!(config.remotes[0].local_connect_port, Some(22));
        },
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
        },
        other => panic!("expected a run invocation, got {other:?}"),
    }
}
