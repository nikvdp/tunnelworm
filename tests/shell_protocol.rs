use tunnelworm::shell::{ShellOpen, ShellPacket};

#[test]
fn shell_open_round_trips_through_json() {
    let open = ShellOpen {
        command: Some("pwd".into()),
        rows: 24,
        cols: 80,
    };
    let encoded = serde_json::to_string(&open).expect("shell open should serialize");
    let decoded: ShellOpen = serde_json::from_str(&encoded).expect("shell open should deserialize");
    assert_eq!(decoded, open);
}

#[test]
fn shell_packets_round_trip_through_bincode() {
    let packet = ShellPacket::Resize { rows: 50, cols: 120 };
    let encoded = bincode::serialize(&packet).expect("shell packet should serialize");
    let decoded: ShellPacket = bincode::deserialize(&encoded).expect("shell packet should deserialize");
    assert_eq!(decoded, packet);
}
