use tunnelworm::{
    control::ControlRequest,
    file_transfer::{FileTransferOpen, FileTransferPacket},
};

#[test]
fn send_file_control_request_round_trips_through_json() {
    let request = ControlRequest::SendFile {
        open: FileTransferOpen {
            source_name: "report.txt".into(),
            destination_path: Some("/tmp/remote-report.txt".into()),
            overwrite: true,
        },
    };
    let encoded = serde_json::to_string(&request).expect("send-file request should serialize");
    let decoded: ControlRequest =
        serde_json::from_str(&encoded).expect("send-file request should deserialize");
    match decoded {
        ControlRequest::SendFile { open } => {
            assert_eq!(open.source_name, "report.txt");
            assert_eq!(
                open.destination_path.as_deref(),
                Some("/tmp/remote-report.txt")
            );
            assert!(open.overwrite);
        }
        other => panic!("decoded the wrong control request: {other:?}"),
    }
}

#[test]
fn file_transfer_packets_round_trip_through_bincode() {
    let packet = FileTransferPacket::Success {
        path: "/tmp/remote-report.txt".into(),
        bytes: 42,
    };
    let encoded = bincode::serialize(&packet).expect("packet should serialize");
    let decoded: FileTransferPacket =
        bincode::deserialize(&encoded).expect("packet should deserialize");
    assert_eq!(decoded, packet);
}
