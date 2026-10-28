use crate::{bail, ResultType};
use std::net::Ipv4Addr;

// Application metadata is fixed for this component fixture; no OS handoff runs.
pub fn get_app_name() -> String {
    "RustDesk".to_owned()
}

include!(env!("DIRECT_CLI_SOURCE"));

#[test]
fn cli_preserves_exact_address_before_receiver_validation() {
    let commands = ["connect", "play", "file-transfer", "view-camera",
                    "port-forward", "rdp", "terminal"];
    let valid = ["192.0.2.10", "192.0.2.10:21118", "Host.Example.:00001",
                 "host.rustdesk.example:21118"];
    let markers = [
        ("192.0.2.10.rustdesk", "192.0.2.10", true),
        ("192.rustdesk.0.2.10.rustdesk", "192.rustdesk.0.2.10", false),
        ("host.rustdesk.example:21118.rustdesk", "host.rustdesk.example:21118", true),
        ("192.0.2.10.rustdesk.rustdesk", "192.0.2.10.rustdesk", false),
    ];
    let mut mismatches = Vec::new();
    for command in commands {
        let flag = format!("--{command}");
        for address in valid {
            let uri = assemble_connection_uri(["rustdesk", &flag, address].map(str::to_owned).into_iter()).unwrap();
            assert_eq!(uri, format!("rustdesk://{command}/{address}"));
            assert!(validate_desktop_url_ipc_open_url(&uri).is_ok());
        }
        for (address, play_target, play_accepted) in markers {
            let (target, accepted) = if command == "play" {
                (play_target, play_accepted)
            } else {
                (address, false)
            };
            let uri = assemble_connection_uri(["rustdesk", &flag, address].map(str::to_owned).into_iter()).unwrap();
            let admitted = validate_desktop_url_ipc_open_url(&uri).is_ok();
            if uri != format!("rustdesk://{command}/{target}") || admitted != accepted {
                mismatches.push((command, address, uri, admitted));
            }
        }
        let arguments = ["rustdesk", &flag, valid[0], "--password", "discard-me"]
            .map(str::to_owned);
        let uri = assemble_connection_uri(arguments.into_iter()).unwrap();
        assert_eq!(uri, format!("rustdesk://{command}/{}", valid[0]));
        assert!(validate_desktop_url_ipc_open_url(&uri).is_ok());
        assert_eq!(assemble_connection_uri(["rustdesk", &flag].map(str::to_owned).into_iter()), None);
        assert_eq!(assemble_connection_uri(["rustdesk", &flag, valid[0], "--relay"].map(str::to_owned).into_iter()), None);
    }
    assert_eq!(assemble_connection_uri(["rustdesk".to_owned()].into_iter()), None);
    println!("DIRECT_CLI_CONTROLS=pass modes=7 valid=28 credentials=discarded missing=refused relay=refused");
    assert!(mismatches.is_empty(), "CLI target rewriting or admission differs: {mismatches:?}");
    println!("DIRECT_CLI_ADDRESS=pass direct_modes=6 valid=28 malformed=24 play_cases=4 extension=final-only receiver=production handoff=unexecuted");
}
