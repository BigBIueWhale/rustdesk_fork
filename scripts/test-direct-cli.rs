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
    let invalid = ["192.0.2.10.rustdesk", "192.rustdesk.0.2.10.rustdesk",
                   "host.rustdesk.example:21118.rustdesk"];
    let mut mismatches = Vec::new();
    for command in commands {
        let flag = format!("--{command}");
        for (addresses, accepted) in [(&valid[..], true), (&invalid[..], false)] {
            for address in addresses {
                let arguments = ["rustdesk", &flag, address].map(str::to_owned);
                let uri = assemble_connection_uri(arguments.into_iter()).unwrap();
                let expected = format!("rustdesk://{command}/{address}");
                let admitted = validate_desktop_url_ipc_open_url(&uri).is_ok();
                if uri != expected || admitted != accepted {
                    mismatches.push((command, *address, uri, admitted));
                }
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
    println!("DIRECT_CLI_ADDRESS=pass modes=7 valid=28 malformed=21 target=exact receiver=production handoff=unexecuted");
}
