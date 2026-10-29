// Execute the production option getter and CLI read body. Transport/status and
// local configuration are doubles; installed/root eligibility is outside scope.
use crate::ResultType;
use std::collections::HashMap;

include!("option_reader.rs");
include!("option_cli.rs");

struct Config;
impl Config {
    fn get_options() -> HashMap<String, String> {
        eprintln!("unexpected local configuration read");
        HashMap::from([("audio-input".to_owned(), "local-value".to_owned())])
    }
}

struct Snapshot {
    options: Options,
}
struct Options;
impl Options {
    fn into_map(self) -> ResultType<HashMap<String, String>> {
        match scenario().as_str() {
            "invalid" => anyhow::bail!("fixture invalid"),
            "missing" => Ok(HashMap::new()),
            "value" => Ok(HashMap::from([
                ("audio-input".to_owned(), "receiver-value".to_owned()),
            ])),
            other => panic!("unexpected snapshot scenario: {other}"),
        }
    }
}

async fn get_main_status_snapshot(ms_timeout: u64) -> ResultType<Snapshot> {
    assert_eq!(ms_timeout, 1000);
    match scenario().as_str() {
        "refused" | "timeout" | "disconnected" => anyhow::bail!("fixture {}", scenario()),
        _ => Ok(Snapshot { options: Options }),
    }
}

fn scenario() -> String {
    std::env::args().nth(1).unwrap().strip_prefix("cli-option-").unwrap().to_owned()
}

pub(crate) fn run() {
    read_option(&["--option".to_owned(), "audio-input".to_owned()]);
}
