// Execute the production option getter and complete CLI branch. Eligibility,
// transport/status, mutation and local configuration are controlled doubles.
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

fn is_cli_setting_change_disabled() -> bool {
    scenario().starts_with("disabled-")
}

fn is_root() -> bool {
    !scenario().starts_with("nonadmin-")
}

pub(crate) mod platform {
    pub(crate) fn is_installed() -> bool {
        !super::scenario().starts_with("uninstalled-")
    }
}

static WRITES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn set_option(key: &str, value: &str) -> ResultType<String> {
    assert_eq!((key, value), ("audio-input", "requested-value"));
    assert_eq!(WRITES.fetch_add(1, std::sync::atomic::Ordering::SeqCst), 0);
    match scenario().as_str() {
        "write" => Ok(value.to_owned()),
        "write-refused" => anyhow::bail!("fixture write refused"),
        other => panic!("unexpected option mutation: {other}"),
    }
}

pub(crate) fn run() {
    let scenario = scenario();
    let mut args = vec!["--option".to_owned()];
    if scenario != "no-key" {
        args.push("audio-input".to_owned());
    }
    if scenario == "write" || scenario == "write-refused"
        || scenario.ends_with("-write") || scenario == "extra-argument"
    {
        args.push("requested-value".to_owned());
    }
    if scenario == "extra-argument" {
        args.push("unexpected".to_owned());
    }
    assert_eq!(run_option(&args), None);
    assert_eq!(WRITES.load(std::sync::atomic::Ordering::SeqCst), usize::from(scenario == "write"));
}
