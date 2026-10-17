#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use librustdesk::*;

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
fn main() {
    if !common::global_init() {
        eprintln!("Global initialization failed.");
        return;
    }
    common::global_clean();
}

// R-B6/R-R2: the non-flutter, non-cli desktop build is now HEADLESS. The legacy Sciter GUI
// (`ui::start`) is deleted; Flutter is the sole shipped front-end (§19). This build target exists
// only as the docker compile/verify proxy and the `--server` runtime — `core_main()` fully handles
// the controlled-side argv (`--server`/`--service`/`--password`, …) and returns
// `Some(args)` only when a GUI would have been launched, which this build cannot do. So when the GUI
// is requested there is nothing to start; the headless build simply finishes. (No shipped artifact
// takes this path: every shipped target builds `--flutter`.)
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "cli",
    feature = "flutter"
)))]
fn main() {
    #[cfg(all(windows, not(feature = "inline")))]
    unsafe {
        winapi::um::shellscalingapi::SetProcessDpiAwareness(2);
    }
    if crate::core_main::core_main().is_some() {
        eprintln!(
            "This is the headless build (Sciter GUI removed, R-B6). The graphical viewer is the \
             Flutter build; run the controlled side with --server / --service."
        );
    }
    common::global_clean();
}

#[cfg(feature = "cli")]
fn main() {
    if !common::global_init() {
        return;
    }
    use hbb_common::log;
    let matches = cli_command::command().get_matches();
    use hbb_common::env_logger::*;
    init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    if let Some(p) = matches.get_one::<String>("port-forward") {
        let options: Vec<String> = p.split(":").map(|x| x.to_owned()).collect();
        if options.len() < 3 {
            log::error!("Wrong port-forward options");
            return;
        }
        let mut port = 0;
        if let Ok(v) = options[1].parse::<i32>() {
            port = v;
        } else {
            log::error!("Wrong local-port");
            return;
        }
        let mut remote_port = 0;
        if let Ok(v) = options[2].parse::<i32>() {
            remote_port = v;
        } else {
            log::error!("Wrong remote-port");
            return;
        }
        let mut remote_host = "localhost".to_owned();
        if options.len() > 3 {
            remote_host = options[3].clone();
        }
        cli::start_one_port_forward(options[0].clone(), port, remote_host, remote_port);
    } else if let Some(p) = matches.get_one::<String>("connect") {
        cli::connect_test(p);
    } else if matches.get_flag("server") {
        crate::start_server(true);
    }
    common::global_clean();
}
