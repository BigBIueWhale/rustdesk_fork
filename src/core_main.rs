#[cfg(not(debug_assertions))]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::platform::breakdown_callback;
#[cfg(not(debug_assertions))]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::platform::register_breakdown_handler;
use hbb_common::{config, log};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::io::{BufRead, IsTerminal, Read as _};

#[cfg(not(any(target_os = "android", target_os = "ios")))]
const PASSWORD_CLI_USAGE: &str = "usage: rustdesk --password | rustdesk --password-stdin";

#[cfg(target_os = "linux")]
const LINUX_SERVICE_OWNED_WORKING_DIRECTORY: &str = "/";

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PasswordCliInput {
    Terminal,
    Stdin,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn password_cli_input(args: &[String]) -> Result<PasswordCliInput, &'static str> {
    match args.first().map(String::as_str) {
        Some("--password") if args.len() == 1 => Ok(PasswordCliInput::Terminal),
        Some("--password-stdin") if args.len() == 1 => Ok(PasswordCliInput::Stdin),
        _ => Err(PASSWORD_CLI_USAGE),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn validate_unattended_password(password: &str) -> Result<(), String> {
    if password.len() > crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES {
        return Err(format!(
            "permanent password exceeds {} bytes",
            crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct SensitivePasswordInput(Vec<u8>);

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for SensitivePasswordInput {
    fn drop(&mut self) {
        crate::ipc::zeroize_sensitive_bytes(&mut self.0);
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_unattended_password_line(
    reader: &mut impl BufRead,
) -> Result<crate::ipc::SensitivePassword, String> {
    let mut bytes = SensitivePasswordInput(Vec::with_capacity(
        crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES + 2,
    ));
    let mut bounded = reader.take((crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES + 2) as u64);
    let read = bounded
        .read_until(b'\n', &mut bytes.0)
        .map_err(|err| format!("failed to read permanent password from stdin: {err}"))?;
    if read == 0 {
        return Err("stdin ended before a permanent password line was read".to_owned());
    }
    if bytes.0.last() == Some(&b'\n') {
        bytes.0.pop();
        if bytes.0.last() == Some(&b'\r') {
            bytes.0.pop();
        }
    }
    if bytes.0.len() > crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES {
        return Err(format!(
            "permanent password exceeds {} bytes",
            crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES
        ));
    }
    match String::from_utf8(std::mem::take(&mut bytes.0)) {
        Ok(password) => Ok(crate::ipc::SensitivePassword::new(password)),
        Err(err) => {
            let mut invalid = err.into_bytes();
            crate::ipc::zeroize_sensitive_bytes(&mut invalid);
            Err("permanent password is not valid UTF-8".to_owned())
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_unattended_password_from_stdin() -> Result<crate::ipc::SensitivePassword, String> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err("--password-stdin requires redirected standard input".to_owned());
    }
    read_unattended_password_line(&mut stdin.lock())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn prompt_unattended_password() -> Result<crate::ipc::SensitivePassword, String> {
    let password = crate::ipc::SensitivePassword::new(
        rpassword::prompt_password("New permanent password: ")
            .map_err(|err| format!("failed to read permanent password from the terminal: {err}"))?,
    );
    validate_unattended_password(password.as_str())?;
    let mut confirmation = crate::ipc::SensitivePassword::new(
        rpassword::prompt_password("Confirm permanent password: ").map_err(|err| {
            format!("failed to read password confirmation from the terminal: {err}")
        })?,
    );
    validate_unattended_password(confirmation.as_str())?;
    let matches = password == confirmation;
    if !confirmation.zeroize() {
        return Err("password confirmation could not be erased".to_owned());
    }
    if !matches {
        return Err("permanent password confirmation does not match".to_owned());
    }
    Ok(password)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn set_cli_permanent_password(
    password: crate::ipc::SensitivePassword,
) -> hbb_common::ResultType<()> {
    crate::ipc::set_permanent_password_sensitive(password)
}

/// shared by flutter and sciter main function
///
/// [Note]
/// If it returns [`None`], then the process will terminate, and flutter gui will not be started.
/// If it returns [`Some`], then the process will continue, and flutter gui will be started.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn core_main() -> Option<Vec<String>> {
    #[cfg(target_os = "linux")]
    let linux_service_owned_config_role = std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--service"))
        || crate::common::is_service_owned_server_process();
    #[cfg(target_os = "linux")]
    if crate::common::is_service_owned_server_process() {
        if let Err(err) = crate::platform::require_service_owned_server_parent_liveness() {
            log::error!(
                "Rejected Linux service-owned --server without a live owning supervisor: {}",
                err
            );
            std::process::exit(1);
        }
    }
    #[cfg(target_os = "linux")]
    if linux_service_owned_config_role {
        if let Err(err) = std::env::set_current_dir(LINUX_SERVICE_OWNED_WORKING_DIRECTORY) {
            log::error!("Linux service-owned working-directory authority failed closed: {err}");
            std::process::exit(1);
        }
    }
    if !crate::common::global_init() {
        return None;
    }
    crate::load_custom_client();
    #[cfg(target_os = "linux")]
    if linux_service_owned_config_role {
        // custom.txt may set the signed app name, but it does not touch Config storage.
        // Bind the service role to its passwd-derived config root before the first
        // Config read, so HOME/XDG_CONFIG_HOME from an init system or sudo policy
        // cannot select the credential namespace.
        if let Err(err) = config::Config::initialize_linux_service_owned_root() {
            log::error!("Linux service-owned config authority failed closed: {err}");
            std::process::exit(1);
        }
    }
    #[cfg(windows)]
    if !crate::platform::windows::bootstrap() {
        // return None to terminate the process
        return None;
    }
    let mut args = Vec::new();
    let mut i = 0;
    // R-X9 (slices 2-4): the --elevate / --run-as-system / --quick_support flags are
    // excised — the portable run-mode and interactive/token-theft elevation they drove
    // are gone; the installed LocalSystem service is the sole controlled entry.
    let mut _is_flutter_invoke_new_connection = false;
    for arg in std::env::args() {
        if i > 0 {
            #[cfg(feature = "flutter")]
            if [
                "--connect",
                "--play",
                "--file-transfer",
                "--view-camera",
                "--port-forward",
                "--terminal",
                "--rdp",
            ]
            .contains(&arg.as_str())
            {
                _is_flutter_invoke_new_connection = true;
            }
            // R-X9 (slices 2-4): the --elevate / --run-as-system / --quick_support arg arms
            // are excised with the portable run-mode + elevation dispatch.
            // R-X10: the --no-server flag is excised (its no_server param was vestigial — the
            // controlled side starts only via the installed --service).
            args.push(arg);
        }
        i += 1;
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    if args.is_empty() {
        #[cfg(target_os = "linux")]
        let should_check_start_tray = crate::check_process("--server", false);
        // We can use `crate::check_process("--server", false)` on Windows.
        // Because `--server` process is the System user's process. We can't get the arguments in `check_process()`.
        // We can assume that self service running means the server is also running on Windows.
        #[cfg(target_os = "windows")]
        let should_check_start_tray = crate::platform::is_self_service_running()
            && crate::platform::is_cur_exe_the_installed();
        if should_check_start_tray && !crate::check_process("--tray", true) {
            #[cfg(target_os = "linux")]
            hbb_common::allow_err!(crate::platform::check_autostart_config());
            hbb_common::allow_err!(crate::run_me(vec!["--tray"]));
        }
    }
    #[cfg(not(debug_assertions))]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    register_breakdown_handler(breakdown_callback);
    #[cfg(target_os = "linux")]
    #[cfg(feature = "flutter")]
    {
        let (k, v) = ("LIBGL_ALWAYS_SOFTWARE", "1");
        if config::option2bool(
            "allow-always-software-render",
            &config::Config::get_option("allow-always-software-render"),
        ) {
            std::env::set_var(k, v);
        } else {
            std::env::remove_var(k);
        }
    }
    #[cfg(windows)]
    if args.contains(&"--connect".to_string()) || args.contains(&"--view-camera".to_string()) {
        hbb_common::platform::windows::start_cpu_performance_monitor();
    }
    #[cfg(feature = "flutter")]
    if _is_flutter_invoke_new_connection {
        return core_main_invoke_new_connection(std::env::args());
    }
    if args.len() > 0 {
        if args[0] == "--version" {
            // Upstream/machine contract: print ONLY the app/wire/package version (numeric), verbatim.
            // res/msi/preprocess.py runs `rustdesk --version`, requires the output to be a numeric
            // version EMBEDDED in the binary (it becomes the WiX ProductVersion), and other tooling
            // parses it too — so the FORK RELEASE identity is a SEPARATE `--fork-version` (below),
            // never mixed in here. (Mixing them broke the MSI build in this release's first attempt.)
            println!("{}", crate::VERSION);
            return None;
        } else if args[0] == "--fork-version" {
            // The fork RELEASE identity (docs/VERSIONING.md): <app-version>-hardened.<N>, embedded at
            // build time from the repo-root FORK_VERSION file (build.rs -> RUSTDESK_FORK_VERSION).
            // crate::VERSION (--version, above) stays the upstream base for tooling + wire negotiation.
            println!("{}", env!("RUSTDESK_FORK_VERSION"));
            return None;
        } else if args[0] == "--build-date" {
            println!("{}", crate::BUILD_DATE);
            return None;
        }
    }
    // R-X9 (slices 2-4): the quick-support detection + `set_quick_support` is excised with
    // the portable run-mode (is_quick_support_exe / pre-elevate-service / is_elevated all
    // fed the now-deleted portable-service start path).
    let mut log_name = "".to_owned();
    if args.len() > 0 && args[0].starts_with("--") {
        let name = args[0].replace("--", "");
        if !name.is_empty() {
            log_name = name;
        }
    }
    hbb_common::init_log(false, &log_name);

    #[cfg(target_os = "linux")]
    if args.first().map(|arg| arg.as_str())
        == Some(crate::platform::linux::REOPEN_AFTER_SERVICE_STOP_ARG)
    {
        let Some(secs) = args.get(1).and_then(|arg| arg.parse::<u32>().ok()) else {
            log::error!("Invalid delayed reopen argument");
            return None;
        };
        if secs > 30 {
            log::error!("Delayed reopen argument is out of range");
            return None;
        }
        crate::platform::linux::reopen_after_service_stop(secs);
        return None;
    }

    // linux uni (url) go here.
    // R-X6: the D-Bus deep-link transport (org.rustdesk.rustdesk `NewConnection`) is excised — a
    // co-installed same-session app could fire it (a local-IPC injection vector) and it claimed the
    // bus name with replace_existing (a name-hijack). A uni-link is now self-handled by this instance
    // (its embedded key/password/relay is stripped per R-X6 before any connect), never forwarded over
    // D-Bus to a running one.
    #[cfg(all(target_os = "linux", feature = "flutter"))]
    if args.len() > 0 && args[0].starts_with(&crate::get_uri_prefix()) {
        return Some(Vec::new());
    }

    // R-X9 (slices 2-4): the Windows run-mode dispatch is excised — the
    // quick-support -> start_portable_service launch and the
    // --elevate/--run-as-system -> elevate_or_run_as_system escalation are gone. On the
    // installed-service fork the controlled side is reached only via `--service`
    // (CreateProcessAsUserW -> `--server` -> `--tray`).
    if args.is_empty() || crate::common::is_empty_uni_link(&args[0]) {
        #[cfg(windows)]
        {
            hbb_common::config::PeerConfig::preload_peers();
        }
        std::thread::spawn(move || crate::start_server(false));
    } else {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        // Root CLI management commands that remain user-owned talk to the user `--server` main IPC.
        // Example: `sudo rustdesk --option custom-rendezvous-server` should query the
        // user's IPC instead of root's `/tmp/<app>-0/ipc`; `connect()` still limits this
        // routing to empty-postfix main IPC only.
        let _user_main_ipc_scope = if crate::platform::is_installed()
            && is_root()
            && is_user_main_ipc_scope_cli_command(&args)
        {
            Some(crate::ipc::UserMainIpcScope::new())
        } else {
            None
        };

        // R-X1: the macOS DMG `--update` apply-handler is excised — it ran the
        // osascript-admin root DMG install (update_from_dmg / update_me); the fork
        // ships its own releases (§12). Its macos.rs source twin is also excised
        // and covered by the Apple source-conformance gate.
        // R-X4: the ungated `--remove <path>` file-delete gadget is excised — it
        // deleted any path with no install/root gate.
        if args[0] == "--tray" {
            if !crate::check_process("--tray", true) {
                crate::tray::start_tray();
            }
            return None;
        } else if args[0] == "--install-service" {
            #[cfg(windows)]
            {
                log::error!("Windows service installation is owned by Windows Installer");
                std::process::exit(1);
            }
            #[cfg(not(windows))]
            {
                log::info!("start --install-service");
                if !crate::platform::install_service() {
                    log::error!("--install-service failed");
                    std::process::exit(1);
                }
            }
            return None;
        } else if args[0] == "--uninstall-service" {
            #[cfg(windows)]
            {
                log::error!("Windows service removal is owned by Windows Installer");
                std::process::exit(1);
            }
            #[cfg(not(windows))]
            {
                log::info!("start --uninstall-service");
                if !crate::platform::uninstall_service(false, true) {
                    log::error!("--uninstall-service failed");
                    std::process::exit(1);
                }
            }
            return None;
        } else if args[0] == "--service" {
            log::info!("start --service");
            #[cfg(target_os = "linux")]
            if let Err(err) = crate::start_os_service() {
                log::error!("Linux service lifecycle authority failed closed: {err}");
                std::process::exit(1);
            }
            #[cfg(not(target_os = "linux"))]
            crate::start_os_service();
            return None;
        } else if args[0] == "--server" {
            log::info!("start --server with user {}", crate::username());
            #[cfg(windows)]
            if crate::common::is_service_owned_server_process() {
                if !crate::platform::is_root() {
                    log::error!("Windows service-owned --server must run as LocalSystem");
                    std::process::exit(1);
                }
                if let Err(err) =
                    crate::platform::windows::require_current_exe_is_fixed_service_runtime()
                {
                    log::error!(
                        "Rejected Windows service-owned --server outside fixed service root: {}",
                        err
                    );
                    std::process::exit(1);
                }
            }
            #[cfg(target_os = "linux")]
            {
                hbb_common::allow_err!(crate::platform::check_autostart_config());
                crate::platform::stop_tray_processes();
                hbb_common::allow_err!(crate::run_me(vec!["--tray"]));
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            {
                crate::start_server(true);
            }
            #[cfg(target_os = "macos")]
            {
                let handler = std::thread::spawn(move || crate::start_server(true));
                crate::tray::start_tray();
                // prevent server exit when encountering errors from tray
                hbb_common::allow_err!(handler.join());
            }
            return None;
        // R-X4: `--import-config <path>` overwrote the entire config (trust anchor +
        // servers) from an attacker-suppliable file with no is_root gate — excised.
        } else if matches!(args[0].as_str(), "--password" | "--password-stdin") {
            let input = match password_cli_input(&args) {
                Ok(input) => input,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
            };
            if is_cli_setting_change_disabled() {
                eprintln!("Settings are disabled!");
                std::process::exit(1);
            }
            if config::Config::is_disable_change_permanent_password() {
                eprintln!("Changing permanent password is disabled!");
                std::process::exit(1);
            }
            let password = match input {
                PasswordCliInput::Terminal => prompt_unattended_password(),
                PasswordCliInput::Stdin => read_unattended_password_from_stdin(),
            };
            let password = match password {
                Ok(password) => password,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(1);
                }
            };
            if let Err(err) = set_cli_permanent_password(password) {
                eprintln!("{err}");
                std::process::exit(1);
            }
            println!("Done!");
            return None;
        } else if args[0] == "--get-id" {
            println!("{}", crate::ipc::get_id());
            return None;
        // R-X4: the `--set-id` (rendezvous-ID change) and `--config` (trust-anchor +
        // server adoption) CLI paths are excised — both presuppose the rendezvous
        // account / anchor this serverless fork removes; the larger account
        // `--assign`/`--deploy` argv-token paths go with the R-D4 account removal.
        } else if args[0] == "--option" {
            if is_cli_setting_change_disabled() {
                println!("Settings are disabled!");
                return None;
            }
            if crate::platform::is_installed() && is_root() {
                if args.len() == 2 {
                    let options = crate::ipc::get_options();
                    println!("{}", options.get(&args[1]).unwrap_or(&"".to_owned()));
                } else if args.len() == 3 {
                    crate::ipc::set_option(&args[1], &args[2]);
                }
            } else {
                println!("Installation and administrative privileges required!");
            }
            return None;
        } else if args[0] == "--assign" {
            if config::Config::no_register_device() {
                println!("Cannot assign an unregistrable device!");
            } else if crate::platform::is_installed() && is_root() {
                let max = args.len() - 1;
                let pos = args.iter().position(|x| x == "--token").unwrap_or(max);
                if pos < max {
                    let token = args[pos + 1].to_owned();
                    let id = crate::ipc::get_id();
                    let uuid = crate::encode64(hbb_common::get_uuid());
                    let get_value = |c: &str| {
                        let pos = args.iter().position(|x| x == c).unwrap_or(max);
                        if pos < max {
                            Some(args[pos + 1].to_owned())
                        } else {
                            None
                        }
                    };
                    let user_name = get_value("--user_name");
                    let strategy_name = get_value("--strategy_name");
                    let address_book_name = get_value("--address_book_name");
                    let address_book_tag = get_value("--address_book_tag");
                    let address_book_alias = get_value("--address_book_alias");
                    let address_book_password = get_value("--address_book_password");
                    let address_book_note = get_value("--address_book_note");
                    let device_group_name = get_value("--device_group_name");
                    let note = get_value("--note");
                    let device_username = get_value("--device_username");
                    let device_name = get_value("--device_name");
                    let mut body = serde_json::json!({
                        "id": id,
                        "uuid": uuid,
                    });
                    let header = "Authorization: Bearer ".to_owned() + &token;
                    if user_name.is_none()
                        && strategy_name.is_none()
                        && address_book_name.is_none()
                        && device_group_name.is_none()
                        && note.is_none()
                        && device_username.is_none()
                        && device_name.is_none()
                    {
                        println!(
                            r#"At least one of the following options is required:
  --user_name
  --strategy_name
  --address_book_name
  --device_group_name
  --note
  --device_username
  --device_name"#
                        );
                    } else {
                        if let Some(name) = user_name {
                            body["user_name"] = serde_json::json!(name);
                        }
                        if let Some(name) = strategy_name {
                            body["strategy_name"] = serde_json::json!(name);
                        }
                        if let Some(name) = address_book_name {
                            body["address_book_name"] = serde_json::json!(name);
                            if let Some(name) = address_book_tag {
                                body["address_book_tag"] = serde_json::json!(name);
                            }
                            if let Some(name) = address_book_alias {
                                body["address_book_alias"] = serde_json::json!(name);
                            }
                            if let Some(name) = address_book_password {
                                body["address_book_password"] = serde_json::json!(name);
                            }
                            if let Some(name) = address_book_note {
                                body["address_book_note"] = serde_json::json!(name);
                            }
                        }
                        if let Some(name) = device_group_name {
                            body["device_group_name"] = serde_json::json!(name);
                        }
                        if let Some(name) = note {
                            body["note"] = serde_json::json!(name);
                        }
                        if let Some(name) = device_username {
                            body["device_username"] = serde_json::json!(name);
                        }
                        if let Some(name) = device_name {
                            body["device_name"] = serde_json::json!(name);
                        }
                        // R-SV6(c) / R-X4 / R-G4 / §18 (dial nobody): the account device-assignment
                        // POST to <api-server>/api/devices/cli is EXCISED — a serverless, direct-IP
                        // fork has no account server to assign devices/strategies/address-books on.
                        // `body`/`header` were assembled above; nothing is sent. (Sibling of the
                        // already-excised `--deploy` /api/devices/deploy POST, R-SV6(c).)
                        let _ = (&body, &header);
                        println!("--assign is not supported: this is a serverless, direct-IP fork (it dials nobody).");
                    }
                } else {
                    println!("--token is required!");
                }
            } else {
                println!("Installation and administrative privileges required!");
            }
            return None;
        // R-SV6(c)/R-X4/§18: the `--deploy` CLI arm is EXCISED. It called
        // ui_interface::deploy_device() to POST {id,uuid,pk}+token to the account
        // server's /api/devices/deploy — account-bound device registration a sovereign,
        // direct-IP fork has no server for (the residual R-X4's --assign/--set-id
        // excision missed). Removed so the egress is structurally absent (R-SV1), not
        // merely pin-safe via the empty api-server; deploy_device itself is gutted to
        // refuse (ui_interface.rs), keeping the flutter FFI signature compiling.
        } else if args[0] == "--terminal-helper" {
            // Terminal helper process - runs as user to create ConPTY
            // This is needed because ConPTY has compatibility issues with CreateProcessAsUserW
            #[cfg(target_os = "windows")]
            {
                let helper_args: Vec<String> = args[1..].to_vec();
                let exit_code =
                    match crate::server::terminal_helper::run_terminal_helper(&helper_args) {
                        Ok(exit_code) => exit_code,
                        Err(err) => {
                            log::error!("Terminal helper failed: {}", err);
                            1
                        }
                    };
                std::process::exit(exit_code);
            }
            return None;
        } else if args[0] == "--cm" {
            // call connection manager to establish connections
            // meanwhile, return true to call flutter window to show control panel
            crate::ui_interface::start_option_status_sync();
        } else if args[0] == "--cm-no-ui" {
            #[cfg(feature = "flutter")]
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                crate::ui_interface::start_option_status_sync();
                crate::flutter::connection_manager::start_cm_no_ui();
            }
            return None;
        } else if args[0] == "--whiteboard" {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                crate::whiteboard::run();
            }
            return None;
        }
    }
    //_async_logger_holder.map(|x| x.flush());
    #[cfg(feature = "flutter")]
    return Some(Vec::new());
    #[cfg(not(feature = "flutter"))]
    return Some(args);
}

/// invoke a new connection
///
/// [Note]
/// this is for invoke new connection from dbus.
/// If it returns [`None`], then the process will terminate, and flutter gui will not be started.
/// If it returns [`Some`], then the process will continue, and flutter gui will be started.
#[cfg(feature = "flutter")]
fn core_main_invoke_new_connection(mut args: std::env::Args) -> Option<Vec<String>> {
    let mut authority = None;
    let mut id = None;
    let mut relay_requested = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--connect" | "--play" | "--file-transfer" | "--view-camera" | "--port-forward"
            | "--terminal" | "--rdp" => {
                authority = Some((&arg.to_string()[2..]).to_owned());
                id = args.next();
            }
            "--password" => {
                // R-X6 (stricter): NEVER fold an embedded credential into the connect URI. A
                // password on argv or in a rustdesk:// link is a footgun — it leaks into shell
                // history, logs, and URL handoff. Consume-and-drop it: the connect proceeds to the
                // address only, and the operator authenticates via the normal password prompt (the
                // CPace secret). The strip holds in BOTH layers — this Rust core AND the Dart
                // handleUriLink parser (spec R-X6; a Dart-only strip is bypassable since the raw URI
                // reaches the core via bind.sendUrlScheme).
                let _ = args.next();
            }
            "--relay" => {
                relay_requested = true;
            }
            _ => {}
        }
    }
    if relay_requested {
        log::warn!("rejecting --relay on direct-only fork");
        return None;
    }
    let mut uni_links = Default::default();
    if let Some(authority) = authority {
        if let Some(mut id) = id {
            let app_name = crate::get_app_name();
            let ext = format!(".{}", app_name.to_lowercase());
            if id.ends_with(&ext) {
                id = id.replace(&ext, "");
            }
            // R-X6 (stricter): the connect URI carries the ADDRESS ONLY — no embedded
            // password/key/relay query params (they are consumed-and-dropped / rejected
            // above), so a link or CLI arg can never convey a credential or trust anchor
            // into URL handoff, nor into the connect it triggers.
            uni_links = format!("{}{}/{}", crate::get_uri_prefix(), authority, id);
        }
    }
    if uni_links.is_empty() {
        return None;
    }

    // R-X6: D-Bus deep-link transport excised — self-handle the uni-link in this instance (no forward).
    #[cfg(target_os = "linux")]
    {
        let _ = &uni_links;
        return Some(Vec::new());
    }

    #[cfg(windows)]
    {
        return if let Err(_) = crate::ipc::send_url_scheme(uni_links) {
            Some(Vec::new())
        } else {
            None
        };
    }
    #[cfg(target_os = "macos")]
    {
        return if let Err(_) = crate::ipc::send_url_scheme(uni_links) {
            Some(Vec::new())
        } else {
            None
        };
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn is_root() -> bool {
    #[cfg(windows)]
    {
        return crate::platform::is_elevated(None).unwrap_or_default()
            || crate::platform::is_root();
    }
    #[allow(unreachable_code)]
    crate::platform::is_root()
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn is_user_main_ipc_scope_cli_command(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("--get-id") | Some("--option") | Some("--assign")
    )
}

#[inline]
fn is_cli_setting_change_disabled() -> bool {
    let option = config::keys::OPTION_ALLOW_COMMAND_LINE_SETTINGS_WHEN_SETTINGS_DISABLED;
    let allow_command_line_settings =
        config::option2bool(option, &crate::get_builtin_option(option));
    config::is_disable_settings() && !allow_command_line_settings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn user_main_ipc_scope_cli_command_matches_management_commands_only() {
        for command in ["--get-id", "--option", "--assign"] {
            assert!(is_user_main_ipc_scope_cli_command(&args(&[command])));
        }

        for command in [
            "--service",
            "--server",
            "--tray",
            "--cm",
            "--password",
            "--password-stdin",
            "--connect",
        ] {
            assert!(!is_user_main_ipc_scope_cli_command(&args(&[command])));
        }
    }

    #[test]
    fn password_cli_rejects_positional_secrets() {
        assert_eq!(
            password_cli_input(&args(&["--password"])),
            Ok(PasswordCliInput::Terminal)
        );
        assert_eq!(
            password_cli_input(&args(&["--password-stdin"])),
            Ok(PasswordCliInput::Stdin)
        );
        assert_eq!(
            password_cli_input(&args(&["--password", "secret"])),
            Err(PASSWORD_CLI_USAGE)
        );
        assert_eq!(
            password_cli_input(&args(&["--password-stdin", "secret"])),
            Err(PASSWORD_CLI_USAGE)
        );
    }

    #[test]
    fn password_stdin_reader_is_line_bounded_and_utf8_only() {
        use std::io::Cursor;

        assert_eq!(
            read_unattended_password_line(&mut Cursor::new(b"secret\n"))
                .unwrap()
                .as_str(),
            "secret"
        );
        assert_eq!(
            read_unattended_password_line(&mut Cursor::new(b"secret\r\n"))
                .unwrap()
                .as_str(),
            "secret"
        );
        assert_eq!(
            read_unattended_password_line(&mut Cursor::new(b"secret"))
                .unwrap()
                .as_str(),
            "secret"
        );
        assert_eq!(
            read_unattended_password_line(&mut Cursor::new(b"\n"))
                .unwrap()
                .as_str(),
            ""
        );
        assert!(read_unattended_password_line(&mut Cursor::new(Vec::<u8>::new())).is_err());
        assert!(read_unattended_password_line(&mut Cursor::new(vec![0xff, b'\n'])).is_err());

        let maximum = "a".repeat(crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES);
        assert_eq!(
            read_unattended_password_line(&mut Cursor::new(format!("{maximum}\n").into_bytes()))
                .unwrap()
                .as_str(),
            maximum
        );
        let oversized = "a".repeat(crate::ipc::UNATTENDED_PASSWORD_MAX_BYTES + 1);
        assert!(read_unattended_password_line(&mut Cursor::new(
            format!("{oversized}\n").into_bytes()
        ))
        .is_err());
    }
}

// R-X9 (slices 2-4): `is_quick_support_exe` is excised — quick-support detection drove
// the now-deleted portable run-mode; the installed-service fork has a single entry path.
