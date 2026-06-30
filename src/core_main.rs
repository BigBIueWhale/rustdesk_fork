#[cfg(any(target_os = "windows", target_os = "macos"))]
use crate::client::translate;
#[cfg(not(debug_assertions))]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::platform::breakdown_callback;
#[cfg(not(debug_assertions))]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::platform::register_breakdown_handler;
use hbb_common::{config, log};
#[cfg(windows)]
use tauri_winrt_notification::{Duration, Sound, Toast};

#[macro_export]
macro_rules! my_println{
    ($($arg:tt)*) => {
        #[cfg(not(windows))]
        println!("{}", format_args!($($arg)*));
        #[cfg(windows)]
        crate::platform::message_box(
            &format!("{}", format_args!($($arg)*))
        );
    };
}

/// shared by flutter and sciter main function
///
/// [Note]
/// If it returns [`None`], then the process will terminate, and flutter gui will not be started.
/// If it returns [`Some`], then the process will continue, and flutter gui will be started.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn core_main() -> Option<Vec<String>> {
    if !crate::common::global_init() {
        return None;
    }
    crate::load_custom_client();
    #[cfg(windows)]
    if !crate::platform::windows::bootstrap() {
        // return None to terminate the process
        return None;
    }
    let mut args = Vec::new();
    let mut flutter_args = Vec::new();
    let mut i = 0;
    // R-X9 (slices 2-4): the --elevate / --run-as-system / --quick_support flags are
    // excised — the portable run-mode and interactive/token-theft elevation they drove
    // are gone; the installed LocalSystem service is the sole controlled entry.
    let mut _is_flutter_invoke_new_connection = false;
    let mut arg_exe = Default::default();
    for arg in std::env::args() {
        if i == 0 {
            arg_exe = arg;
        } else if i > 0 {
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
    let click_setup = cfg!(windows) && args.is_empty() && crate::common::is_setup(&arg_exe);
    if click_setup && !config::is_disable_installation() {
        args.push("--install".to_owned());
        flutter_args.push("--install".to_string());
    }
    if args.contains(&"--noinstall".to_string()) {
        args.clear();
    }
    if args.len() > 0 {
        if args[0] == "--version" {
            println!("{}", crate::VERSION);
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
    // (launch_privileged_process / CreateProcessAsUserW -> `--server` -> `--tray`).
    if args.is_empty() || crate::common::is_empty_uni_link(&args[0]) {
        #[cfg(target_os = "macos")]
        {
            crate::platform::macos::try_remove_temp_update_dir(None);
        }

        #[cfg(windows)]
        {
            crate::platform::try_remove_temp_update_files();
            hbb_common::config::PeerConfig::preload_peers();
        }
        std::thread::spawn(move || crate::start_server(false));
    } else {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        // Root CLI management commands must talk to the user `--server` main IPC.
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

        #[cfg(windows)]
        {
            use crate::platform;
            if args[0] == "--uninstall" {
                if let Err(err) = platform::uninstall_me(true) {
                    log::error!("Failed to uninstall: {}", err);
                }
                return None;
            // R-X1: the `--update` apply-handler is excised with the fetch-and-run
            // updater — the fork ships its own releases (§12), verified by pinned
            // SHA-256 (R-B2), never fetched-and-run.
            } else if args[0] == "--after-install" {
                if let Err(err) = platform::run_after_install() {
                    log::error!("Failed to after-install: {}", err);
                }
                return None;
            } else if args[0] == "--before-uninstall" {
                if let Err(err) = platform::run_before_uninstall() {
                    log::error!("Failed to before-uninstall: {}", err);
                }
                return None;
            } else if args[0] == "--silent-install" {
                if config::is_disable_installation() {
                    return None;
                }
                #[cfg(not(windows))]
                let options = "desktopicon startmenu";
                #[cfg(windows)]
                let options = "desktopicon startmenu printer";
                let res = platform::install_me(options, "".to_owned(), true, args.len() > 1);
                let text = match res {
                    Ok(_) => translate("Installation Successful!".to_string()),
                    Err(err) => {
                        println!("Failed with error: {err}");
                        translate("Installation failed!".to_string())
                    }
                };
                Toast::new(Toast::POWERSHELL_APP_ID)
                    .title(&config::APP_NAME.read().unwrap())
                    .text1(&text)
                    .sound(Some(Sound::Default))
                    .duration(Duration::Short)
                    .show()
                    .ok();
                return None;
            } else if args[0] == "--uninstall-cert" {
                #[cfg(windows)]
                hbb_common::allow_err!(crate::platform::windows::uninstall_cert());
                return None;
            } else if args[0] == "--install-idd" {
                #[cfg(windows)]
                if crate::virtual_display_manager::is_virtual_display_supported() {
                    hbb_common::allow_err!(
                        crate::virtual_display_manager::rustdesk_idd::install_update_driver()
                    );
                }
                return None;
            // R-X9 (slices 2-4): the `--portable-service` arg handler is excised — it
            // dispatched into elevate_or_run_as_system to stand up the portable SYSTEM
            // helper, which is gone.
            } else if args[0] == "--uninstall-amyuni-idd" {
                #[cfg(windows)]
                hbb_common::allow_err!(
                    crate::virtual_display_manager::amyuni_idd::uninstall_driver()
                );
                return None;
            } else if args[0] == "--install-remote-printer" {
                #[cfg(windows)]
                if crate::platform::is_win_10_or_greater() {
                    match remote_printer::install_update_printer(&crate::get_app_name()) {
                        Ok(_) => {
                            log::info!("Remote printer installed/updated successfully");
                        }
                        Err(e) => {
                            log::error!("Failed to install/update the remote printer: {}", e);
                        }
                    }
                } else {
                    log::error!("Win10 or greater required!");
                }
                return None;
            } else if args[0] == "--uninstall-remote-printer" {
                #[cfg(windows)]
                if crate::platform::is_win_10_or_greater() {
                    remote_printer::uninstall_printer(&crate::get_app_name());
                    log::info!("Remote printer uninstalled");
                }
                return None;
            }
        }
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
            log::info!("start --install-service");
            crate::platform::install_service();
            return None;
        } else if args[0] == "--uninstall-service" {
            log::info!("start --uninstall-service");
            crate::platform::uninstall_service(false, true);
            return None;
        } else if args[0] == "--service" {
            log::info!("start --service");
            crate::start_os_service();
            return None;
        } else if args[0] == "--server" {
            log::info!("start --server with user {}", crate::username());
            #[cfg(target_os = "linux")]
            {
                hbb_common::allow_err!(crate::platform::check_autostart_config());
                std::process::Command::new("pkill")
                    .arg("-f")
                    .arg(&format!("{} --tray", crate::get_app_name().to_lowercase()))
                    .status()
                    .ok();
                hbb_common::allow_err!(crate::run_me(vec!["--tray"]));
            }
            #[cfg(windows)]
            crate::privacy_mode::restore_reg_connectivity(true, false);
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
        } else if args[0] == "--password" {
            if is_cli_setting_change_disabled() {
                println!("Settings are disabled!");
                return None;
            }
            if config::Config::is_disable_change_permanent_password() {
                println!("Changing permanent password is disabled!");
                return None;
            }
            if args.len() == 2 {
                // A2/R-D8: provisioning the permanent password requires only the INSTALLED binary
                // that can reach a running `--server`'s per-uid IPC — NOT additionally root. The IPC
                // socket is per-uid (`/tmp/<app>-<uid>/ipc`), mode 0600, gated by SO_PEERCRED +
                // parent-dir hardening (R-S11), so `set_permanent_password` succeeds only for the
                // `--server`'s own uid (the same-uid owner) or root (which reaches the user IPC via
                // `UserMainIpcScope`); any other uid simply fails to connect. Dropping the `is_root()`
                // pre-gate lets an unprivileged owner provision their own box under a per-user
                // supervisor / container (R-D8) WITHOUT the cross-uid `/proc/<pid>/exe` scan that
                // otherwise forces CAP_SYS_PTRACE in a container — the IPC's uid-scoping is the real
                // authorization, not the CLI gate.
                if crate::platform::is_installed() {
                    if let Err(err) = crate::ipc::set_permanent_password(args[1].to_owned()) {
                        println!("{err}");
                    } else {
                        println!("Done!");
                    }
                } else {
                    println!("Run the installed binary to set the permanent password.");
                }
            }
            return None;
        } else if args[0] == "--set-unlock-pin" {
            if config::Config::is_disable_unlock_pin() {
                println!("Unlock PIN is disabled!");
                return None;
            }
            #[cfg(feature = "flutter")]
            if args.len() == 2 {
                if crate::platform::is_installed() && is_root() {
                    if let Err(err) = crate::ipc::set_unlock_pin(args[1].to_owned(), false) {
                        println!("{err}");
                    } else {
                        println!("Done!");
                    }
                } else {
                    println!("Installation and administrative privileges required!");
                }
            }
            return None;
        } else if args[0] == "--get-id" {
            println!("{}", crate::ipc::get_id());
            return None;
        } else if args[0] == "--get-fingerprint" {
            // R-S17: print the box's self-generated Ed25519 host-key fingerprint
            // so the operator can learn it OUT-OF-BAND (over the trusted
            // SSH/console channel they deployed through) and dictate it into the
            // viewer's first-connect known_hosts seed — SSH's "the key
            // fingerprint is …". Computed directly from the persisted local key
            // pair (Config::get_key_pair().1 — stable, the same key the host-proof
            // signature uses), so it needs no running daemon and no network and
            // works headless on the --server box, where no GUI/FFI is shown to
            // reach get_fingerprint (R-R2b). Read-only, like --get-id.
            println!(
                "{}",
                crate::common::pk_to_fingerprint(config::Config::get_key_pair().1)
            );
            return None;
        } else if args[0] == "--pin-host" {
            // R-S17 known_hosts seed (headless): pin a box's Ed25519 host key for an
            // address, learned OUT-OF-BAND from the box's `--get-fingerprint` (whose output
            // IS the key's lowercase hex, space-grouped — strip whitespace and decode). This
            // is SSH's "type yes to the fingerprint", done deliberately rather than on faith:
            // the viewer then refuses any box at that address whose HostIdentity host-proof
            // (R-S17) does not match this key. Seeds ONLY from this explicit operator action,
            // never from a peer message (R-S15).
            if args.len() != 3 {
                println!(
                    "usage: --pin-host <address> <fingerprint-from --get-fingerprint on the box>"
                );
                return None;
            }
            let hex: String = args[2].chars().filter(|c| !c.is_whitespace()).collect();
            let pk: Option<Vec<u8>> =
                if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    (0..64)
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                        .collect()
                } else {
                    None
                };
            match pk {
                Some(pk) => match hbb_common::host_pin::set_pinned_pk(&args[1], &pk) {
                    Ok(()) => {
                        println!("pinned {} -> {}", args[1], crate::common::pk_to_fingerprint(pk))
                    }
                    Err(e) => println!("failed to pin {}: {}", args[1], e),
                },
                None => println!(
                    "invalid host-key fingerprint: need 64 hex chars (the 32-byte Ed25519 key) as printed by `--get-fingerprint`"
                ),
            }
            return None;
        } else if args[0] == "--list-known-hosts" {
            // R-S17: the pinned hosts (the viewer's known_hosts) — address + fingerprint.
            for (addr, hex) in hbb_common::host_pin::list_pinned() {
                let bytes: Option<Vec<u8>> = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or(""), 16).ok())
                    .collect();
                let fp = bytes.map(crate::common::pk_to_fingerprint).unwrap_or(hex);
                println!("{}  {}", addr, fp);
            }
            return None;
        } else if args[0] == "--forget-host" {
            // R-S17 / §19: drop a pin (a legitimately re-keyed box, or a decommissioned one).
            if args.len() != 2 {
                println!("usage: --forget-host <address>");
                return None;
            }
            match hbb_common::host_pin::remove_pinned(&args[1]) {
                Ok(()) => println!("forgot {}", args[1]),
                Err(e) => println!("failed to forget {}: {}", args[1], e),
            }
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
        } else if args[0] == "--check-hwcodec-config" {
            #[cfg(feature = "hwcodec")]
            crate::ipc::hwcodec_process();
            return None;
        } else if args[0] == "--terminal-helper" {
            // Terminal helper process - runs as user to create ConPTY
            // This is needed because ConPTY has compatibility issues with CreateProcessAsUserW
            #[cfg(target_os = "windows")]
            {
                let helper_args: Vec<String> = args[1..].to_vec();
                if let Err(e) = crate::server::terminal_helper::run_terminal_helper(&helper_args) {
                    log::error!("Terminal helper failed: {}", e);
                }
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
    return Some(flutter_args);
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
    let mut param_array = vec![];
    let mut relay_requested = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--connect" | "--play" | "--file-transfer" | "--view-camera" | "--port-forward"
            | "--terminal" | "--rdp" => {
                authority = Some((&arg.to_string()[2..]).to_owned());
                id = args.next();
            }
            "--password" => {
                if let Some(password) = args.next() {
                    param_array.push(format!("password={password}"));
                }
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
            let params = param_array.join("&");
            let params_flag = if params.is_empty() { "" } else { "?" };
            uni_links = format!(
                "{}{}/{}{}{}",
                crate::get_uri_prefix(),
                authority,
                id,
                params_flag,
                params
            );
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
        use winapi::um::winuser::WM_USER;
        let res = crate::platform::send_message_to_hnwd(
            &crate::platform::FLUTTER_RUNNER_WIN32_WINDOW_CLASS,
            &crate::get_app_name(),
            (WM_USER + 2) as _, // referred from unilinks desktop pub
            uni_links.as_str(),
            false,
        );
        return if res { None } else { Some(Vec::new()) };
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
        Some("--password")
            | Some("--set-unlock-pin")
            | Some("--get-id")
            | Some("--option")
            | Some("--assign")
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
        for command in [
            "--password",
            "--set-unlock-pin",
            "--get-id",
            "--option",
            "--assign",
        ] {
            assert!(is_user_main_ipc_scope_cli_command(&args(&[command])));
        }

        for command in [
            "--service",
            "--server",
            "--tray",
            "--cm",
            "--check-hwcodec-config",
            "--connect",
        ] {
            assert!(!is_user_main_ipc_scope_cli_command(&args(&[command])));
        }
    }
}

// R-X9 (slices 2-4): `is_quick_support_exe` is excised — quick-support detection drove
// the now-deleted portable run-mode; the installed-service fork has a single entry path.
