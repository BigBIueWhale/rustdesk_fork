use super::*;

pub fn set_option(key: String, value: String) {
    // R-X9/R-X10: the installed desktop service is ALWAYS present + auto-start and is un-killable at
    // runtime. The `stop-service` set_option special-case (value=="Y" -> uninstall_service, else ->
    // install_service) is REMOVED so NO local UI/FFI/IPC option-write can disable the headless host's
    // service — it was the live service-kill path (the sciter "Enable service"/"Start service" toggle,
    // macos.rs, any ipc::set_option). The key stays pinned "N" + in the is_option_can_save reject set
    // (R-S16/R-S11), so a write now falls through inert. On Android there is no stop-service config toggle at all: the
    // controlled-side stop is the OS foreground-service lifecycle (MainService.onDestroy -> the JNI
    // deactivateServer, which drives the direct listener's exact-generation teardown, R-D7a), not
    // a Config write — so no option-write path reaches the Android listener either.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        match ipc::set_option(&key, &value) {
            Ok(effective) => {
                let mut options = OPTIONS.lock().unwrap();
                if effective.is_empty() {
                    options.remove(&key);
                } else {
                    options.insert(key.clone(), effective);
                }
                if &key == "audio-input" {
                    crate::audio_service::restart();
                }
            }
            Err(err) => log::warn!("Failed to set option via IPC: key={}, err={}", key, err),
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let audio_input = key == "audio-input";
        if let Err(err) = Config::set_option(key, value) {
            log::warn!("Failed to persist option: {err}");
            return;
        }
        if audio_input {
            #[cfg(not(target_os = "ios"))]
            crate::audio_service::restart();
        }
    }
}

pub fn main_set_option(key: String, value: String) {
    #[cfg(target_os = "android")]
    {
        let is_permission_option = key.eq(config::keys::OPTION_ENABLE_CLIPBOARD)
            || key.eq(config::keys::OPTION_ENABLE_FILE_TRANSFER)
            || key.eq(config::keys::OPTION_ENABLE_AUDIO);
        let allow_perm_change_in_accept_window = config::option2bool(
            config::keys::OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW,
            &crate::get_builtin_option(config::keys::OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW),
        );
        if is_permission_option
            && !allow_perm_change_in_accept_window
            && crate::ui_cm_interface::has_active_clients()
        {
            log::info!(
                "blocked main_set_option by policy, key={}, value={}",
                key,
                value
            );
            return;
        }
    }
    // R-S19: the Android `switch_permission_all` push on ENABLE_KEYBOARD / ENABLE_CLIPBOARD toggle
    // is removed with the rest of the runtime permission-widener (`Data::SwitchPermission` is
    // excised). The toggle still persists below and new sessions read it at authorization time,
    // where capabilities are derived from AuthConnType — mid-session widening had no live effect.

    // R-D4/R-G1/R-D5/R-SV6: the mediator-restart-on-network-option-change is REMOVED. Every option it
    // watched is excised or inert — custom-rendezvous-server/api-server are lockdown-pinned, the
    // rendezvous mediator is gone (test_rendezvous_server dials nobody, R-D6), and allow-websocket/
    // disable-udp/allow-insecure-tls-fallback are dead. Just persist the option.
    set_option(key, value.clone());
}
