#[cfg(any(target_os = "android", target_os = "ios"))]
use hbb_common::password_security;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::sleep;
use hbb_common::{
    allow_err,
    bytes::Bytes,
    config::{self, keys::*, Config, LocalConfig, PeerConfig, CONNECT_TIMEOUT},
    directories_next,
    futures::future::join_all,
    log, tokio,
};
use serde_derive::Serialize;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::process::Child;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[cfg(not(any(target_os = "ios")))]
use crate::ipc;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub type Children = Arc<Mutex<(bool, HashMap<(String, String), Child>)>>;

#[derive(Clone, Debug, Serialize)]
pub struct UiStatus {
    #[cfg(not(feature = "flutter"))]
    pub id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginDeviceInfo {
    pub os: String,
    pub r#type: String,
    pub name: String,
}

lazy_static::lazy_static! {
    static ref UI_STATUS : Arc<Mutex<UiStatus>> = Arc::new(Mutex::new(UiStatus{
        #[cfg(not(feature = "flutter"))]
        id: "".to_owned(),
    }));
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
lazy_static::lazy_static! {
    static ref OPTION_SYNCED: Arc<Mutex<bool>> = Default::default();
    static ref OPTIONS : Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(Config::get_options()));
    static ref CHILDREN : Children = Default::default();
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
static OPTION_STATUS_SYNC: std::sync::Once = std::sync::Once::new();

#[cfg(target_os = "windows")]
lazy_static::lazy_static! {
    pub static ref IS_FILE_TRANSFER_ENABLED: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_id() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::get_id();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_id();
}

// R-X1 / R-SV2 (§18): ui_interface::update_me (the cross-platform self-updater dispatch) is excised —
// there is no self-update path; the fork ships SHA-pinned releases (R-B2), never fetch-and-run.

#[inline]
pub fn get_license() -> String {
    // R-X4: the custom_server license (custom-rendezvous-server-from-exe-name) is excised;
    // the fork is direct-IP only, so there is no license to display.
    Default::default()
}

#[inline]
pub fn refresh_options() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        *OPTIONS.lock().unwrap() = Config::get_options();
    }
}

#[inline]
pub fn get_option<T: AsRef<str>>(key: T) -> String {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let map = OPTIONS.lock().unwrap();
        if let Some(v) = map.get(key.as_ref()) {
            v.to_owned()
        } else {
            "".to_owned()
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        Config::get_option(key.as_ref())
    }
}

#[inline]
pub fn use_texture_render() -> bool {
    #[cfg(target_os = "android")]
    return false;
    #[cfg(target_os = "ios")]
    return false;

    #[cfg(target_os = "macos")]
    return cfg!(feature = "flutter")
        && LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) == "Y";

    #[cfg(target_os = "linux")]
    return cfg!(feature = "flutter")
        && LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) != "N";

    #[cfg(target_os = "windows")]
    {
        if !cfg!(feature = "flutter") {
            return false;
        }
        // https://learn.microsoft.com/en-us/windows/win32/sysinfo/targeting-your-application-at-windows-8-1
        #[cfg(debug_assertions)]
        let default_texture = true;
        #[cfg(not(debug_assertions))]
        let default_texture = crate::platform::is_win_10_or_greater();
        if default_texture {
            LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) != "N"
        } else {
            return LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) == "Y";
        }
    }
}

#[inline]
pub fn is_option_fixed(key: &str) -> bool {
    config::OVERWRITE_DISPLAY_SETTINGS
        .read()
        .unwrap()
        .contains_key(key)
        || config::OVERWRITE_LOCAL_SETTINGS
            .read()
            .unwrap()
            .contains_key(key)
        || config::OVERWRITE_SETTINGS.read().unwrap().contains_key(key)
        // R-S16(d): a key pinned by the controlled-side policy funnel is ALSO immutable — its writes are
        // rejected by is_option_can_save / the Config::get_option funnel returns the policy verbatim. The
        // OVERWRITE_* maps only fill from a RustDesk-SIGNED config blob a sovereign fork never has, so without
        // this every PINNED control (Access-Mode, the permission checkboxes, Stop-service, enable-terminal, …)
        // rendered EDITABLE and its write then silently no-op'd / snapped back — a control that does nothing.
        // Reporting pinned keys as fixed greys them, matching the enforced policy (R-G4 / R-X7a / R-X8).
        || config::keys::PINNED_SETTINGS.iter().any(|(k, _)| *k == key)
}

#[inline]
pub fn get_local_option(key: String) -> String {
    crate::get_local_option(&key)
}

#[inline]
#[cfg(feature = "flutter")]
pub fn get_hard_option(key: String) -> String {
    config::HARD_SETTINGS
        .read()
        .unwrap()
        .get(&key)
        .cloned()
        .unwrap_or_default()
}

#[inline]
pub fn get_builtin_option(key: &str) -> String {
    crate::get_builtin_option(key)
}

#[inline]
pub fn set_local_option(key: String, value: String) {
    LocalConfig::set_option(key.clone(), value);
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_local_flutter_option(key: String) -> String {
    LocalConfig::get_flutter_option(&key)
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn set_local_flutter_option(key: String, value: String) {
    LocalConfig::set_flutter_option(key, value);
}

#[cfg(feature = "flutter")]
#[inline]
pub fn get_kb_layout_type() -> String {
    LocalConfig::get_kb_layout_type()
}

#[cfg(feature = "flutter")]
#[inline]
pub fn set_kb_layout_type(kb_layout_type: String) {
    LocalConfig::set_kb_layout_type(kb_layout_type);
}

#[inline]
pub fn peer_has_password(id: String) -> bool {
    // R-S16 (viewer twin): under the R-T15c collapse the remembered credential is the derived
    // CPace PRS (`password_prs`), not the dead legacy salted-hash `password` — so a peer "has a
    // saved password" if EITHER is set, else the forget affordance would never surface for a
    // PRS-remembered peer.
    let c = PeerConfig::load(&id);
    !c.password.is_empty() || !c.password_prs.is_empty()
}

#[inline]
pub fn forget_password(id: String) {
    let mut c = PeerConfig::load(&id);
    c.password.clear();
    // R-S16 (viewer twin): also clear the derived CPace PRS — it is the connect-equivalent
    // credential under the collapse, so "unremember password" MUST drop it too, not leave it at
    // rest (else the peer stays connectable after the operator asked to forget it).
    c.password_prs.clear();
    c.store(&id);
}

#[inline]
pub fn get_peer_option(id: String, name: String) -> String {
    let c = PeerConfig::load(&id);
    c.options.get(&name).unwrap_or(&"".to_owned()).to_owned()
}

#[inline]
#[cfg(feature = "flutter")]
pub fn get_peer_flutter_option(id: String, name: String) -> String {
    let c = PeerConfig::load(&id);
    c.ui_flutter.get(&name).unwrap_or(&"".to_owned()).to_owned()
}

#[inline]
#[cfg(feature = "flutter")]
pub fn set_peer_flutter_option(id: String, name: String, value: String) {
    let mut c = PeerConfig::load(&id);
    if value.is_empty() {
        c.ui_flutter.remove(&name);
    } else {
        c.ui_flutter.insert(name, value);
    }
    c.store(&id);
}

#[inline]
pub fn set_peer_option(id: String, name: String, value: String) {
    let mut c = PeerConfig::load(&id);
    if value.is_empty() {
        c.options.remove(&name);
    } else {
        c.options.insert(name, value);
    }
    c.store(&id);
}

#[inline]
pub fn get_options() -> String {
    let options = {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            OPTIONS.lock().unwrap()
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            Config::get_options()
        }
    };
    let mut m = serde_json::Map::new();
    for (k, v) in options.iter() {
        m.insert(k.into(), v.to_owned().into());
    }
    serde_json::to_string(&m).unwrap_or_default()
}

#[inline]
#[cfg(feature = "flutter")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_sound_inputs() -> Vec<String> {
    let mut a = Vec::new();
    #[cfg(not(target_os = "linux"))]
    {
        fn get_sound_inputs_() -> Vec<String> {
            let mut out = Vec::new();
            use cpal::traits::{DeviceTrait, HostTrait};
            // Do not use `cpal::host_from_id(cpal::HostId::ScreenCaptureKit)` for feature = "screencapturekit"
            // Because we explicitly handle the "System Sound" device.
            let host = cpal::default_host();
            if let Ok(devices) = host.devices() {
                for device in devices {
                    if device.default_input_config().is_err() {
                        continue;
                    }
                    if let Ok(name) = device.name() {
                        out.push(name);
                    }
                }
            }
            out
        }

        let inputs = Arc::new(Mutex::new(Vec::new()));
        let cloned = inputs.clone();
        // can not call below in UI thread, because conflict with sciter sound com initialization
        std::thread::spawn(move || *cloned.lock().unwrap() = get_sound_inputs_())
            .join()
            .ok();
        for name in inputs.lock().unwrap().drain(..) {
            a.push(name);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let inputs: Vec<String> = crate::platform::linux::get_pa_sources()
            .drain(..)
            .map(|x| x.1)
            .collect();

        for name in inputs {
            a.push(name);
        }
    }
    a
}

#[inline]
pub fn set_option(key: String, value: String) {
    // R-X9/R-X10: the installed desktop service is ALWAYS present + auto-start and is un-killable at
    // runtime. The `stop-service` set_option special-case (value=="Y" -> uninstall_service, else ->
    // install_service) is REMOVED so NO local UI/FFI/IPC option-write can disable the headless host's
    // service — it was the live service-kill path (the sciter "Enable service"/"Start service" toggle,
    // macos.rs, any ipc::set_option). The key stays pinned "N" + in the is_option_can_save reject set
    // (R-S16/R-S11), so a write now falls through inert. On Android there is no stop-service config toggle at all: the
    // controlled-side stop is the OS foreground-service lifecycle (MainService.onDestroy -> the JNI
    // stopServer, which drives the direct listener's service-owned-generation teardown, R-D7a), not
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
        if &key == "audio-input" {
            #[cfg(not(target_os = "ios"))]
            crate::audio_service::restart();
        }
        Config::set_option(key, value);
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[inline]
pub fn is_installed() -> bool {
    crate::platform::is_installed()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[inline]
pub fn is_installed() -> bool {
    false
}

#[inline]
pub fn is_share_rdp() -> bool {
    #[cfg(windows)]
    return crate::platform::windows::is_share_rdp();
    #[cfg(not(windows))]
    return false;
}

#[inline]
pub fn set_share_rdp(_enable: bool) {
    #[cfg(windows)]
    if let Err(err) = crate::ipc::set_service_owned_share_rdp(_enable) {
        log::warn!("Failed to set RDP session sharing through Windows service: {err}");
    }
}

#[inline]
pub fn is_installed_lower_version() -> bool {
    #[cfg(not(windows))]
    return false;
    #[cfg(windows)]
    {
        let b = crate::platform::windows::installed_build_date();
        return crate::BUILD_DATE.cmp(&b).is_gt();
    }
}

// R-X7: temporary_password()/update_temporary_password() removed with the OTP credential.

#[inline]
pub fn is_permanent_password_set() -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::has_permanent_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        ipc::is_permanent_password_set()
    }
}

#[inline]
pub fn is_local_permanent_password_set() -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::has_local_permanent_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        ipc::is_local_permanent_password_set()
    }
}

pub fn can_set_user_owned_permanent_password() -> bool {
    if config::Config::is_disable_change_permanent_password() {
        return false;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        return true;
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        crate::ipc::can_set_user_owned_permanent_password()
    }
}

pub fn can_set_permanent_password() -> bool {
    if config::Config::is_disable_change_permanent_password() {
        return false;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        return true;
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        crate::ipc::can_set_permanent_password()
    }
}

pub fn set_permanent_password_with_result(password: String) -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        if !can_set_permanent_password() {
            return false;
        }
        return config::Config::set_permanent_password(&password);
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let password = crate::ipc::SensitivePassword::new(password);
        match crate::ipc::set_permanent_password_sensitive(password) {
            Ok(()) => true,
            Err(err) => {
                log::warn!("Failed to set permanent password: {err}");
                false
            }
        }
    }
}

#[inline]
pub fn get_peer(id: String) -> PeerConfig {
    PeerConfig::load(&id)
}

#[inline]
pub fn get_fav() -> Vec<String> {
    LocalConfig::get_fav()
}

#[inline]
pub fn store_fav(fav: Vec<String>) {
    LocalConfig::set_fav(fav);
}

#[inline]
pub fn is_process_trusted(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_process_trusted(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
pub fn is_can_screen_recording(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_can_screen_recording(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
pub fn is_installed_daemon(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_installed_daemon(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
#[cfg(feature = "flutter")]
pub fn is_can_input_monitoring(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_can_input_monitoring(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
pub fn get_error() -> String {
    #[cfg(not(any(feature = "cli")))]
    #[cfg(target_os = "linux")]
    {
        let dtype = crate::platform::linux::get_display_server();
        if crate::platform::linux::DISPLAY_SERVER_WAYLAND == dtype {
            return crate::server::wayland::common_get_error();
        }
        if dtype != crate::platform::linux::DISPLAY_SERVER_X11 {
            return format!(
                "{} {}, {}",
                crate::client::translate("Unsupported display server".to_owned()),
                dtype,
                crate::client::translate("x11 expected".to_owned()),
            );
        }
    }
    return "".to_owned();
}

#[inline]
pub fn is_login_wayland() -> bool {
    #[cfg(target_os = "linux")]
    return crate::platform::linux::is_login_wayland();
    #[cfg(not(target_os = "linux"))]
    return false;
}

#[inline]
pub fn current_is_wayland() -> bool {
    #[cfg(target_os = "linux")]
    return crate::platform::linux::current_is_wayland();
    #[cfg(not(target_os = "linux"))]
    return false;
}

#[inline]
pub fn get_version() -> String {
    crate::VERSION.to_owned()
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_app_name() -> String {
    crate::get_app_name()
}

#[cfg(windows)]
#[inline]
pub fn create_shortcut(_id: String) {
    if let Err(err) = crate::platform::windows::create_shortcut(&_id) {
        log::error!("Failed to create shortcut: {err}");
    }
}

#[cfg(feature = "flutter")]
pub fn peer_to_map(id: String, p: PeerConfig) -> HashMap<&'static str, String> {
    use hbb_common::sodiumoxide::base64;
    HashMap::<&str, String>::from_iter([
        ("id", id),
        ("username", p.info.username.clone()),
        ("hostname", p.info.hostname.clone()),
        ("platform", p.info.platform.clone()),
        (
            "alias",
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ),
        (
            "hash",
            base64::encode(p.password, base64::Variant::Original),
        ),
    ])
}

#[cfg(feature = "flutter")]
pub fn peer_exists(id: &str) -> bool {
    PeerConfig::exists(id)
}

#[inline]
pub fn get_uuid() -> String {
    crate::encode64(hbb_common::get_uuid())
}

// R-SV5 / R-G4: the numeric-RustDesk-ID change flow (`change_id` + the `async_job_status`
// progress mechanism it was the sole user of) is excised — the fork connects by direct address,
// not by a mutable numeric ID (there is no rendezvous to register a new ID with), and the Sciter
// Change-ID UI + the `main_change_id`/`main_get_async_status` FFIs are gone.

#[inline]
pub fn get_langs() -> String {
    use serde_json::json;
    let mut x: Vec<(&str, String)> = crate::lang::LANGS
        .iter()
        .map(|a| (a.0, format!("{} ({})", a.1, a.0)))
        .collect();
    x.sort_by(|a, b| a.0.cmp(b.0));
    json!(x).to_string()
}

#[inline]
pub fn video_save_directory(root: bool) -> String {
    let appname = crate::get_app_name();
    // ui process can show it correctly Once vidoe process created it.
    let try_create = |path: &std::path::Path| {
        if !path.exists() {
            std::fs::create_dir_all(path).ok();
        }
        if path.exists() {
            path.to_string_lossy().to_string()
        } else {
            "".to_string()
        }
    };

    if root {
        // Currently, only installed windows run as root
        #[cfg(windows)]
        {
            return match crate::platform::windows::program_data_dir() {
                Ok(program_data) => program_data
                    .join(&appname)
                    .join("recording")
                    .to_string_lossy()
                    .to_string(),
                Err(err) => {
                    log::error!("Failed to resolve ProgramData recording directory: {err}");
                    String::new()
                }
            };
        }
    }
    // Get directory from config file otherwise --server will use the old value from global var.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let dir = LocalConfig::get_option_from_file(OPTION_VIDEO_SAVE_DIRECTORY);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let dir = LocalConfig::get_option(OPTION_VIDEO_SAVE_DIRECTORY);
    if !dir.is_empty() {
        return dir;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    if let Ok(home) = config::APP_HOME_DIR.read() {
        let mut path = home.to_owned();
        path.push_str(format!("/{appname}/ScreenRecord").as_str());
        let dir = try_create(&std::path::Path::new(&path));
        if !dir.is_empty() {
            return dir;
        }
    }

    if let Some(user) = directories_next::UserDirs::new() {
        if let Some(video_dir) = user.video_dir() {
            let dir = try_create(&video_dir.join(&appname));
            if !dir.is_empty() {
                return dir;
            }
            if video_dir.exists() {
                return video_dir.to_string_lossy().to_string();
            }
        }
        if let Some(desktop_dir) = user.desktop_dir() {
            if desktop_dir.exists() {
                return desktop_dir.to_string_lossy().to_string();
            }
        }
        let home = user.home_dir();
        if home.exists() {
            return home.to_string_lossy().to_string();
        }
    }

    // same order as above
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Some(home) = crate::platform::get_active_user_home() {
        let name = if cfg!(target_os = "macos") {
            "Movies"
        } else {
            "Videos"
        };
        let video_dir = home.join(name);
        let dir = try_create(&video_dir.join(&appname));
        if !dir.is_empty() {
            return dir;
        }
        if video_dir.exists() {
            return video_dir.to_string_lossy().to_string();
        }
        let desktop_dir = home.join("Desktop");
        if desktop_dir.exists() {
            return desktop_dir.to_string_lossy().to_string();
        }
        if home.exists() {
            return home.to_string_lossy().to_string();
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let dir = try_create(&parent.join("videos"));
            if !dir.is_empty() {
                return dir;
            }
            // basically exist
            return parent.to_string_lossy().to_string();
        }
    }
    Default::default()
}

#[inline]
pub fn has_hwcodec() -> bool {
    // Has real hardware codec using gpu
    (cfg!(feature = "hwcodec") && cfg!(not(target_os = "ios"))) || cfg!(feature = "mediacodec")
}

#[inline]
pub fn has_vram() -> bool {
    cfg!(feature = "vram")
}

// R-R2b / R-G1 (§18/§19): supported_hwdecodings (the H264/H265 decode-ability the excised Default-Codec
// radios read via the main_supported_hwdecodings FFI, removed with them) is excised — the FFI was its
// sole caller. hwcodec/vram/mediacodec are compiled out and AV1/libaom is absent, so it only ever returned
// (false, false). scrap::codec::Decoder::supported_decodings — the LIVE protocol decode-ability path —
// is deliberately retained; only this UI-only wrapper is gone.

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[inline]
pub fn is_root() -> bool {
    crate::platform::is_root()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[inline]
pub fn is_root() -> bool {
    false
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn check_super_user_permission() -> bool {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    return crate::platform::check_super_user_permission().unwrap_or(false);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    return true;
}

#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
pub fn check_zombie() {
    let mut deads = Vec::new();
    loop {
        let mut lock = CHILDREN.lock().unwrap();
        let mut n = 0;
        for (id, c) in lock.1.iter_mut() {
            if let Ok(Some(_)) = c.try_wait() {
                deads.push(id.clone());
                n += 1;
            }
        }
        for ref id in deads.drain(..) {
            lock.1.remove(id);
        }
        if n > 0 {
            lock.0 = true;
        }
        drop(lock);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
pub fn recent_sessions_updated() -> bool {
    let mut children = CHILDREN.lock().unwrap();
    if children.0 {
        children.0 = false;
        true
    } else {
        false
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
pub fn new_remote(id: String, remote_type: String) {
    let mut lock = CHILDREN.lock().unwrap();
    let args = vec![format!("--{}", remote_type), id.clone()];
    let key = (id.clone(), remote_type.clone());
    if let Some(c) = lock.1.get_mut(&key) {
        if let Ok(Some(_)) = c.try_wait() {
            lock.1.remove(&key);
        } else {
            if remote_type == "rdp" {
                allow_err!(c.kill());
                std::thread::sleep(std::time::Duration::from_millis(30));
                c.try_wait().ok();
                lock.1.remove(&key);
            } else {
                return;
            }
        }
    }
    match crate::run_me(args) {
        Ok(child) => {
            lock.1.insert(key, child);
        }
        Err(err) => {
            log::error!("Failed to spawn remote: {}", err);
        }
    }
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn start_main_status_sync() {
    OPTION_STATUS_SYNC.call_once(|| {
        if let Err(err) = std::thread::Builder::new()
            .name("main-ipc-status".to_owned())
            .spawn(sync_main_status)
        {
            log::error!("Failed to start main IPC status synchronization: {err}");
        }
    });
}

#[cfg(feature = "flutter")]
pub fn set_user_default_option(key: String, value: String) {
    use hbb_common::config::UserDefaultConfig;
    UserDefaultConfig::load().set(key, value);
}

#[cfg(feature = "flutter")]
pub fn get_user_default_option(key: String) -> String {
    use hbb_common::config::UserDefaultConfig;
    UserDefaultConfig::load().get(&key)
}

#[inline]
pub fn get_login_device_info() -> LoginDeviceInfo {
    LoginDeviceInfo {
        // std::env::consts::OS is better than whoami::platform() here.
        os: std::env::consts::OS.to_owned(),
        r#type: "client".to_owned(),
        name: crate::common::hostname(),
    }
}

#[inline]
pub fn get_login_device_info_json() -> String {
    serde_json::to_string(&get_login_device_info()).unwrap_or("{}".to_string())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn sync_main_status() {
    let is_cm = crate::common::is_cm();
    let mut was_connected = false;

    loop {
        match ipc::get_main_status_snapshot(1000).await {
            Ok(snapshot) => {
                was_connected = true;
                let options = match snapshot.options.into_map() {
                    Ok(options) => options,
                    Err(err) => {
                        log::error!("Main IPC returned invalid status options: {err}");
                        sleep(1.).await;
                        continue;
                    }
                };
                *OPTIONS.lock().unwrap() = options;
                *OPTION_SYNCED.lock().unwrap() = true;
                *UI_STATUS.lock().unwrap() = UiStatus {
                    #[cfg(not(feature = "flutter"))]
                    id: snapshot.id,
                };
                #[cfg(target_os = "windows")]
                if let Some(enabled) = snapshot.file_transfer_enabled {
                    let mut current = IS_FILE_TRANSFER_ENABLED.lock().unwrap();
                    if *current != Some(enabled) {
                        clipboard::ContextSend::enable(enabled);
                        *current = Some(enabled);
                    }
                }
            }
            Err(err) => {
                log::trace!("Main IPC status transaction failed: {err}");
                if was_connected && is_cm {
                    crate::ui_cm_interface::quit_cm();
                    return;
                }
            }
        };
        sleep(1.).await;
    }
}

#[allow(dead_code)]
pub fn option_synced() -> bool {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        OPTION_SYNCED.lock().unwrap().clone()
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        true
    }
}

// R-G6/R-SV4: relay-route suffixes (`/r`, `/r@server`) are dead on this direct-only fork (no relay).
// The `handle_relay_id` identity shim + its `main_handle_relay_id` FFI are excised — there is no
// Change-ID / relay-address UI left to feed them.

pub fn support_remove_wallpaper() -> bool {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    return crate::platform::WallPaperRemover::support();
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    return false;
}

pub fn check_hwcodec() {}

#[cfg(feature = "flutter")]
pub fn max_encrypt_len() -> usize {
    hbb_common::config::ENCRYPT_MAX_LEN
}
