use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, RwLock},
    task::Poll,
};

use serde_json::{json, Map, Value};

#[cfg(not(target_os = "ios"))]
use hbb_common::whoami;
use hbb_common::{
    anyhow::anyhow,
    bail, base64,
    config::{self, keys, Config, LocalConfig},
    futures_util::future::poll_fn,
    get_version_number, log,
    message_proto::*,
    protobuf::{Enum, Message as _},
    rendezvous_proto::*,
    socket_client,
    sodiumoxide::crypto::sign,
    tokio::{
        self,
        time::{Duration, Instant, Interval},
    },
    ResultType,
};

use crate::ui_interface::{get_option, set_option};

#[derive(Debug, Eq, PartialEq)]
pub enum GrabState {
    Ready,
    Run,
    Wait,
    Exit,
}

pub type NotifyMessageBox = fn(String, String, String, String) -> dyn Future<Output = ()>;

// the executable name of the portable version
pub const PORTABLE_APPNAME_RUNTIME_ENV_KEY: &str = "RUSTDESK_APPNAME";

pub const PLATFORM_WINDOWS: &str = "Windows";
pub const PLATFORM_LINUX: &str = "Linux";
pub const PLATFORM_MACOS: &str = "Mac OS";
pub const PLATFORM_ANDROID: &str = "Android";

pub const TIMER_OUT: Duration = Duration::from_secs(1);
pub const DEFAULT_KEEP_ALIVE: i32 = 60_000;

const MIN_VER_MULTI_UI_SESSION: &str = "1.2.4";

pub mod input {
    pub const MOUSE_TYPE_MOVE: i32 = 0;
    pub const MOUSE_TYPE_DOWN: i32 = 1;
    pub const MOUSE_TYPE_UP: i32 = 2;
    pub const MOUSE_TYPE_WHEEL: i32 = 3;
    pub const MOUSE_TYPE_TRACKPAD: i32 = 4;
    /// Relative mouse movement type for gaming/3D applications.
    /// This type sends delta (dx, dy) values instead of absolute coordinates.
    /// NOTE: This is only supported by the Flutter client. The Sciter client (deprecated)
    /// does not support relative mouse mode due to:
    /// 1. Fixed send_mouse() function signature that doesn't allow type differentiation
    /// 2. Lack of pointer lock API in Sciter/TIS
    /// 3. No OS cursor control (hide/show/clip) FFI bindings in Sciter UI
    pub const MOUSE_TYPE_MOVE_RELATIVE: i32 = 5;

    /// Mask to extract the mouse event type from the mask field.
    /// The lower 3 bits contain the event type (MOUSE_TYPE_*), giving a valid range of 0-7.
    /// Currently defined types use values 0-5; values 6 and 7 are reserved for future use.
    pub const MOUSE_TYPE_MASK: i32 = 0x7;

    pub const MOUSE_BUTTON_LEFT: i32 = 0x01;
    pub const MOUSE_BUTTON_RIGHT: i32 = 0x02;
    pub const MOUSE_BUTTON_WHEEL: i32 = 0x04;
    pub const MOUSE_BUTTON_BACK: i32 = 0x08;
    pub const MOUSE_BUTTON_FORWARD: i32 = 0x10;
}

lazy_static::lazy_static! {
    pub static ref DEVICE_ID: Arc<Mutex<String>> = Default::default();
    pub static ref DEVICE_NAME: Arc<Mutex<String>> = Default::default();
}

lazy_static::lazy_static! {
    // Is server process, with "--server" args
    static ref IS_SERVER: bool = std::env::args().nth(1) == Some("--server".to_owned());
    // Is server logic running. The server code can invoked to run by the main process if --server is not running.
    static ref SERVER_RUNNING: Arc<RwLock<bool>> = Default::default();
    static ref IS_MAIN: bool = std::env::args().nth(1).map_or(true, |arg| !arg.starts_with("--"));
    static ref IS_CM: bool = std::env::args().nth(1) == Some("--cm".to_owned()) || std::env::args().nth(1) == Some("--cm-no-ui".to_owned());
}

pub const SERVICE_OWNED_SERVER_ARG: &str = "--service-owned-server";
#[cfg(target_os = "linux")]
pub const SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV: &str =
    "RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT";
#[cfg(target_os = "linux")]
pub const SERVICE_OWNED_SERVER_GENERATION_ENV: &str = "RUSTDESK_SERVICE_OWNED_SERVER_GENERATION";
#[cfg(target_os = "linux")]
pub const SERVICE_OWNED_SERVER_EXECUTABLE_FD_ENV: &str =
    "RUSTDESK_SERVICE_OWNED_SERVER_EXECUTABLE_FD";
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub const CM_LAUNCH_TOKEN_ENV: &str = "RUSTDESK_CM_LAUNCH_TOKEN";
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub const CM_LAUNCH_PARENT_ENV: &str = "RUSTDESK_CM_LAUNCH_PARENT";
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub const WHITEBOARD_LAUNCH_TOKEN_ENV: &str = "RUSTDESK_WHITEBOARD_LAUNCH_TOKEN";
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub const WHITEBOARD_LAUNCH_PARENT_ENV: &str = "RUSTDESK_WHITEBOARD_LAUNCH_PARENT";

pub fn is_service_owned_server_process() -> bool {
    std::env::args_os().any(|arg| arg == std::ffi::OsStr::new(SERVICE_OWNED_SERVER_ARG))
}

pub struct SimpleCallOnReturn {
    pub b: bool,
    pub f: Box<dyn Fn() + Send + 'static>,
}

impl Drop for SimpleCallOnReturn {
    fn drop(&mut self) {
        if self.b {
            (self.f)();
        }
    }
}

pub fn global_init() -> bool {
    #[cfg(target_os = "linux")]
    {
        if !crate::platform::linux::is_x11() {
            crate::server::wayland::init();
        }
    }
    true
}

pub fn global_clean() {}

#[inline]
pub fn set_server_running(b: bool) {
    *SERVER_RUNNING.write().unwrap() = b;
}

#[inline]
pub fn is_support_multi_ui_session(ver: &str) -> bool {
    is_support_multi_ui_session_num(hbb_common::get_version_number(ver))
}

#[inline]
pub fn is_support_multi_ui_session_num(ver: i64) -> bool {
    ver >= hbb_common::get_version_number(MIN_VER_MULTI_UI_SESSION)
}

#[inline]
#[cfg(feature = "unix-file-copy-paste")]
pub fn is_support_file_copy_paste(ver: &str) -> bool {
    is_support_file_copy_paste_num(hbb_common::get_version_number(ver))
}

#[inline]
#[cfg(feature = "unix-file-copy-paste")]
pub fn is_support_file_copy_paste_num(ver: i64) -> bool {
    ver >= hbb_common::get_version_number("1.3.8")
}

pub fn is_support_file_paste_if_macos(ver: &str) -> bool {
    hbb_common::get_version_number(ver) >= hbb_common::get_version_number("1.3.9")
}

#[inline]
pub fn is_support_screenshot(ver: &str) -> bool {
    is_support_multi_ui_session_num(hbb_common::get_version_number(ver))
}

#[inline]
pub fn is_support_screenshot_num(ver: i64) -> bool {
    ver >= hbb_common::get_version_number("1.4.0")
}

#[inline]
pub fn is_support_file_transfer_resume(ver: &str) -> bool {
    is_support_file_transfer_resume_num(hbb_common::get_version_number(ver))
}

#[inline]
pub fn is_support_file_transfer_resume_num(ver: i64) -> bool {
    ver >= hbb_common::get_version_number("1.4.2")
}

/// Minimum server version required for relative mouse mode support.
/// This constant must mirror Flutter's `kMinVersionForRelativeMouseMode` in `consts.dart`.
const MIN_VERSION_RELATIVE_MOUSE_MODE: &str = "1.4.5";

#[inline]
pub fn is_support_relative_mouse_mode(ver: &str) -> bool {
    is_support_relative_mouse_mode_num(hbb_common::get_version_number(ver))
}

#[inline]
pub fn is_support_relative_mouse_mode_num(ver: i64) -> bool {
    ver >= hbb_common::get_version_number(MIN_VERSION_RELATIVE_MOUSE_MODE)
}

// is server process, with "--server" args
#[inline]
pub fn is_server() -> bool {
    *IS_SERVER
}

#[inline]
pub fn need_fs_cm_send_files() -> bool {
    #[cfg(windows)]
    {
        is_server()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[inline]
pub fn is_main() -> bool {
    *IS_MAIN
}

#[inline]
pub fn is_cm() -> bool {
    *IS_CM
}

// Is server logic running.
#[inline]
pub fn is_server_running() -> bool {
    *SERVER_RUNNING.read().unwrap()
}

#[inline]
pub fn valid_for_numlock(evt: &KeyEvent) -> bool {
    if let Some(key_event::Union::ControlKey(ck)) = evt.union {
        let v = ck.value();
        (v >= ControlKey::Numpad0.value() && v <= ControlKey::Numpad9.value())
            || v == ControlKey::Decimal.value()
    } else {
        false
    }
}

/// Set sound input device.
pub fn set_sound_input(device: String) {
    let prior_device = get_option("audio-input".to_owned());
    if prior_device != device {
        log::info!("switch to audio input device {}", device);
        std::thread::spawn(move || {
            set_option("audio-input".to_owned(), device);
        });
    } else {
        log::info!("audio input is already set to {}", device);
    }
}

/// Get system's default sound input device name.
#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_default_sound_input() -> Option<String> {
    #[cfg(not(target_os = "linux"))]
    {
        use cpal::traits::{DeviceTrait, HostTrait};
        let host = cpal::default_host();
        let dev = host.default_input_device();
        return if let Some(dev) = dev {
            match dev.name() {
                Ok(name) => Some(name),
                Err(_) => None,
            }
        } else {
            None
        };
    }
    #[cfg(target_os = "linux")]
    {
        let input = crate::platform::linux::get_default_pa_source();
        return if let Some(input) = input {
            Some(input.1)
        } else {
            None
        };
    }
}

#[inline]
#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn get_default_sound_input() -> Option<String> {
    None
}

#[cfg(feature = "use_rubato")]
pub fn resample_channels(
    data: &[f32],
    sample_rate0: u32,
    sample_rate: u32,
    channels: u16,
) -> Vec<f32> {
    use rubato::{
        InterpolationParameters, InterpolationType, Resampler, SincFixedIn, WindowFunction,
    };
    let params = InterpolationParameters {
        sinc_len: 256,
        f_cutoff: 0.95,
        interpolation: InterpolationType::Nearest,
        oversampling_factor: 160,
        window: WindowFunction::BlackmanHarris2,
    };
    let mut resampler = SincFixedIn::<f64>::new(
        sample_rate as f64 / sample_rate0 as f64,
        params,
        data.len() / (channels as usize),
        channels as _,
    );
    let mut waves_in = Vec::new();
    if channels == 2 {
        waves_in.push(
            data.iter()
                .step_by(2)
                .map(|x| *x as f64)
                .collect::<Vec<_>>(),
        );
        waves_in.push(
            data.iter()
                .skip(1)
                .step_by(2)
                .map(|x| *x as f64)
                .collect::<Vec<_>>(),
        );
    } else {
        waves_in.push(data.iter().map(|x| *x as f64).collect::<Vec<_>>());
    }
    if let Ok(x) = resampler.process(&waves_in) {
        if x.is_empty() {
            Vec::new()
        } else if x.len() == 2 {
            x[0].chunks(1)
                .zip(x[1].chunks(1))
                .flat_map(|(a, b)| a.into_iter().chain(b))
                .map(|x| *x as f32)
                .collect()
        } else {
            x[0].iter().map(|x| *x as f32).collect()
        }
    } else {
        Vec::new()
    }
}

#[cfg(feature = "use_dasp")]
pub fn audio_resample(
    data: &[f32],
    sample_rate0: u32,
    sample_rate: u32,
    channels: u16,
) -> Vec<f32> {
    use dasp::{interpolate::linear::Linear, signal, Signal};
    let n = data.len() / (channels as usize);
    let n = n * sample_rate as usize / sample_rate0 as usize;
    if channels == 2 {
        let mut source = signal::from_interleaved_samples_iter::<_, [_; 2]>(data.iter().cloned());
        let a = source.next();
        let b = source.next();
        let interp = Linear::new(a, b);
        let mut data = Vec::with_capacity(n << 1);
        for x in source
            .from_hz_to_hz(interp, sample_rate0 as _, sample_rate as _)
            .take(n)
        {
            data.push(x[0]);
            data.push(x[1]);
        }
        data
    } else {
        let mut source = signal::from_iter(data.iter().cloned());
        let a = source.next();
        let b = source.next();
        let interp = Linear::new(a, b);
        source
            .from_hz_to_hz(interp, sample_rate0 as _, sample_rate as _)
            .take(n)
            .collect()
    }
}

#[cfg(feature = "use_samplerate")]
pub fn audio_resample(
    data: &[f32],
    sample_rate0: u32,
    sample_rate: u32,
    channels: u16,
) -> Vec<f32> {
    use samplerate::{convert, ConverterType};
    convert(
        sample_rate0 as _,
        sample_rate as _,
        channels as _,
        ConverterType::SincBestQuality,
        data,
    )
    .unwrap_or_default()
}

pub fn audio_rechannel(
    input: Vec<f32>,
    in_hz: u32,
    out_hz: u32,
    in_chan: u16,
    output_chan: u16,
) -> Vec<f32> {
    if in_chan == output_chan {
        return input;
    }
    let mut input = input;
    input.truncate(input.len() / in_chan as usize * in_chan as usize);
    match (in_chan, output_chan) {
        (1, 2) => audio_rechannel_1_2(&input, in_hz, out_hz),
        (1, 3) => audio_rechannel_1_3(&input, in_hz, out_hz),
        (1, 4) => audio_rechannel_1_4(&input, in_hz, out_hz),
        (1, 5) => audio_rechannel_1_5(&input, in_hz, out_hz),
        (1, 6) => audio_rechannel_1_6(&input, in_hz, out_hz),
        (1, 7) => audio_rechannel_1_7(&input, in_hz, out_hz),
        (1, 8) => audio_rechannel_1_8(&input, in_hz, out_hz),
        (2, 1) => audio_rechannel_2_1(&input, in_hz, out_hz),
        (2, 3) => audio_rechannel_2_3(&input, in_hz, out_hz),
        (2, 4) => audio_rechannel_2_4(&input, in_hz, out_hz),
        (2, 5) => audio_rechannel_2_5(&input, in_hz, out_hz),
        (2, 6) => audio_rechannel_2_6(&input, in_hz, out_hz),
        (2, 7) => audio_rechannel_2_7(&input, in_hz, out_hz),
        (2, 8) => audio_rechannel_2_8(&input, in_hz, out_hz),
        (3, 1) => audio_rechannel_3_1(&input, in_hz, out_hz),
        (3, 2) => audio_rechannel_3_2(&input, in_hz, out_hz),
        (3, 4) => audio_rechannel_3_4(&input, in_hz, out_hz),
        (3, 5) => audio_rechannel_3_5(&input, in_hz, out_hz),
        (3, 6) => audio_rechannel_3_6(&input, in_hz, out_hz),
        (3, 7) => audio_rechannel_3_7(&input, in_hz, out_hz),
        (3, 8) => audio_rechannel_3_8(&input, in_hz, out_hz),
        (4, 1) => audio_rechannel_4_1(&input, in_hz, out_hz),
        (4, 2) => audio_rechannel_4_2(&input, in_hz, out_hz),
        (4, 3) => audio_rechannel_4_3(&input, in_hz, out_hz),
        (4, 5) => audio_rechannel_4_5(&input, in_hz, out_hz),
        (4, 6) => audio_rechannel_4_6(&input, in_hz, out_hz),
        (4, 7) => audio_rechannel_4_7(&input, in_hz, out_hz),
        (4, 8) => audio_rechannel_4_8(&input, in_hz, out_hz),
        (5, 1) => audio_rechannel_5_1(&input, in_hz, out_hz),
        (5, 2) => audio_rechannel_5_2(&input, in_hz, out_hz),
        (5, 3) => audio_rechannel_5_3(&input, in_hz, out_hz),
        (5, 4) => audio_rechannel_5_4(&input, in_hz, out_hz),
        (5, 6) => audio_rechannel_5_6(&input, in_hz, out_hz),
        (5, 7) => audio_rechannel_5_7(&input, in_hz, out_hz),
        (5, 8) => audio_rechannel_5_8(&input, in_hz, out_hz),
        (6, 1) => audio_rechannel_6_1(&input, in_hz, out_hz),
        (6, 2) => audio_rechannel_6_2(&input, in_hz, out_hz),
        (6, 3) => audio_rechannel_6_3(&input, in_hz, out_hz),
        (6, 4) => audio_rechannel_6_4(&input, in_hz, out_hz),
        (6, 5) => audio_rechannel_6_5(&input, in_hz, out_hz),
        (6, 7) => audio_rechannel_6_7(&input, in_hz, out_hz),
        (6, 8) => audio_rechannel_6_8(&input, in_hz, out_hz),
        (7, 1) => audio_rechannel_7_1(&input, in_hz, out_hz),
        (7, 2) => audio_rechannel_7_2(&input, in_hz, out_hz),
        (7, 3) => audio_rechannel_7_3(&input, in_hz, out_hz),
        (7, 4) => audio_rechannel_7_4(&input, in_hz, out_hz),
        (7, 5) => audio_rechannel_7_5(&input, in_hz, out_hz),
        (7, 6) => audio_rechannel_7_6(&input, in_hz, out_hz),
        (7, 8) => audio_rechannel_7_8(&input, in_hz, out_hz),
        (8, 1) => audio_rechannel_8_1(&input, in_hz, out_hz),
        (8, 2) => audio_rechannel_8_2(&input, in_hz, out_hz),
        (8, 3) => audio_rechannel_8_3(&input, in_hz, out_hz),
        (8, 4) => audio_rechannel_8_4(&input, in_hz, out_hz),
        (8, 5) => audio_rechannel_8_5(&input, in_hz, out_hz),
        (8, 6) => audio_rechannel_8_6(&input, in_hz, out_hz),
        (8, 7) => audio_rechannel_8_7(&input, in_hz, out_hz),
        _ => input,
    }
}

macro_rules! audio_rechannel {
    ($name:ident, $in_channels:expr, $out_channels:expr) => {
        fn $name(input: &[f32], in_hz: u32, out_hz: u32) -> Vec<f32> {
            use fon::{chan::Ch32, Audio, Frame};
            let mut in_audio =
                Audio::<Ch32, $in_channels>::with_silence(in_hz, input.len() / $in_channels);
            for (x, y) in input.chunks_exact($in_channels).zip(in_audio.iter_mut()) {
                let mut f = Frame::<Ch32, $in_channels>::default();
                let mut i = 0;
                for c in f.channels_mut() {
                    *c = x[i].into();
                    i += 1;
                }
                *y = f;
            }
            Audio::<Ch32, $out_channels>::with_audio(out_hz, &in_audio)
                .as_f32_slice()
                .to_owned()
        }
    };
}

audio_rechannel!(audio_rechannel_1_2, 1, 2);
audio_rechannel!(audio_rechannel_1_3, 1, 3);
audio_rechannel!(audio_rechannel_1_4, 1, 4);
audio_rechannel!(audio_rechannel_1_5, 1, 5);
audio_rechannel!(audio_rechannel_1_6, 1, 6);
audio_rechannel!(audio_rechannel_1_7, 1, 7);
audio_rechannel!(audio_rechannel_1_8, 1, 8);
audio_rechannel!(audio_rechannel_2_1, 2, 1);
audio_rechannel!(audio_rechannel_2_3, 2, 3);
audio_rechannel!(audio_rechannel_2_4, 2, 4);
audio_rechannel!(audio_rechannel_2_5, 2, 5);
audio_rechannel!(audio_rechannel_2_6, 2, 6);
audio_rechannel!(audio_rechannel_2_7, 2, 7);
audio_rechannel!(audio_rechannel_2_8, 2, 8);
audio_rechannel!(audio_rechannel_3_1, 3, 1);
audio_rechannel!(audio_rechannel_3_2, 3, 2);
audio_rechannel!(audio_rechannel_3_4, 3, 4);
audio_rechannel!(audio_rechannel_3_5, 3, 5);
audio_rechannel!(audio_rechannel_3_6, 3, 6);
audio_rechannel!(audio_rechannel_3_7, 3, 7);
audio_rechannel!(audio_rechannel_3_8, 3, 8);
audio_rechannel!(audio_rechannel_4_1, 4, 1);
audio_rechannel!(audio_rechannel_4_2, 4, 2);
audio_rechannel!(audio_rechannel_4_3, 4, 3);
audio_rechannel!(audio_rechannel_4_5, 4, 5);
audio_rechannel!(audio_rechannel_4_6, 4, 6);
audio_rechannel!(audio_rechannel_4_7, 4, 7);
audio_rechannel!(audio_rechannel_4_8, 4, 8);
audio_rechannel!(audio_rechannel_5_1, 5, 1);
audio_rechannel!(audio_rechannel_5_2, 5, 2);
audio_rechannel!(audio_rechannel_5_3, 5, 3);
audio_rechannel!(audio_rechannel_5_4, 5, 4);
audio_rechannel!(audio_rechannel_5_6, 5, 6);
audio_rechannel!(audio_rechannel_5_7, 5, 7);
audio_rechannel!(audio_rechannel_5_8, 5, 8);
audio_rechannel!(audio_rechannel_6_1, 6, 1);
audio_rechannel!(audio_rechannel_6_2, 6, 2);
audio_rechannel!(audio_rechannel_6_3, 6, 3);
audio_rechannel!(audio_rechannel_6_4, 6, 4);
audio_rechannel!(audio_rechannel_6_5, 6, 5);
audio_rechannel!(audio_rechannel_6_7, 6, 7);
audio_rechannel!(audio_rechannel_6_8, 6, 8);
audio_rechannel!(audio_rechannel_7_1, 7, 1);
audio_rechannel!(audio_rechannel_7_2, 7, 2);
audio_rechannel!(audio_rechannel_7_3, 7, 3);
audio_rechannel!(audio_rechannel_7_4, 7, 4);
audio_rechannel!(audio_rechannel_7_5, 7, 5);
audio_rechannel!(audio_rechannel_7_6, 7, 6);
audio_rechannel!(audio_rechannel_7_8, 7, 8);
audio_rechannel!(audio_rechannel_8_1, 8, 1);
audio_rechannel!(audio_rechannel_8_2, 8, 2);
audio_rechannel!(audio_rechannel_8_3, 8, 3);
audio_rechannel!(audio_rechannel_8_4, 8, 4);
audio_rechannel!(audio_rechannel_8_5, 8, 5);
audio_rechannel!(audio_rechannel_8_6, 8, 6);
audio_rechannel!(audio_rechannel_8_7, 8, 7);

// R-SV4(d) / R-S11 / §18: CheckTestNatType (the RAII Drop-guard that fired test_nat_type at arm entry
// when is_direct flipped) and test_nat_type (the startup NAT/STUN probe — already a no-op after the
// egressing test_nat_type_ / test_ipv6_sync→test_ipv6→test_bind_ipv6 / STUNS_* probes were excised)
// are EXCISED — cfg-absent, not stubbed (the spec's bar: "a no-op stub is DIFFERENT from being
// cfg-absent"). The fork keys at the choke point + ships direct-only (R-D4) + v4-only (R-D5), so no
// NAT/IPv6 discovery exists in any role, the startup entries dial nobody, and the Drop-guard
// reachability R-S11 flags is gone with the guard.

// R-SV4 / R-X3 / §18: test_nat_type_ — the NAT-type probe that connected to the
// rendezvous server (and whose reply's `cu` field could re-home the client) — is
// excised. The fork keys at the choke point and ships direct-only (R-D4); there is
// no rendezvous probe and no probe-reply config adoption.

// R-SV4 / §18 (dial nobody): the `get_rendezvous_server[_]` resolver chain (which port-checked and
// ranked the rendezvous server list) is excised — it had ZERO callers (the direct-IP fork keys at the
// choke point and never dials a mediator, R-D4/R-SV4). The live LOCAL accessors
// `Config::get_rendezvous_server[s]` (the vestigial stored value) stay; only the async resolver +
// its IPC query hop are gone.

#[inline]
pub async fn get_nat_type(_ms_timeout: u64) -> i32 {
    Config::get_nat_type()
}

// R-SV4(d)/R-SV10: the rendezvous-server latency probe is EXCISED. It used to
// spawn a startup outbound `connect_tcp` to RENDEZVOUS_PORT on each configured
// rendezvous host to pick the fastest broker. The fork is direct-IP only —
// `RENDEZVOUS_SERVERS` is empty (R-SV4) so there is no broker to probe — and the
// spec names `test_rendezvous_server` as a sovereignty symbol that MUST be
// absent, not merely dead. The function and all of its callers are removed so the
// R-SV10 grep is sound (no startup phone-home a config-write could ever revive).

pub fn run_me<T: AsRef<std::ffi::OsStr>>(args: Vec<T>) -> std::io::Result<std::process::Child> {
    run_me_with_env(args, std::iter::empty::<(&str, &str)>())
}

pub fn run_me_with_env<T, I, K, V>(args: Vec<T>, envs: I) -> std::io::Result<std::process::Child>
where
    T: AsRef<std::ffi::OsStr>,
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    run_me_with_env_inner(args, envs, false)
}

#[cfg(target_os = "linux")]
pub(crate) fn run_me_with_env_and_parent_death<T, I, K, V>(
    args: Vec<T>,
    envs: I,
) -> std::io::Result<std::process::Child>
where
    T: AsRef<std::ffi::OsStr>,
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    run_me_with_env_inner(args, envs, true)
}

fn run_me_with_env_inner<T, I, K, V>(
    args: Vec<T>,
    envs: I,
    kill_on_parent_death: bool,
) -> std::io::Result<std::process::Child>
where
    T: AsRef<std::ffi::OsStr>,
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let envs = envs
        .into_iter()
        .map(|(k, v)| {
            (
                std::ffi::OsString::from(k.as_ref()),
                std::ffi::OsString::from(v.as_ref()),
            )
        })
        .collect::<Vec<_>>();
    let cmd = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(cmd);
    cmd.envs(envs.iter().map(|(k, v)| (k, v)));
    #[cfg(target_os = "linux")]
    if kill_on_parent_death {
        crate::platform::linux::configure_command_kill_on_parent_death(&mut cmd)?;
    }
    #[cfg(target_os = "linux")]
    hbb_common::platform::linux::configure_command_close_nonstdio_on_exec(&mut cmd).map_err(
        |err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to constrain RustDesk child descriptors: {err}"),
            )
        },
    )?;
    #[cfg(not(target_os = "linux"))]
    let _ = kill_on_parent_death;
    #[cfg(target_os = "macos")]
    hbb_common::platform::macos::configure_command_close_nonstdio_on_exec(&mut cmd).map_err(
        |err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to constrain RustDesk child descriptors: {err}"),
            )
        },
    )?;
    let result = cmd.args(&args).spawn();
    match result.as_ref() {
        Ok(_) => {}
        Err(err) => log::error!("run_me: {err:?}"),
    }
    result
}

#[inline]
pub fn username() -> String {
    // fix bug of whoami
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return whoami::username().trim_end_matches('\0').to_owned();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return DEVICE_NAME.lock().unwrap().clone();
}

// Exactly the implementation of "whoami::hostname()".
// This wrapper is to suppress warnings.
#[inline(always)]
#[cfg(not(target_os = "ios"))]
pub fn whoami_hostname() -> String {
    let mut hostname = whoami::fallible::hostname().unwrap_or_else(|_| "localhost".to_string());
    hostname.make_ascii_lowercase();
    hostname
}

#[inline]
pub fn hostname() -> String {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        #[allow(unused_mut)]
        let mut name = whoami_hostname();
        // some time, there is .local, some time not, so remove it for osx
        #[cfg(target_os = "macos")]
        if name.ends_with(".local") {
            name = name.trim_end_matches(".local").to_owned();
        }
        name
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return DEVICE_NAME.lock().unwrap().clone();
}

#[inline]
pub fn get_sysinfo() -> serde_json::Value {
    use hbb_common::sysinfo::System;
    let mut system = System::new();
    system.refresh_memory();
    system.refresh_cpu();
    let memory = system.total_memory();
    let memory = (memory as f64 / 1024. / 1024. / 1024. * 100.).round() / 100.;
    let cpus = system.cpus();
    let cpu_name = cpus.first().map(|x| x.brand()).unwrap_or_default();
    let cpu_name = cpu_name.trim_end();
    let cpu_freq = cpus.first().map(|x| x.frequency()).unwrap_or_default();
    let cpu_freq = (cpu_freq as f64 / 1024. * 100.).round() / 100.;
    let cpu = if cpu_freq > 0. {
        format!("{}, {}GHz, ", cpu_name, cpu_freq)
    } else {
        "".to_owned() // android
    };
    let num_cpus = num_cpus::get();
    let num_pcpus = num_cpus::get_physical();
    let mut os = system.distribution_id();
    os = format!("{} / {}", os, system.long_os_version().unwrap_or_default());
    #[cfg(windows)]
    {
        os = format!("{os} - {}", system.os_version().unwrap_or_default());
    }
    let hostname = hostname(); // sys.hostname() return localhost on android in my test
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let out;
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let mut out;
    out = json!({
        "cpu": format!("{cpu}{num_cpus}/{num_pcpus} cores"),
        "memory": format!("{memory}GB"),
        "os": os,
        "hostname": hostname,
    });
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let username = crate::platform::get_active_username();
        if !username.is_empty() && (!cfg!(windows) || username != "SYSTEM") {
            out["username"] = json!(username);
        }
    }
    out
}

#[inline]
pub fn check_port<T: std::string::ToString>(host: T, port: i32) -> String {
    hbb_common::socket_client::check_port(host, port)
}

#[inline]
pub fn increase_port<T: std::string::ToString>(host: T, offset: i32) -> String {
    hbb_common::socket_client::increase_port(host, offset)
}

pub const POSTFIX_SERVICE: &'static str = "_service";

#[inline]
pub fn is_control_key(evt: &KeyEvent, key: &ControlKey) -> bool {
    if let Some(key_event::Union::ControlKey(ck)) = evt.union {
        ck.value() == key.value()
    } else {
        false
    }
}

#[inline]
pub fn is_modifier(evt: &KeyEvent) -> bool {
    if let Some(key_event::Union::ControlKey(ck)) = evt.union {
        let v = ck.value();
        v == ControlKey::Alt.value()
            || v == ControlKey::Shift.value()
            || v == ControlKey::Control.value()
            || v == ControlKey::Meta.value()
            || v == ControlKey::RAlt.value()
            || v == ControlKey::RShift.value()
            || v == ControlKey::RControl.value()
            || v == ControlKey::RWin.value()
    } else {
        false
    }
}

#[inline]
pub fn get_app_name() -> String {
    hbb_common::config::APP_NAME.read().unwrap().clone()
}

#[inline]
pub fn is_rustdesk() -> bool {
    hbb_common::config::APP_NAME.read().unwrap().eq("RustDesk")
}

#[inline]
pub fn get_uri_prefix() -> String {
    format!("{}://", get_app_name().to_lowercase())
}

#[cfg(target_os = "macos")]
pub fn get_full_name() -> String {
    format!(
        "{}.{}",
        hbb_common::config::ORG.read().unwrap(),
        hbb_common::config::APP_NAME.read().unwrap(),
    )
}

pub fn get_custom_rendezvous_server(custom: String) -> String {
    // R-X4: exe-name license rendezvous-server override removed (direct-IP only).
    if !custom.is_empty() {
        return custom;
    }
    if !config::PROD_RENDEZVOUS_SERVER.read().unwrap().is_empty() {
        return config::PROD_RENDEZVOUS_SERVER.read().unwrap().clone();
    }
    "".to_owned()
}

#[inline]
pub fn get_api_server(api: String, custom: String) -> String {
    if Config::no_register_device() {
        return "".to_owned();
    }
    let mut res = get_api_server_(api, custom);
    if res.ends_with('/') {
        res.pop();
    }
    if res.starts_with("https")
        && res.ends_with(":21114")
        && get_builtin_option(keys::OPTION_ALLOW_HTTPS_21114) != "Y"
    {
        return res.replace(":21114", "");
    }
    res
}

fn get_api_server_(api: String, custom: String) -> String {
    // R-X4: exe-name license api-server override removed (direct-IP only).
    if !api.is_empty() {
        return api.to_owned();
    }
    let s0 = get_custom_rendezvous_server(custom);
    if !s0.is_empty() {
        let s = crate::increase_port(&s0, -2);
        if s == s0 {
            return format!("http://{}:{}", s, config::RENDEZVOUS_PORT - 2);
        } else {
            return format!("http://{}", s);
        }
    }
    // R-SV6(d) / R-D6 / §18: NO global-host default. Upstream returned the hardcoded
    // "https://admin.rustdesk.com" here, and the only thing that kept the audit POSTs
    // (post_conn_audit etc.) silent was get_audit_server's `is_public(&url)` string-
    // match on "rustdesk.com" — a fragile silencing the spec forbids ("the silencing
    // MUST NOT rest on is_public()'s hostname string-match"). With api-server and
    // custom-rendezvous-server pinned empty (R-S16) the fork reaches this fallback, so
    // returning "" makes get_audit_server short-circuit on url.is_empty() — no global
    // host can ever resolve, independent of is_public(). (BUILTIN_SETTINGS is asserted
    // empty by R-A4, so no_register_device() is false and this path IS reached.)
    String::new()
}

#[inline]
pub fn is_public(url: &str) -> bool {
    let url = url.to_ascii_lowercase();
    url.contains("rustdesk.com/") || url.ends_with("rustdesk.com")
}

pub fn get_local_option(key: &str) -> String {
    LocalConfig::get_option(key)
}

pub fn get_audit_server(api: String, custom: String, typ: String) -> String {
    let url = get_api_server(api, custom);
    if url.is_empty() || is_public(&url) {
        return "".to_owned();
    }
    format!("{}/api/audit/{}", url, typ)
}

#[inline]
pub fn make_privacy_mode_msg_with_details(
    state: back_notification::PrivacyModeState,
    details: String,
    impl_key: String,
) -> Message {
    let mut misc = Misc::new();
    let mut back_notification = BackNotification {
        details,
        impl_key,
        ..Default::default()
    };
    back_notification.set_privacy_mode_state(state);
    misc.set_back_notification(back_notification);
    let mut msg_out = Message::new();
    msg_out.set_misc(misc);
    msg_out
}

#[inline]
pub fn make_privacy_mode_msg(
    state: back_notification::PrivacyModeState,
    impl_key: String,
) -> Message {
    make_privacy_mode_msg_with_details(state, "".to_owned(), impl_key)
}

pub fn is_keyboard_mode_supported(
    keyboard_mode: &KeyboardMode,
    version_number: i64,
    peer_platform: &str,
) -> bool {
    match keyboard_mode {
        KeyboardMode::Legacy => true,
        KeyboardMode::Map => {
            if peer_platform.to_lowercase() == crate::PLATFORM_ANDROID.to_lowercase() {
                false
            } else {
                version_number >= hbb_common::get_version_number("1.2.0")
            }
        }
        KeyboardMode::Translate => version_number >= hbb_common::get_version_number("1.2.0"),
        KeyboardMode::Auto => version_number >= hbb_common::get_version_number("1.2.0"),
    }
}

pub fn get_supported_keyboard_modes(version: i64, peer_platform: &str) -> Vec<KeyboardMode> {
    KeyboardMode::iter()
        .filter(|&mode| is_keyboard_mode_supported(mode, version, peer_platform))
        .map(|&mode| mode)
        .collect::<Vec<_>>()
}

pub fn make_fd_to_json(id: i32, path: String, entries: &Vec<FileEntry>) -> String {
    let fd_json = _make_fd_to_json(id, path, entries);
    serde_json::to_string(&fd_json).unwrap_or("".into())
}

pub fn _make_fd_to_json(id: i32, path: String, entries: &Vec<FileEntry>) -> Map<String, Value> {
    let mut fd_json = serde_json::Map::new();
    fd_json.insert("id".into(), json!(id));
    fd_json.insert("path".into(), json!(path));

    let mut entries_out = vec![];
    for entry in entries {
        let mut entry_map = serde_json::Map::new();
        entry_map.insert("entry_type".into(), json!(entry.entry_type.value()));
        entry_map.insert("name".into(), json!(entry.name));
        entry_map.insert("size".into(), json!(entry.size));
        entry_map.insert("modified_time".into(), json!(entry.modified_time));
        entries_out.push(entry_map);
    }
    fd_json.insert("entries".into(), json!(entries_out));
    fd_json
}

pub fn make_vec_fd_to_json(fds: &[FileDirectory]) -> String {
    let mut fd_jsons = vec![];

    for fd in fds.iter() {
        let fd_json = _make_fd_to_json(fd.id, fd.path.clone(), &fd.entries);
        fd_jsons.push(fd_json);
    }

    serde_json::to_string(&fd_jsons).unwrap_or("".into())
}

pub fn make_empty_dirs_response_to_json(res: &ReadEmptyDirsResponse) -> String {
    let mut map: Map<String, Value> = serde_json::Map::new();
    map.insert("path".into(), json!(res.path));

    let mut fd_jsons = vec![];

    for fd in res.empty_dirs.iter() {
        let fd_json = _make_fd_to_json(fd.id, fd.path.clone(), &fd.entries);
        fd_jsons.push(fd_json);
    }
    map.insert("empty_dirs".into(), fd_jsons.into());

    serde_json::to_string(&map).unwrap_or("".into())
}

/// The function to handle the url scheme sent by the system.
///
/// 1. Try to send the url scheme from ipc.
/// 2. If failed to send the url scheme, we open a new main window to handle this url scheme.
pub fn handle_url_scheme(url: String) {
    #[cfg(not(target_os = "ios"))]
    if let Err(err) = crate::ipc::send_url_scheme(url.clone()) {
        log::debug!("Send the url to the existing flutter process failed, {}. Let's open a new program to handle this.", err);
        let _ = crate::run_me(vec![url]);
    }
}

#[inline]
pub fn encode64<T: AsRef<[u8]>>(input: T) -> String {
    #[allow(deprecated)]
    base64::encode(input)
}

#[inline]
pub fn decode64<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, base64::DecodeError> {
    #[allow(deprecated)]
    base64::decode(input)
}

pub async fn get_key(_sync: bool) -> String {
    // R-X4: the rendezvous trust anchor is the fork's baked constant,
    // unconditionally. Every runtime override is IGNORED — the config option (all
    // platforms, including iOS), the async IPC options blob, and the Windows
    // license/exe-name (renamed-exe / RUSTDESK_APPNAME) spoof — so a malicious
    // installer name or a shared "config string" can never re-point the client at
    // attacker infrastructure under the attacker's key. RS_PUB_KEY remains only as
    // this baked default; the override path is gone (the macOS/iOS source obeys the
    // same rule, R-X4).
    config::RS_PUB_KEY.to_owned()
}

#[allow(unused_mut)]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn check_process(arg: &str, mut same_uid: bool) -> bool {
    #[cfg(target_os = "macos")]
    if !crate::platform::is_root() && !same_uid {
        log::warn!("Can not get other process's command line arguments on macos without root");
        same_uid = true;
    }
    use hbb_common::sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes();
    let mut path = std::env::current_exe().unwrap_or_default();
    if let Ok(linked) = path.read_link() {
        path = linked;
    }
    let path = path.to_string_lossy().to_lowercase();
    let my_uid = sys
        .process((std::process::id() as usize).into())
        .map(|x| x.user_id())
        .unwrap_or_default();
    for (_, p) in sys.processes().iter() {
        let mut cur_path = p.exe().to_path_buf();
        if let Ok(linked) = cur_path.read_link() {
            cur_path = linked;
        }
        if cur_path.to_string_lossy().to_lowercase() != path {
            continue;
        }
        if p.pid().to_string() == std::process::id().to_string() {
            continue;
        }
        if same_uid && p.user_id() != my_uid {
            continue;
        }
        // on mac, p.cmd() get "/Applications/RustDesk.app/Contents/MacOS/RustDesk", "XPC_SERVICE_NAME=com.carriez.RustDesk_server"
        let parg = if p.cmd().len() <= 1 { "" } else { &p.cmd()[1] };
        if arg.is_empty() {
            if !parg.starts_with("--") {
                return true;
            }
        } else if arg == parg {
            return true;
        }
    }
    false
}

#[inline]
fn get_pk(pk: &[u8]) -> Option<[u8; 32]> {
    if pk.len() == 32 {
        let mut tmp = [0u8; 32];
        tmp[..].copy_from_slice(&pk);
        Some(tmp)
    } else {
        None
    }
}

#[inline]
pub fn get_rs_pk(str_base64: &str) -> Option<sign::PublicKey> {
    if let Ok(pk) = crate::decode64(str_base64) {
        get_pk(&pk).map(|x| sign::PublicKey(x))
    } else {
        None
    }
}

pub struct ThrottledInterval {
    interval: Interval,
    next_tick: Instant,
    min_interval: Duration,
}

impl ThrottledInterval {
    pub fn new(i: Interval) -> ThrottledInterval {
        let period = i.period();
        ThrottledInterval {
            interval: i,
            next_tick: Instant::now(),
            min_interval: Duration::from_secs_f64(period.as_secs_f64() * 0.9),
        }
    }

    pub async fn tick(&mut self) -> Instant {
        let instant = poll_fn(|cx| self.poll_tick(cx));
        instant.await
    }

    pub fn poll_tick(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Instant> {
        match self.interval.poll_tick(cx) {
            Poll::Ready(instant) => {
                let now = Instant::now();
                if self.next_tick <= now {
                    self.next_tick = now + self.min_interval;
                    Poll::Ready(instant)
                } else {
                    // This call is required since tokio 1.27
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub type RustDeskInterval = ThrottledInterval;

#[inline]
pub fn rustdesk_interval(i: Interval) -> ThrottledInterval {
    ThrottledInterval::new(i)
}

pub fn load_custom_client() {
    let Some(path) = std::env::current_exe()
        .ok()
        .and_then(|executable| custom_client_config_path(&executable))
    else {
        return;
    };
    if path.is_file() {
        let Ok(data) = std::fs::read_to_string(&path) else {
            log::error!("Failed to read custom client config");
            return;
        };
        read_custom_client(&data.trim());
    }
}

fn custom_client_config_path(executable: &std::path::Path) -> Option<std::path::PathBuf> {
    if !executable.is_absolute() {
        return None;
    }
    let path = executable.parent()?.to_path_buf();
    #[cfg(target_os = "macos")]
    let path = path.join("../Resources");
    Some(path.join("custom.txt"))
}

fn read_custom_client_advanced_settings(
    settings: serde_json::Value,
    map_display_settings: &HashMap<String, &&str>,
    map_local_settings: &HashMap<String, &&str>,
    map_settings: &HashMap<String, &&str>,
    map_buildin_settings: &HashMap<String, &&str>,
    is_override: bool,
) {
    let mut display_settings = if is_override {
        config::OVERWRITE_DISPLAY_SETTINGS.write().unwrap()
    } else {
        config::DEFAULT_DISPLAY_SETTINGS.write().unwrap()
    };
    let mut local_settings = if is_override {
        config::OVERWRITE_LOCAL_SETTINGS.write().unwrap()
    } else {
        config::DEFAULT_LOCAL_SETTINGS.write().unwrap()
    };
    let mut server_settings = if is_override {
        config::OVERWRITE_SETTINGS.write().unwrap()
    } else {
        config::DEFAULT_SETTINGS.write().unwrap()
    };
    let mut buildin_settings = config::BUILTIN_SETTINGS.write().unwrap();

    if let Some(settings) = settings.as_object() {
        for (k, v) in settings {
            let Some(v) = v.as_str() else {
                continue;
            };
            if let Some(k2) = map_display_settings.get(k) {
                display_settings.insert(k2.to_string(), v.to_owned());
            } else if let Some(k2) = map_local_settings.get(k) {
                local_settings.insert(k2.to_string(), v.to_owned());
            } else if let Some(k2) = map_settings.get(k) {
                server_settings.insert(k2.to_string(), v.to_owned());
            } else if let Some(k2) = map_buildin_settings.get(k) {
                buildin_settings.insert(k2.to_string(), v.to_owned());
            } else {
                let k2 = k.replace("_", "-");
                let k = k2.replace("-", "_");
                // display
                display_settings.insert(k.clone(), v.to_owned());
                display_settings.insert(k2.clone(), v.to_owned());
                // local
                local_settings.insert(k.clone(), v.to_owned());
                local_settings.insert(k2.clone(), v.to_owned());
                // server
                server_settings.insert(k.clone(), v.to_owned());
                server_settings.insert(k2.clone(), v.to_owned());
                // buildin
                buildin_settings.insert(k.clone(), v.to_owned());
                buildin_settings.insert(k2.clone(), v.to_owned());
            }
        }
    }
}

#[inline]
#[cfg(target_os = "macos")]
pub fn get_dst_align_rgba() -> usize {
    // https://developer.apple.com/forums/thread/712709
    // Memory alignment should be multiple of 64.
    if crate::ui_interface::use_texture_render() {
        64
    } else {
        1
    }
}

#[inline]
#[cfg(not(target_os = "macos"))]
pub fn get_dst_align_rgba() -> usize {
    1
}

const MAX_CUSTOM_CLIENT_APP_NAME_LEN: usize = 64;

fn custom_client_app_name_is_valid(app_name: &str) -> bool {
    let bytes = app_name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_CUSTOM_CLIENT_APP_NAME_LEN {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

pub fn read_custom_client(config: &str) {
    let Ok(data) = decode64(config) else {
        log::error!("Failed to decode custom client config");
        return;
    };
    const KEY: &str = "5Qbwsde3unUcJBtrx9ZkvUmwFNoExHzpryHuPUdqlWM=";
    let Some(pk) = get_rs_pk(KEY) else {
        log::error!("Failed to parse public key of custom client");
        return;
    };
    let Ok(data) = sign::verify(&data, &pk) else {
        log::error!("Failed to dec custom client config");
        return;
    };
    let Ok(mut data) =
        serde_json::from_slice::<std::collections::HashMap<String, serde_json::Value>>(&data)
    else {
        log::error!("Failed to parse custom client config");
        return;
    };

    if let Some(app_name) = data.remove("app-name") {
        let Some(app_name) = app_name.as_str() else {
            log::error!("Invalid custom client app-name");
            return;
        };
        if !custom_client_app_name_is_valid(app_name) {
            log::error!("Invalid custom client app-name");
            return;
        }
        *config::APP_NAME.write().unwrap() = app_name.to_owned();
    }

    let mut map_display_settings = HashMap::new();
    for s in keys::KEYS_DISPLAY_SETTINGS {
        map_display_settings.insert(s.replace("_", "-"), s);
    }
    let mut map_local_settings = HashMap::new();
    for s in keys::KEYS_LOCAL_SETTINGS {
        map_local_settings.insert(s.replace("_", "-"), s);
    }
    let mut map_settings = HashMap::new();
    for s in keys::KEYS_SETTINGS {
        map_settings.insert(s.replace("_", "-"), s);
    }
    let mut buildin_settings = HashMap::new();
    for s in keys::KEYS_BUILDIN_SETTINGS {
        buildin_settings.insert(s.replace("_", "-"), s);
    }
    if let Some(default_settings) = data.remove("default-settings") {
        read_custom_client_advanced_settings(
            default_settings,
            &map_display_settings,
            &map_local_settings,
            &map_settings,
            &buildin_settings,
            false,
        );
    }
    if let Some(overwrite_settings) = data.remove("override-settings") {
        read_custom_client_advanced_settings(
            overwrite_settings,
            &map_display_settings,
            &map_local_settings,
            &map_settings,
            &buildin_settings,
            true,
        );
    }
    for (k, v) in data {
        if let Some(v) = v.as_str() {
            config::HARD_SETTINGS
                .write()
                .unwrap()
                .insert(k, v.to_owned());
        };
    }
}

#[inline]
pub fn is_empty_uni_link(arg: &str) -> bool {
    let prefix = crate::get_uri_prefix();
    if !arg.starts_with(&prefix) {
        return false;
    }
    arg[prefix.len()..].chars().all(|c| c == '/')
}

#[inline]
pub fn get_builtin_option(key: &str) -> String {
    config::BUILTIN_SETTINGS
        .read()
        .unwrap()
        .get(key)
        .cloned()
        .unwrap_or_default()
}

#[inline]
pub fn is_custom_client() -> bool {
    get_app_name() != "RustDesk"
}

pub fn verify_login(_raw: &str, _id: &str) -> bool {
    true
    /*
    if is_custom_client() {
        return true;
    }
    #[cfg(debug_assertions)]
    return true;
    let Ok(pk) = crate::decode64("IycjQd4TmWvjjLnYd796Rd+XkK+KG+7GU1Ia7u4+vSw=") else {
        return false;
    };
    let Some(key) = get_pk(&pk).map(|x| sign::PublicKey(x)) else {
        return false;
    };
    let Ok(v) = crate::decode64(raw) else {
        return false;
    };
    let raw = sign::verify(&v, &key).unwrap_or_default();
    let v_str = std::str::from_utf8(&raw)
        .unwrap_or_default()
        .split(":")
        .next()
        .unwrap_or_default();
    v_str == id
    */
}

// R-SV4 / R-D6: test_ipv6_sync (the synchronous wrapper that spawned test_ipv6 at
// process startup) is REMOVED — it was the only reach to the STUN-resolving
// test_bind_ipv6 from the startup path (test_nat_type), and that DNS resolution +
// UDP6 bind is a startup phone-home the sovereign fork forbids. The async test_ipv6
// remains for now (the connect-time client.rs caller), excised in the R-SV4(d)
// token-absent follow-on.

// The color is the same to `str2color()` in flutter.
pub fn str2color(s: &str, alpha: u8) -> u32 {
    let bytes = s.as_bytes();
    // dart code `160 << 16 + 114 << 8 + 91` results `0`.
    let mut hash: u32 = 0;
    for &byte in bytes {
        let code = byte as u32;
        hash = code.wrapping_add((hash << 5).wrapping_sub(hash));
    }

    hash = hash % 16777216;
    let rgb = hash & 0xFF7FFF;

    (alpha as u32) << 24 | rgb
}

/// Check control permission state from a u64 bitmap.
/// Each permission uses 2 bits: 0 = not set, 1 = disable, 2 = enable, 3 = invalid (treated as not set)
/// Returns: Some(true) = enabled, Some(false) = disabled, None = not set or invalid
pub fn get_control_permission(
    permissions: u64,
    permission: hbb_common::rendezvous_proto::control_permissions::Permission,
) -> Option<bool> {
    use hbb_common::protobuf::Enum;
    let index = permission.value();
    if index >= 0 && index < 32 {
        let shift = index * 2;
        let value = (permissions >> shift) & 0b11;
        match value {
            1 => Some(false), // disable
            2 => Some(true),  // enable
            _ => None,        // 0 = not set, 3 = invalid
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio::{
        self,
        time::{interval, interval_at, sleep, Duration, Instant, Interval},
    };
    use std::collections::HashSet;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_run_me_child_excludes_inherited_nonstdio_descriptors() {
        use std::{
            fs::{self, OpenOptions},
            os::unix::fs::MetadataExt,
            process::Command,
        };

        const ROLE_ENV: &str = "RUSTDESK_RUN_ME_DESCRIPTOR_TEST_ROLE";
        const TARGET_ENV: &str = "RUSTDESK_RUN_ME_DESCRIPTOR_TEST_TARGET";
        const TEST_NAME: &str =
            "common::tests::linux_run_me_child_excludes_inherited_nonstdio_descriptors";

        let descriptor_for_target = || {
            let target_path = std::env::var_os(TARGET_ENV)
                .map(std::path::PathBuf::from)
                .expect("target path must be supplied by the parent test");
            let target = fs::metadata(&target_path).expect("target metadata must be readable");
            for entry in fs::read_dir("/proc/self/fd").expect("child proc fd directory must exist")
            {
                let entry = entry.expect("child proc fd entry must be readable");
                let Ok(metadata) = fs::metadata(entry.path()) else {
                    continue;
                };
                if metadata.dev() == target.dev() && metadata.ino() == target.ino() {
                    return Some(entry.file_name());
                }
            }
            None
        };

        match std::env::var(ROLE_ENV).as_deref() {
            Ok("child") => {
                let inherited = descriptor_for_target();
                assert!(
                    inherited.is_none(),
                    "run_me child retained the launcher's non-stdio descriptor as {inherited:?}"
                );
                return;
            }
            Ok("launcher") => {
                assert_eq!(
                    descriptor_for_target().as_deref(),
                    Some(std::ffi::OsStr::new("9")),
                    "shell launcher must inject the hostile descriptor before run_me is tested"
                );
                let envs = [
                    (
                        std::ffi::OsString::from(ROLE_ENV),
                        std::ffi::OsString::from("child"),
                    ),
                    (
                        std::ffi::OsString::from(TARGET_ENV),
                        std::env::var_os(TARGET_ENV).expect("launcher target path must be present"),
                    ),
                ];
                let mut child = run_me_with_env(vec!["--exact", TEST_NAME, "--nocapture"], envs)
                    .expect("same-executable child must spawn");
                let status = child
                    .wait()
                    .expect("same-executable child must be waitable");
                assert!(status.success(), "descriptor-check child failed: {status}");
                return;
            }
            Ok(role) => panic!("unexpected descriptor-test role: {role}"),
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("descriptor-test role must be Unicode")
            }
            Err(std::env::VarError::NotPresent) => {}
        }

        let test_root = std::env::temp_dir().join(format!(
            "rustdesk-run-me-descriptor-{}-{}",
            std::process::id(),
            std::time::SystemTime::UNIX_EPOCH
                .elapsed()
                .expect("test clock must follow the Unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&test_root).expect("descriptor test directory must be creatable");
        let target_path = test_root.join("parent-authority");
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&target_path)
            .expect("descriptor test target must be creatable");

        let current_exe = std::env::current_exe().expect("test executable path must be available");
        let status = Command::new("/bin/sh")
            .args([
                std::ffi::OsStr::new("-c"),
                std::ffi::OsStr::new("exec 9<>\"$1\"; exec \"$2\" --exact \"$3\" --nocapture"),
                std::ffi::OsStr::new("rustdesk-run-me-descriptor-test"),
                target_path.as_os_str(),
                current_exe.as_os_str(),
                std::ffi::OsStr::new(TEST_NAME),
            ])
            .env(ROLE_ENV, "launcher")
            .env(TARGET_ENV, &target_path)
            .status()
            .expect("descriptor-injecting shell must execute");

        fs::remove_file(&target_path).expect("descriptor test target must be removable");
        fs::remove_dir(&test_root).expect("descriptor test directory must be removable");
        assert!(
            status.success(),
            "descriptor-test launcher failed: {status}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn r_s11e44_linux_parent_bound_child_dies_with_launcher() {
        use std::{
            fs,
            io::{ErrorKind, Read as _, Write as _},
            os::{
                fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
                unix::{fs::DirBuilderExt as _, net::UnixListener, net::UnixStream},
            },
            process::{Child, Command},
        };

        const TEST_NAME: &str =
            "common::tests::r_s11e44_linux_parent_bound_child_dies_with_launcher";
        const ROLE_ENV: &str = "RUSTDESK_TEST_PARENT_BOUND_CHILD_ROLE";
        const SOCKET_ENV: &str = "RUSTDESK_TEST_PARENT_BOUND_CHILD_SOCKET";

        match std::env::var(ROLE_ENV).as_deref() {
            Ok("launcher") => {
                let socket = std::env::var_os(SOCKET_ENV)
                    .expect("parent-bound child socket must be supplied");
                let envs = [
                    (
                        std::ffi::OsString::from(ROLE_ENV),
                        std::ffi::OsString::from("worker"),
                    ),
                    (std::ffi::OsString::from(SOCKET_ENV), socket),
                ];
                let _worker = run_me_with_env_and_parent_death(
                    vec!["--exact", TEST_NAME, "--nocapture"],
                    envs,
                )
                .expect("parent-bound child must spawn");
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
            Ok("worker") => {
                let mut stream = UnixStream::connect(
                    std::env::var_os(SOCKET_ENV)
                        .expect("parent-bound child socket must be supplied"),
                )
                .expect("parent-bound child must reach the controller");
                stream
                    .write_all(&std::process::id().to_ne_bytes())
                    .expect("parent-bound child pid must be reported");
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
            Ok(role) => panic!("unexpected parent-bound child test role: {role}"),
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("parent-bound child test role must be Unicode")
            }
            Err(std::env::VarError::NotPresent) => {}
        }

        struct LauncherGuard(Child);
        impl Drop for LauncherGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let test_root = std::env::temp_dir().join(format!(
            "rustdesk-parent-bound-child-{}-{}",
            std::process::id(),
            std::time::SystemTime::UNIX_EPOCH
                .elapsed()
                .expect("test clock must follow the Unix epoch")
                .as_nanos()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&test_root)
            .expect("parent-bound child test directory must be creatable");
        let socket_path = test_root.join("ready.sock");
        let listener = UnixListener::bind(&socket_path)
            .expect("parent-bound child listener must be creatable");
        listener
            .set_nonblocking(true)
            .expect("parent-bound child listener must be nonblocking");
        let mut launcher = LauncherGuard(
            Command::new(std::env::current_exe().expect("test executable must be available"))
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(ROLE_ENV, "launcher")
                .env(SOCKET_ENV, &socket_path)
                .spawn()
                .expect("parent-bound child launcher must spawn"),
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut worker_stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    if let Some(status) = launcher
                        .0
                        .try_wait()
                        .expect("launcher status must be observable")
                    {
                        panic!("parent-bound child launcher exited early: {status}");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("parent-bound child did not report readiness: {err}"),
            }
        };
        let mut worker_pid = [0u8; std::mem::size_of::<u32>()];
        worker_stream
            .read_exact(&mut worker_pid)
            .expect("parent-bound child pid must be readable");
        let worker_pid = hbb_common::libc::pid_t::try_from(u32::from_ne_bytes(worker_pid))
            .expect("parent-bound child pid must fit pid_t");
        let pidfd =
            unsafe { hbb_common::libc::syscall(hbb_common::libc::SYS_pidfd_open, worker_pid, 0) };
        assert!(
            pidfd >= 0,
            "pidfd_open is required for the parent-bound child test"
        );
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };

        launcher
            .0
            .kill()
            .expect("parent-bound child launcher must be killable");
        launcher
            .0
            .wait()
            .expect("parent-bound child launcher must be reapable");
        let mut pollfd = hbb_common::libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: hbb_common::libc::POLLIN,
            revents: 0,
        };
        let observed = unsafe { hbb_common::libc::poll(&mut pollfd, 1, 5_000) };
        if observed != 1 || pollfd.revents & hbb_common::libc::POLLIN == 0 {
            unsafe {
                hbb_common::libc::syscall(
                    hbb_common::libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    hbb_common::libc::SIGKILL,
                    std::ptr::null::<hbb_common::libc::siginfo_t>(),
                    0,
                );
            }
        }
        assert_eq!(observed, 1, "parent-bound child survived launcher death");
        assert_ne!(pollfd.revents & hbb_common::libc::POLLIN, 0);

        drop(worker_stream);
        drop(listener);
        fs::remove_file(&socket_path).expect("parent-bound child socket must be removable");
        fs::remove_dir(&test_root).expect("parent-bound child test directory must be removable");
    }

    // R-SV6(d) / R-D6 / §18: the api-server resolution MUST default to a sovereign empty string —
    // no hardwired global host. Upstream returned "https://admin.rustdesk.com" as the fallback and
    // also derived an api endpoint from the built-in rs-ny.rustdesk.com rendezvous default; the fork
    // excises both (the admin.rustdesk.com default is gone, and PROD_RENDEZVOUS_SERVER is init-empty
    // and never written — verified: zero write sites). With empty api-server / custom-rendezvous-server
    // inputs (those options are themselves pinned empty at the config layer — config_it/lockdown.rs),
    // the resolver must yield "" so a future account/address-book API path has no host to dial. This
    // test guards the *resolution* layer (distinct from the config-pin layer) against re-introducing
    // either hardwired host.
    #[test]
    fn api_server_resolution_defaults_to_sovereign_empty() {
        assert_eq!(
            get_custom_rendezvous_server(String::new()),
            "",
            "no built-in rendezvous host may resolve (PROD_RENDEZVOUS_SERVER must stay empty)"
        );
        assert_eq!(
            get_api_server(String::new(), String::new()),
            "",
            "no hardwired global api host may resolve (the upstream global-host default is excised)"
        );
    }

    // R-A4 / R-X4 / §18: the rendezvous trust anchor is the baked RS_PUB_KEY, unconditionally.
    // Upstream's get_key read an override from Config::get_option("key"), the async IPC options blob,
    // or the Windows license/renamed-exe. The fork has no stored override: the option is pinned empty
    // at the config funnel, and both get_key paths return the constant.
    #[tokio::test]
    async fn get_key_uses_pinned_anchor_and_rejects_option_override() {
        use hbb_common::config::{Config, RS_PUB_KEY};
        Config::set_option(
            "key".to_owned(),
            "ATTACKER-REPOINTED-TRUST-ANCHOR=".to_owned(),
        );
        assert_eq!(
            Config::get_option("key"),
            "",
            "R-S16/R-S11b-3: the trust-anchor option must be pinned empty"
        );
        assert_eq!(
            Config::get_options().get("key").map(String::as_str),
            Some(""),
            "R-S16/R-S11b-3: whole-map option reads must expose the pinned empty trust-anchor value"
        );
        // both invocations (the upstream sync=true Config path and sync=false IPC path) yield the anchor
        assert_eq!(
            get_key(true).await,
            RS_PUB_KEY,
            "R-A4: the trust anchor must be the pinned RS_PUB_KEY, never an option override"
        );
        assert_eq!(
            get_key(false).await,
            RS_PUB_KEY,
            "R-A4: the anchor is constant across the sync flag"
        );
    }

    #[test]
    fn custom_client_app_name_identifier_contract() {
        for app_name in ["RustDesk", "RustDesk-Admin", "A", "A1", "A-1"] {
            assert!(custom_client_app_name_is_valid(app_name), "{app_name}");
        }

        let max_len = format!("A{}1", "a".repeat(62));
        assert!(custom_client_app_name_is_valid(&max_len));

        let too_long = format!("A{}1", "a".repeat(63));
        assert!(!custom_client_app_name_is_valid(&too_long));

        for app_name in [
            "",
            "-RustDesk",
            "RustDesk-",
            "1RustDesk",
            "RustDesk Admin",
            "RustDesk_Admin",
            "RustDesk.Admin",
            "RustDesk+Admin",
            "RustDesk&Admin",
            "RustDesk\"Admin",
            "RustDesk%Admin",
            "RustDesk/Admin",
            "RustDesk\\Admin",
            "RustDesk\nAdmin",
            "RustDeské",
        ] {
            assert!(!custom_client_app_name_is_valid(app_name), "{app_name:?}");
        }
    }

    #[test]
    fn custom_client_config_is_executable_relative() {
        let executable = std::path::Path::new("/opt/rustdesk/bin/rustdesk");
        #[cfg(not(target_os = "macos"))]
        let expected = std::path::Path::new("/opt/rustdesk/bin/custom.txt");
        #[cfg(target_os = "macos")]
        let expected = std::path::Path::new("/opt/rustdesk/bin/../Resources/custom.txt");

        assert_eq!(
            custom_client_config_path(executable).as_deref(),
            Some(expected)
        );
        assert_eq!(
            custom_client_config_path(std::path::Path::new("rustdesk")),
            None
        );
    }

    #[inline]
    fn get_timestamp_secs() -> u128 {
        (std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_millis()
            + 500)
            / 1000
    }

    fn interval_maker() -> Interval {
        interval(Duration::from_secs(1))
    }

    fn interval_at_maker() -> Interval {
        interval_at(
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        )
    }

    // ThrottledInterval tick at the same time as tokio interval, if no sleeps
    #[allow(non_snake_case)]
    #[tokio::test]
    async fn test_RustDesk_interval() {
        let base_intervals = [interval_maker, interval_at_maker];
        for maker in base_intervals.into_iter() {
            let mut tokio_timer = maker();
            let mut tokio_times = Vec::new();
            let mut timer = rustdesk_interval(maker());
            let mut times = Vec::new();
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        if tokio_times.len() >= 10 && times.len() >= 10 {
                            break;
                        }
                        times.push(get_timestamp_secs());
                    }
                    _ = tokio_timer.tick() => {
                        if tokio_times.len() >= 10 && times.len() >= 10 {
                            break;
                        }
                        tokio_times.push(get_timestamp_secs());
                    }
                }
            }
            assert_eq!(times, tokio_times);
        }
    }

    #[tokio::test]
    async fn test_tokio_time_interval_sleep() {
        let mut timer = interval_maker();
        let mut times = Vec::new();
        sleep(Duration::from_secs(3)).await;
        loop {
            tokio::select! {
                _ = timer.tick() => {
                    times.push(get_timestamp_secs());
                    if times.len() == 5 {
                        break;
                    }
                }
            }
        }
        let times2: HashSet<u128> = HashSet::from_iter(times.clone());
        assert_eq!(times.len(), times2.len() + 3);
    }

    // ThrottledInterval tick less times than tokio interval, if there're sleeps
    #[allow(non_snake_case)]
    #[tokio::test]
    async fn test_RustDesk_interval_sleep() {
        let base_intervals = [interval_maker, interval_at_maker];
        for (i, maker) in base_intervals.into_iter().enumerate() {
            let mut timer = rustdesk_interval(maker());
            let mut times = Vec::new();
            sleep(Duration::from_secs(3)).await;
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        times.push(get_timestamp_secs());
                        if times.len() == 5 {
                            break;
                        }
                    }
                }
            }
            // No multiple ticks in the `interval` time.
            // Values in "times" are unique and are less than normal tokio interval.
            // See previous test (test_tokio_time_interval_sleep) for comparison.
            let times2: HashSet<u128> = HashSet::from_iter(times.clone());
            assert_eq!(times.len(), times2.len(), "test: {}", i);
        }
    }

    #[test]
    fn test_duration_multiplication() {
        let dur = Duration::from_secs(1);

        assert_eq!(dur * 2, Duration::from_secs(2));
        assert_eq!(
            Duration::from_secs_f64(dur.as_secs_f64() * 0.9),
            Duration::from_millis(900)
        );
        assert_eq!(
            Duration::from_secs_f64(dur.as_secs_f64() * 0.923),
            Duration::from_millis(923)
        );
        assert_eq!(
            Duration::from_secs_f64(dur.as_secs_f64() * 0.923 * 1e-3),
            Duration::from_micros(923)
        );
        assert_eq!(
            Duration::from_secs_f64(dur.as_secs_f64() * 0.923 * 1e-6),
            Duration::from_nanos(923)
        );
        assert_eq!(
            Duration::from_secs_f64(dur.as_secs_f64() * 0.923 * 1e-9),
            Duration::from_nanos(1)
        );
        assert_eq!(
            Duration::from_secs_f64(dur.as_secs_f64() * 0.5 * 1e-9),
            Duration::from_nanos(1)
        );
        assert_eq!(
            Duration::from_secs_f64(dur.as_secs_f64() * 0.499 * 1e-9),
            Duration::from_nanos(0)
        );
    }

    #[test]
    fn test_is_public() {
        // Test URLs containing "rustdesk.com/"
        assert!(is_public("https://rustdesk.com/"));
        assert!(is_public("https://www.rustdesk.com/"));
        assert!(is_public("https://api.rustdesk.com/v1"));
        assert!(is_public("https://API.RUSTDESK.COM/v1"));
        assert!(is_public("https://rustdesk.com/path"));

        // Test URLs ending with "rustdesk.com"
        assert!(is_public("rustdesk.com"));
        assert!(is_public("https://rustdesk.com"));
        assert!(is_public("https://RustDesk.com"));
        assert!(is_public("http://www.rustdesk.com"));
        assert!(is_public("https://api.rustdesk.com"));

        // Test non-public URLs
        assert!(!is_public("https://example.com"));
        assert!(!is_public("https://custom-server.com"));
        assert!(!is_public("http://192.168.1.1"));
        assert!(!is_public("localhost"));
        assert!(!is_public("https://rustdesk.computer.com"));
        assert!(!is_public("rustdesk.comhello.com"));
    }

    #[test]
    fn test_mouse_event_constants_and_mask_layout() {
        use super::input::*;

        // Verify MOUSE_TYPE constants are unique and within the mask range.
        let types = [
            MOUSE_TYPE_MOVE,
            MOUSE_TYPE_DOWN,
            MOUSE_TYPE_UP,
            MOUSE_TYPE_WHEEL,
            MOUSE_TYPE_TRACKPAD,
            MOUSE_TYPE_MOVE_RELATIVE,
        ];

        let mut seen = std::collections::HashSet::new();
        for t in types.iter() {
            assert!(seen.insert(*t), "Duplicate mouse type: {}", t);
            assert_eq!(
                *t & MOUSE_TYPE_MASK,
                *t,
                "Mouse type {} exceeds mask {}",
                t,
                MOUSE_TYPE_MASK
            );
        }

        // The mask layout is: lower 3 bits for type, upper bits for buttons (shifted by 3).
        let combined_mask = MOUSE_TYPE_DOWN | ((MOUSE_BUTTON_LEFT | MOUSE_BUTTON_RIGHT) << 3);
        assert_eq!(combined_mask & MOUSE_TYPE_MASK, MOUSE_TYPE_DOWN);
        assert_eq!(combined_mask >> 3, MOUSE_BUTTON_LEFT | MOUSE_BUTTON_RIGHT);
    }
}
