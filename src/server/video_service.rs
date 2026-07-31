// 24FPS (actually 23.976FPS) is what video professionals ages ago determined to be the
// slowest playback rate that still looks smooth enough to feel real.
// Our eyes can see a slight difference and even though 30FPS actually shows
// more information and is more realistic.
// 60FPS is commonly used in game, teamviewer 12 support this for video editing user.

// how to capture with mouse cursor:
// https://docs.microsoft.com/zh-cn/windows/win32/direct3ddxgi/desktop-dup-api?redirectedfrom=MSDN

// RECORD: The following Project has implemented audio capture, hardware codec and mouse cursor drawn.
// https://github.com/PHZ76/DesktopSharing

// dxgi memory leak issue
// https://stackoverflow.com/questions/47801238/memory-leak-in-creating-direct2d-device
// but per my test, it is more related to AcquireNextFrame,
// https://forums.developer.nvidia.com/t/dxgi-outputduplication-memory-leak-when-using-nv-but-not-amd-drivers/108582

// to-do:
// https://slhck.info/video/2017/03/01/rate-control.html

use super::{display_service::check_display_changed, service::ServiceTmpl, video_qos::VideoQoS, *};
#[cfg(target_os = "linux")]
use crate::common::SimpleCallOnReturn;
#[cfg(target_os = "linux")]
use crate::platform::linux::is_x11;
use crate::privacy_mode::{get_privacy_mode_conn_id, INVALID_PRIVACY_MODE_CONN_ID};
#[cfg(windows)]
use crate::{
    platform::windows::is_process_consent_running,
    privacy_mode::{is_current_privacy_mode_impl, PRIVACY_MODE_IMPL_WIN_MAG},
    ui_interface::is_installed,
};
use hbb_common::{anyhow::anyhow, config};
#[cfg(feature = "hwcodec")]
use scrap::hwcodec::{HwRamEncoder, HwRamEncoderConfig};
#[cfg(feature = "vram")]
use scrap::vram::{VRamEncoder, VRamEncoderConfig};
// R-X9 (slices 2-4): `Capturer` is now used on ALL platforms in `create_capturer` — the
// Windows portable-service capture route was excised, so the direct `Capturer::new` path
// (formerly the `#[cfg(not(windows))]` arm) is unconditional. The import was previously
// `#[cfg(not(windows))]`-gated because Windows went through portable_service::client; it is
// valid on Windows (the deleted portable_service.rs used `scrap::Capturer` there too).
use scrap::Capturer;
use scrap::{
    codec::{Encoder, EncoderCfg},
    record::{Recorder, RecorderContext},
    vpxcodec::{VpxEncoderConfig, VpxVideoCodecId},
    CodecFormat, Display, EncodeInput, TraitCapturer, TraitPixelBuffer,
};
#[cfg(windows)]
use std::sync::Once;
use std::{
    collections::{HashMap, HashSet},
    io::ErrorKind::WouldBlock,
    ops::{Deref, DerefMut},
    sync::{Arc, Condvar, Mutex, Weak},
    time::{self, Duration, Instant},
};

pub const OPTION_REFRESH: &'static str = "refresh";

const MAX_VIDEO_FRAME_ACK_CONTROLLERS: usize = 64;
const MAX_SCREENSHOT_REQUEST_OWNERS: usize = 64;
const SCREENSHOT_ENCODE_QUEUE_CAPACITY: usize = 2;

lazy_static::lazy_static! {
    static ref VIDEO_FRAME_ACK_CONTROLLERS: Mutex<HashMap<VideoFrameStreamKey, Weak<VideoFrameAckState>>> = Default::default();
    pub static ref VIDEO_QOS: Arc<Mutex<VideoQoS>> = Default::default();
    pub static ref IS_UAC_RUNNING: Arc<Mutex<bool>> = Default::default();
    pub static ref IS_FOREGROUND_WINDOW_ELEVATED: Arc<Mutex<bool>> = Default::default();
    static ref SCREENSHOTS: Mutex<PendingScreenshots> = Default::default();
    static ref SCREENSHOT_ENCODER: Result<ScreenshotEncoder, String> = ScreenshotEncoder::new();
}

struct PendingScreenshotRequest {
    source: VideoSource,
    display_idx: usize,
    sid: String,
    restore_vram: bool,
}

struct PendingScreenshotOwner {
    tx: Sender,
    pending: Option<PendingScreenshotRequest>,
    in_flight: bool,
}

#[derive(Default)]
struct PendingScreenshots {
    owners: HashMap<i32, PendingScreenshotOwner>,
}

struct ScreenshotWork {
    connection_id: i32,
    tx: Sender,
    request: PendingScreenshotRequest,
}

struct ScreenshotEncodeJob {
    screenshots: Vec<ScreenshotWork>,
    msg: String,
    width: usize,
    height: usize,
    rgba: Vec<u8>,
}

struct BoundedScreenshotPng {
    data: Vec<u8>,
    max_bytes: usize,
}

struct ScreenshotEncoder {
    sender: std::sync::mpsc::SyncSender<ScreenshotEncodeJob>,
    _worker: std::thread::JoinHandle<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScreenshotAdmissionError {
    Capacity,
}

impl BoundedScreenshotPng {
    fn new() -> Self {
        Self::with_limit(crate::peer_text::MAX_PEER_SCREENSHOT_RESPONSE_BYTES)
    }

    fn with_limit(max_bytes: usize) -> Self {
        Self {
            data: Vec::new(),
            max_bytes,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl std::io::Write for BoundedScreenshotPng {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next_len =
            self.data.len().checked_add(buf.len()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "PNG too large")
            })?;
        if next_len > self.max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PNG exceeds screenshot response limit",
            ));
        }
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl PendingScreenshots {
    fn replace(
        &mut self,
        connection_id: i32,
        source: VideoSource,
        display_idx: usize,
        sid: String,
        tx: Sender,
    ) -> Result<(), ScreenshotAdmissionError> {
        let request = PendingScreenshotRequest {
            source,
            display_idx,
            sid,
            restore_vram: false,
        };
        if let Some(owner) = self.owners.get_mut(&connection_id) {
            if owner.tx.same_channel(&tx) {
                owner.pending = Some(request);
                return Ok(());
            }
        }
        if !self.owners.contains_key(&connection_id)
            && self.owners.len() >= MAX_SCREENSHOT_REQUEST_OWNERS
        {
            return Err(ScreenshotAdmissionError::Capacity);
        }
        self.owners.insert(
            connection_id,
            PendingScreenshotOwner {
                tx,
                pending: Some(request),
                in_flight: false,
            },
        );
        Ok(())
    }

    fn take_for_frame(&mut self, source: VideoSource, display_idx: usize) -> Vec<ScreenshotWork> {
        let mut screenshots = Vec::new();
        for (&connection_id, owner) in self.owners.iter_mut() {
            let matches_frame = !owner.in_flight
                && owner
                    .pending
                    .as_ref()
                    .map(|request| request.source == source && request.display_idx == display_idx)
                    .unwrap_or(false);
            if matches_frame {
                if let Some(request) = owner.pending.take() {
                    owner.in_flight = true;
                    screenshots.push(ScreenshotWork {
                        connection_id,
                        tx: owner.tx.clone(),
                        request,
                    });
                }
            }
        }
        screenshots
    }

    fn complete(&mut self, connection_id: i32, tx: &Sender) {
        let remove = if let Some(owner) = self.owners.get_mut(&connection_id) {
            if owner.tx.same_channel(tx) && owner.in_flight {
                owner.in_flight = false;
                owner.pending.is_none()
            } else {
                false
            }
        } else {
            false
        };
        if remove {
            self.owners.remove(&connection_id);
        }
    }

    fn retry_after_texture(&mut self, mut screenshot: ScreenshotWork) {
        let Some(owner) = self.owners.get_mut(&screenshot.connection_id) else {
            return;
        };
        if !owner.tx.same_channel(&screenshot.tx) || !owner.in_flight {
            return;
        }
        owner.in_flight = false;
        if owner.pending.is_none() {
            screenshot.request.restore_vram = true;
            owner.pending = Some(screenshot.request);
        }
    }

    fn cancel(&mut self, connection_id: i32, tx: &Sender) {
        let remove = self
            .owners
            .get(&connection_id)
            .map(|owner| owner.tx.same_channel(tx))
            .unwrap_or(false);
        if remove {
            self.owners.remove(&connection_id);
        }
    }

    fn is_in_flight(&self, screenshot: &ScreenshotWork) -> bool {
        self.owners
            .get(&screenshot.connection_id)
            .map(|owner| owner.in_flight && owner.tx.same_channel(&screenshot.tx))
            .unwrap_or(false)
    }
}

impl ScreenshotEncoder {
    fn new() -> Result<Self, String> {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<ScreenshotEncodeJob>(SCREENSHOT_ENCODE_QUEUE_CAPACITY);
        let worker = std::thread::Builder::new()
            .name("screenshot-encoder".to_owned())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    handle_screenshot_job(job);
                }
            })
            .map_err(|err| format!("failed to start screenshot encoder: {err}"))?;
        Ok(Self {
            sender,
            _worker: worker,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct VideoFrameStreamKey {
    source: VideoSource,
    display_idx: usize,
}

#[derive(Default)]
struct VideoFrameAckRound {
    pending: HashSet<i32>,
    acknowledged: HashSet<i32>,
}

impl VideoFrameAckRound {
    fn complete(&self) -> bool {
        self.pending
            .iter()
            .all(|connection_id| self.acknowledged.contains(connection_id))
    }
}

#[derive(Default)]
struct VideoFrameAckState {
    round: Mutex<VideoFrameAckRound>,
    changed: Condvar,
}

impl VideoFrameAckState {
    fn reset(&self) {
        let mut round = self.round.lock().unwrap();
        round.pending.clear();
        round.acknowledged.clear();
        self.changed.notify_all();
    }

    fn prepare(&self, connection_ids: &HashSet<i32>) {
        let mut round = self.round.lock().unwrap();
        round.pending.clone_from(connection_ids);
        round.acknowledged.clear();
        self.changed.notify_all();
    }

    fn acknowledge(&self, connection_id: i32) -> bool {
        let mut round = self.round.lock().unwrap();
        if !round.pending.contains(&connection_id) || !round.acknowledged.insert(connection_id) {
            return false;
        }
        self.changed.notify_all();
        true
    }

    fn wait_for_all(&self, timeout: Duration) -> bool {
        let round = self.round.lock().unwrap();
        if round.complete() {
            return true;
        }
        let (round, _) = self
            .changed
            .wait_timeout_while(round, timeout, |round| !round.complete())
            .unwrap();
        round.complete()
    }
}

struct VideoFrameController {
    key: VideoFrameStreamKey,
    state: Arc<VideoFrameAckState>,
}

impl VideoFrameController {
    fn new(source: VideoSource, display_idx: usize) -> ResultType<Self> {
        let key = VideoFrameStreamKey {
            source,
            display_idx,
        };
        let state = Arc::new(VideoFrameAckState::default());
        let mut controllers = VIDEO_FRAME_ACK_CONTROLLERS.lock().unwrap();
        controllers.retain(|_, state| state.strong_count() != 0);
        if controllers.get(&key).and_then(Weak::upgrade).is_some() {
            bail!(
                "video acknowledgement controller is already active for {:?} display {}",
                source,
                display_idx
            );
        }
        if controllers.len() >= MAX_VIDEO_FRAME_ACK_CONTROLLERS {
            bail!(
                "video acknowledgement controller limit {} reached",
                MAX_VIDEO_FRAME_ACK_CONTROLLERS
            );
        }
        controllers.insert(key, Arc::downgrade(&state));
        drop(controllers);
        Ok(Self { key, state })
    }

    fn reset(&self) {
        self.state.reset();
    }

    fn prepare(&self, connection_ids: &HashSet<i32>) {
        self.state.prepare(connection_ids);
    }

    fn wait_for_all(&self, timeout: Duration) -> bool {
        self.state.wait_for_all(timeout)
    }
}

impl Drop for VideoFrameController {
    fn drop(&mut self) {
        let mut controllers = VIDEO_FRAME_ACK_CONTROLLERS.lock().unwrap();
        let remove = controllers
            .get(&self.key)
            .and_then(Weak::upgrade)
            .map(|state| Arc::ptr_eq(&state, &self.state))
            .unwrap_or(false);
        if remove {
            controllers.remove(&self.key);
        }
        drop(controllers);
        self.state.reset();
    }
}

fn video_frame_ack_state(key: VideoFrameStreamKey) -> Option<Arc<VideoFrameAckState>> {
    let mut controllers = VIDEO_FRAME_ACK_CONTROLLERS.lock().unwrap();
    let state = controllers.get(&key).and_then(Weak::upgrade);
    if state.is_none() {
        controllers.remove(&key);
    }
    state
}

#[inline]
pub fn notify_video_frame_fetched(
    source: VideoSource,
    display_idx: usize,
    conn_id: i32,
    frame_tm: Option<Instant>,
) {
    let key = VideoFrameStreamKey {
        source,
        display_idx,
    };
    if video_frame_ack_state(key)
        .map(|state| state.acknowledge(conn_id))
        .unwrap_or(false)
    {
        if let Some(tm) = frame_tm {
            log::trace!("Channel recv latency: {}", tm.elapsed().as_secs_f32());
        }
    }
}

#[inline]
pub fn notify_video_frame_fetched_by_conn_id(
    source: VideoSource,
    conn_id: i32,
    frame_tm: Option<Instant>,
) {
    let states = {
        let mut controllers = VIDEO_FRAME_ACK_CONTROLLERS.lock().unwrap();
        controllers.retain(|_, state| state.strong_count() != 0);
        controllers
            .iter()
            .filter_map(|(key, state)| (key.source == source).then(|| state.upgrade()).flatten())
            .collect::<Vec<_>>()
    };
    let mut acknowledged = false;
    for state in states {
        acknowledged |= state.acknowledge(conn_id);
    }
    if acknowledged {
        if let Some(tm) = frame_tm {
            log::trace!("Channel recv latency: {}", tm.elapsed().as_secs_f32());
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VideoSource {
    Monitor,
    Camera,
}

impl VideoSource {
    pub fn service_name_prefix(&self) -> &'static str {
        match self {
            VideoSource::Monitor => "monitor",
            VideoSource::Camera => "camera",
        }
    }

    pub fn is_monitor(&self) -> bool {
        matches!(self, VideoSource::Monitor)
    }

    pub fn is_camera(&self) -> bool {
        matches!(self, VideoSource::Camera)
    }
}

#[derive(Clone)]
pub struct VideoService {
    sp: GenericService,
    idx: usize,
    source: VideoSource,
    #[cfg(target_os = "android")]
    android_generation: u64,
}

impl Deref for VideoService {
    type Target = ServiceTmpl<ConnInner>;

    fn deref(&self) -> &Self::Target {
        &self.sp
    }
}

impl DerefMut for VideoService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sp
    }
}

pub fn get_service_name(source: VideoSource, idx: usize) -> String {
    format!("{}{}", source.service_name_prefix(), idx)
}

pub fn new(
    source: VideoSource,
    idx: usize,
    #[cfg(target_os = "android")] android_generation: u64,
) -> GenericService {
    let vs = VideoService {
        sp: GenericService::new(get_service_name(source, idx), true),
        idx,
        source,
        #[cfg(target_os = "android")]
        android_generation,
    };
    GenericService::run(&vs, run);
    vs.sp
}

// Capturer object is expensive, avoiding to create it frequently.
fn create_capturer(
    privacy_mode_id: i32,
    display: Display,
    _current: usize,
) -> ResultType<Box<dyn TraitCapturer>> {
    #[cfg(not(windows))]
    let c: Option<Box<dyn TraitCapturer>> = None;
    #[cfg(windows)]
    let mut c: Option<Box<dyn TraitCapturer>> = None;
    if privacy_mode_id > 0 {
        #[cfg(windows)]
        {
            if let Some(c1) = crate::privacy_mode::win_mag::create_capturer(
                privacy_mode_id,
                display.origin(),
                display.width(),
                display.height(),
            )? {
                c = Some(Box::new(c1));
            }
        }
    }

    match c {
        Some(c1) => return Ok(c1),
        None => {
            // R-X9: the helper capturer route is excised; always create the direct
            // dxgi|gdi/scrap capturer.
            log::debug!("Create capturer from scrap");
            return Ok(Box::new(
                Capturer::new(display).with_context(|| "Failed to create capturer")?,
            ));
        }
    };
}

// This function works on privacy mode. Windows only for now.
pub fn test_create_capturer(
    privacy_mode_id: i32,
    display_idx: usize,
    timeout_millis: u64,
) -> String {
    let test_begin = Instant::now();
    loop {
        let err = match Display::all() {
            Ok(mut displays) => {
                if displays.len() <= display_idx {
                    anyhow!(
                        "Failed to get display {}, the displays' count is {}",
                        display_idx,
                        displays.len()
                    )
                } else {
                    let display = displays.remove(display_idx);
                    match create_capturer(privacy_mode_id, display, display_idx) {
                        Ok(_) => return "".to_owned(),
                        Err(e) => e,
                    }
                }
            }
            Err(e) => e.into(),
        };
        if test_begin.elapsed().as_millis() >= timeout_millis as _ {
            return err.to_string();
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

// Note: This function is extremely expensive, do not call it frequently.
#[cfg(windows)]
fn check_uac_switch(privacy_mode_id: i32, capturer_privacy_mode_id: i32) -> ResultType<()> {
    if capturer_privacy_mode_id != INVALID_PRIVACY_MODE_CONN_ID
        && is_current_privacy_mode_impl(PRIVACY_MODE_IMPL_WIN_MAG)
    {
        if !is_installed() {
            if privacy_mode_id != capturer_privacy_mode_id {
                if !is_process_consent_running()? {
                    bail!("consent.exe is not running");
                }
            }
            if is_process_consent_running()? {
                bail!("consent.exe is running");
            }
        }
    }
    Ok(())
}

pub(super) struct CapturerInfo {
    pub origin: (i32, i32),
    pub width: usize,
    pub height: usize,
    #[cfg(target_os = "android")]
    pub android_scale: u16,
    pub ndisplay: usize,
    pub current: usize,
    pub privacy_mode_id: i32,
    pub _capturer_privacy_mode_id: i32,
    pub capturer: Box<dyn TraitCapturer>,
}

impl Deref for CapturerInfo {
    type Target = Box<dyn TraitCapturer>;

    fn deref(&self) -> &Self::Target {
        &self.capturer
    }
}

impl DerefMut for CapturerInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.capturer
    }
}

fn get_capturer_monitor(
    current: usize,
    #[cfg(target_os = "android")] android_generation: u64,
) -> ResultType<CapturerInfo> {
    #[cfg(target_os = "linux")]
    {
        if !is_x11() {
            return super::wayland::get_capturer_for_display(current);
        }
    }

    #[cfg(target_os = "android")]
    let mut displays = Display::all_for_generation(android_generation)?;
    #[cfg(not(target_os = "android"))]
    let mut displays = Display::all()?;
    let ndisplay = displays.len();
    if ndisplay <= current {
        bail!(
            "Failed to get display {}, displays len: {}",
            current,
            ndisplay
        );
    }

    let display = displays.remove(current);

    #[cfg(target_os = "linux")]
    if let Display::X11(inner) = &display {
        if let Err(err) = inner.get_shm_status() {
            log::warn!(
                "MIT-SHM extension not working properly on select X11 server: {:?}",
                err
            );
        }
    }

    let (origin, width, height) = (display.origin(), display.width(), display.height());
    #[cfg(target_os = "android")]
    let android_scale = display.scale();
    let name = display.name();
    log::debug!(
        "#displays={}, current={}, origin: {:?}, width={}, height={}, cpus={}/{}, name:{}",
        ndisplay,
        current,
        &origin,
        width,
        height,
        num_cpus::get_physical(),
        num_cpus::get(),
        &name,
    );

    let privacy_mode_id = get_privacy_mode_conn_id().unwrap_or(INVALID_PRIVACY_MODE_CONN_ID);
    #[cfg(not(windows))]
    let capturer_privacy_mode_id = privacy_mode_id;
    #[cfg(windows)]
    let mut capturer_privacy_mode_id = privacy_mode_id;
    #[cfg(windows)]
    {
        if capturer_privacy_mode_id != INVALID_PRIVACY_MODE_CONN_ID
            && is_current_privacy_mode_impl(PRIVACY_MODE_IMPL_WIN_MAG)
        {
            if !is_installed() {
                if is_process_consent_running()? {
                    capturer_privacy_mode_id = INVALID_PRIVACY_MODE_CONN_ID;
                }
            }
        }
    }
    log::debug!(
        "Try create capturer with capturer privacy mode id {}",
        capturer_privacy_mode_id,
    );

    if privacy_mode_id != INVALID_PRIVACY_MODE_CONN_ID {
        if privacy_mode_id != capturer_privacy_mode_id {
            log::info!("In privacy mode, but show UAC prompt window for now");
        } else {
            log::info!("In privacy mode, the peer side cannot watch the screen");
        }
    }
    let capturer = create_capturer(capturer_privacy_mode_id, display, current)?;
    Ok(CapturerInfo {
        origin,
        width,
        height,
        #[cfg(target_os = "android")]
        android_scale,
        ndisplay,
        current,
        privacy_mode_id,
        _capturer_privacy_mode_id: capturer_privacy_mode_id,
        capturer,
    })
}

fn get_capturer_camera(current: usize) -> ResultType<CapturerInfo> {
    let cameras = camera::Cameras::get_sync_cameras();
    let ncamera = cameras.len();
    if ncamera <= current {
        bail!("Failed to get camera {}, cameras len: {}", current, ncamera,);
    }
    let Some(camera) = cameras.get(current) else {
        bail!(
            "Camera of index {} doesn't exist or platform not supported",
            current
        );
    };
    let capturer = camera::Cameras::get_capturer(current)?;
    let (width, height) = (camera.width as usize, camera.height as usize);
    let origin = (camera.x as i32, camera.y as i32);
    let name = &camera.name;
    let privacy_mode_id = get_privacy_mode_conn_id().unwrap_or(INVALID_PRIVACY_MODE_CONN_ID);
    let _capturer_privacy_mode_id = privacy_mode_id;
    log::debug!(
        "#cameras={}, current={}, origin: {:?}, width={}, height={}, cpus={}/{}, name:{}",
        ncamera,
        current,
        &origin,
        width,
        height,
        num_cpus::get_physical(),
        num_cpus::get(),
        name,
    );
    return Ok(CapturerInfo {
        origin,
        width,
        height,
        #[cfg(target_os = "android")]
        android_scale: 1,
        ndisplay: ncamera,
        current,
        privacy_mode_id,
        _capturer_privacy_mode_id: privacy_mode_id,
        capturer,
    });
}
fn get_capturer(
    source: VideoSource,
    current: usize,
    #[cfg(target_os = "android")] android_generation: u64,
) -> ResultType<CapturerInfo> {
    match source {
        VideoSource::Monitor => get_capturer_monitor(
            current,
            #[cfg(target_os = "android")]
            android_generation,
        ),
        VideoSource::Camera => get_capturer_camera(current),
    }
}

fn run(vs: VideoService) -> ResultType<()> {
    let mut _raii = Raii::new(vs.sp.name());
    // Wayland only support one video capturer for now. It is ok to call ensure_inited() here.
    //
    // ensure_inited() is needed because clear() may be called.
    // to-do: wayland ensure_inited should pass current display index.
    // But for now, we do not support multi-screen capture on wayland.
    #[cfg(target_os = "linux")]
    super::wayland::ensure_inited()?;
    #[cfg(target_os = "linux")]
    let _wayland_call_on_ret = {
        // Increment active display count when starting
        let _display_count = super::wayland::increment_active_display_count();

        SimpleCallOnReturn {
            b: true,
            f: Box::new(|| {
                // Decrement active display count and only clear if this was the last display
                let remaining_count = super::wayland::decrement_active_display_count();
                if remaining_count == 0 {
                    super::wayland::clear();
                }
            }),
        }
    };

    let display_idx = vs.idx;
    let source = vs.source; // R-S19: screenshot requests are keyed by (source, display_idx)
    let sp = vs.sp;
    let mut c = get_capturer(
        source,
        display_idx,
        #[cfg(target_os = "android")]
        vs.android_generation,
    )?;
    #[cfg(windows)]
    if !scrap::codec::enable_directx_capture() && !c.is_gdi() {
        log::info!("disable dxgi with option, fall back to gdi");
        c.set_gdi();
    }
    let mut video_qos = VIDEO_QOS.lock().unwrap();
    let mut spf = video_qos.spf();
    let mut quality = video_qos.ratio();
    let record_incoming = config::option2bool(
        "allow-auto-record-incoming",
        &Config::get_option("allow-auto-record-incoming"),
    );
    let client_record = video_qos.record();
    drop(video_qos);
    let (mut encoder, encoder_cfg, codec_format, use_i444, recorder) = match setup_encoder(
        &c,
        sp.name(),
        quality,
        client_record,
        record_incoming,
        vs.source,
        display_idx,
    ) {
        Ok(result) => result,
        Err(err) => {
            log::error!("Failed to create encoder: {err:?}, fallback to VP9");
            Encoder::set_fallback(&EncoderCfg::VPX(VpxEncoderConfig {
                width: c.width as _,
                height: c.height as _,
                #[cfg(target_os = "android")]
                android_scale: c.android_scale,
                quality,
                codec: VpxVideoCodecId::VP9,
                keyframe_interval: None,
            }));
            setup_encoder(
                &c,
                sp.name(),
                quality,
                client_record,
                record_incoming,
                vs.source,
                display_idx,
            )?
        }
    };
    #[cfg(feature = "vram")]
    c.set_output_texture(encoder.input_texture());
    #[cfg(target_os = "android")]
    if vs.source.is_monitor() {
        if let Err(e) = check_change_scale(vs.android_generation, encoder.is_hardware()) {
            try_broadcast_display_changed(&sp, display_idx, &c, true, vs.android_generation).ok();
            bail!(e);
        }
    }
    VIDEO_QOS.lock().unwrap().store_bitrate(encoder.bitrate());
    VIDEO_QOS
        .lock()
        .unwrap()
        .set_support_changing_quality(&sp.name(), encoder.support_changing_quality());
    log::info!("initial quality: {quality:?}");

    if sp.is_option_true(OPTION_REFRESH) {
        sp.set_option_bool(OPTION_REFRESH, false);
    }

    let frame_controller = VideoFrameController::new(source, display_idx)?;

    let start = time::Instant::now();
    let mut last_check_displays = time::Instant::now();
    #[cfg(windows)]
    let mut try_gdi = 1;
    #[cfg(windows)]
    log::info!("gdi: {}", c.is_gdi());
    #[cfg(windows)]
    start_uac_elevation_check();

    #[cfg(target_os = "linux")]
    let mut would_block_count = 0u32;
    let mut yuv = Vec::new();
    let mut mid_data = Vec::new();
    let mut repeat_encode_counter = 0;
    let repeat_encode_max = 10;
    let mut encode_fail_counter = 0;
    let mut first_frame = true;
    let capture_width = c.width;
    let capture_height = c.height;
    let (mut second_instant, mut send_counter) = (Instant::now(), 0);

    while sp.ok() {
        #[cfg(windows)]
        check_uac_switch(c.privacy_mode_id, c._capturer_privacy_mode_id)?;
        check_qos(
            &mut encoder,
            &mut quality,
            &mut spf,
            client_record,
            &mut send_counter,
            &mut second_instant,
            &sp.name(),
        )?;
        if sp.is_option_true(OPTION_REFRESH) {
            if vs.source.is_monitor() {
                let _ = try_broadcast_display_changed(
                    &sp,
                    display_idx,
                    &c,
                    true,
                    #[cfg(target_os = "android")]
                    vs.android_generation,
                );
            }
            log::info!("switch to refresh");
            bail!("SWITCH");
        }
        if codec_format != Encoder::negotiated_codec() {
            log::info!(
                "switch due to codec changed, {:?} -> {:?}",
                codec_format,
                Encoder::negotiated_codec()
            );
            bail!("SWITCH");
        }
        // R-X9: the "portable service running changed" SWITCH trigger is excised — the
        // portable SYSTEM service is gone, so its running-state is a constant `false` and
        // can never change. (Was: bail!("SWITCH") on last != client::running().)
        if Encoder::use_i444(&encoder_cfg) != use_i444 {
            log::info!("switch due to i444 changed");
            bail!("SWITCH");
        }
        #[cfg(all(windows, feature = "vram"))]
        if c.is_gdi() && encoder.input_texture() {
            log::info!("changed to gdi when using vram");
            VRamEncoder::set_fallback_gdi(sp.name(), true);
            bail!("SWITCH");
        }
        if vs.source.is_monitor() {
            check_privacy_mode_changed(
                &sp,
                display_idx,
                &c,
                #[cfg(target_os = "android")]
                vs.android_generation,
            )?;
        }
        #[cfg(windows)]
        {
            // R-X9: the `&& !portable_service::client::running()` guard is excised — the
            // portable service is gone (running() was always going to be false here), so a
            // desktop change always bails. Behaviorally identical (it was `&& !false`).
            if crate::platform::windows::desktop_changed() {
                bail!("Desktop changed");
            }
        }
        let now = time::Instant::now();
        if vs.source.is_monitor() && last_check_displays.elapsed().as_millis() > 1000 {
            last_check_displays = now;
            // This check may be redundant, but it is better to be safe.
            // The previous check in `sp.is_option_true(OPTION_REFRESH)` block may be enough.
            try_broadcast_display_changed(
                &sp,
                display_idx,
                &c,
                false,
                #[cfg(target_os = "android")]
                vs.android_generation,
            )?;
        }

        frame_controller.reset();

        let time = now - start;
        let ms = (time.as_secs() * 1000 + time.subsec_millis() as u64) as i64;
        let res = match c.frame(spf) {
            Ok(frame) => {
                repeat_encode_counter = 0;
                if frame.valid() {
                    let screenshots = SCREENSHOTS
                        .lock()
                        .unwrap()
                        .take_for_frame(source, display_idx);
                    if !screenshots.is_empty() {
                        let restore_vram = screenshots
                            .iter()
                            .any(|screenshot| screenshot.request.restore_vram);
                        match &frame {
                            scrap::Frame::PixelBuffer(f) => {
                                let (msg, width, height, rgba) =
                                    if screenshot_dimensions_are_bounded(f.width(), f.height()) {
                                        match get_rgba_from_pixelbuf(f) {
                                            Ok(rgba) => {
                                                (String::new(), f.width(), f.height(), rgba)
                                            }
                                            Err(err) => {
                                                log::error!(
                                                    "Failed to convert screenshot pixels into RGBA: {err}"
                                                );
                                                (
                                                    "Failed to convert screenshot pixels."
                                                        .to_owned(),
                                                    0,
                                                    0,
                                                    Vec::new(),
                                                )
                                            }
                                        }
                                    } else {
                                        log::warn!(
                                            "Rejecting screenshot dimensions {}x{}",
                                            f.width(),
                                            f.height()
                                        );
                                        (
                                            "Screenshot dimensions exceed the safety limit."
                                                .to_owned(),
                                            0,
                                            0,
                                            Vec::new(),
                                        )
                                    };
                                submit_screenshot_job(ScreenshotEncodeJob {
                                    screenshots,
                                    msg,
                                    width,
                                    height,
                                    rgba,
                                });
                            }
                            scrap::Frame::Texture(_) => {
                                let (retry, failed): (Vec<_>, Vec<_>) = screenshots
                                    .into_iter()
                                    .partition(|screenshot| !screenshot.request.restore_vram);
                                if !failed.is_empty() {
                                    submit_screenshot_job(ScreenshotEncodeJob {
                                        screenshots: failed,
                                        msg: "Please change codec and try again.".to_owned(),
                                        width: 0,
                                        height: 0,
                                        rgba: Vec::new(),
                                    });
                                }
                                if !retry.is_empty() {
                                    let mut pending = SCREENSHOTS.lock().unwrap();
                                    for screenshot in retry {
                                        pending.retry_after_texture(screenshot);
                                    }
                                    drop(pending);
                                    #[cfg(all(windows, feature = "vram"))]
                                    VRamEncoder::set_not_use(sp.name(), true);
                                    _raii.try_vram = false;
                                }
                            }
                        }
                        if restore_vram || matches!(&frame, scrap::Frame::Texture(_)) {
                            bail!("SWITCH");
                        }
                    }

                    let frame = frame.to(encoder.yuvfmt(), &mut yuv, &mut mid_data)?;
                    handle_one_frame(
                        display_idx,
                        &sp,
                        &frame_controller,
                        frame,
                        ms,
                        &mut encoder,
                        recorder.clone(),
                        &mut encode_fail_counter,
                        &mut first_frame,
                        capture_width,
                        capture_height,
                    )?;
                    send_counter += 1;
                }
                #[cfg(windows)]
                {
                    #[cfg(feature = "vram")]
                    if try_gdi == 1 && !c.is_gdi() {
                        VRamEncoder::set_fallback_gdi(sp.name(), false);
                    }
                    try_gdi = 0;
                }
                Ok(())
            }
            Err(err) => Err(err),
        };

        match res {
            Err(ref e) if e.kind() == WouldBlock => {
                #[cfg(windows)]
                if try_gdi > 0 && !c.is_gdi() {
                    if try_gdi > 3 {
                        c.set_gdi();
                        try_gdi = 0;
                        log::info!("No image, fall back to gdi");
                    }
                    try_gdi += 1;
                }
                #[cfg(target_os = "linux")]
                {
                    would_block_count += 1;
                    if !is_x11() {
                        if would_block_count >= 100 {
                            // to-do: Unknown reason for WouldBlock 100 times (seconds = 100 * 1 / fps)
                            // https://github.com/rustdesk/rustdesk/blob/63e6b2f8ab51743e77a151e2b7ff18816f5fa2fb/libs/scrap/src/common/wayland.rs#L81
                            //
                            // Do not reset the capturer for now, as it will cause the prompt to show every few minutes.
                            // https://github.com/rustdesk/rustdesk/issues/4276
                            //
                            // super::wayland::clear();
                            // bail!("Wayland capturer none 100 times, try restart capture");
                        }
                    }
                }
                if !encoder.latency_free() && yuv.len() > 0 {
                    // yun.len() > 0 means the frame is not texture.
                    if repeat_encode_counter < repeat_encode_max {
                        repeat_encode_counter += 1;
                        handle_one_frame(
                            display_idx,
                            &sp,
                            &frame_controller,
                            EncodeInput::YUV(&yuv),
                            ms,
                            &mut encoder,
                            recorder.clone(),
                            &mut encode_fail_counter,
                            &mut first_frame,
                            capture_width,
                            capture_height,
                        )?;
                        send_counter += 1;
                    }
                }
            }
            Err(err) => {
                // This check may be redundant, but it is better to be safe.
                // The previous check in `sp.is_option_true(OPTION_REFRESH)` block may be enough.
                if vs.source.is_monitor() {
                    try_broadcast_display_changed(
                        &sp,
                        display_idx,
                        &c,
                        true,
                        #[cfg(target_os = "android")]
                        vs.android_generation,
                    )?;
                }

                #[cfg(windows)]
                if !c.is_gdi() {
                    c.set_gdi();
                    log::info!("dxgi error, fall back to gdi: {:?}", err);
                    continue;
                }
                return Err(err.into());
            }
            _ => {
                #[cfg(target_os = "linux")]
                {
                    would_block_count = 0;
                }
            }
        }

        let timeout_millis = 3_000u64;
        let wait_begin = Instant::now();
        while wait_begin.elapsed().as_millis() < timeout_millis as _ {
            if vs.source.is_monitor() {
                check_privacy_mode_changed(
                    &sp,
                    display_idx,
                    &c,
                    #[cfg(target_os = "android")]
                    vs.android_generation,
                )?;
            }
            if frame_controller.wait_for_all(Duration::from_millis(300)) {
                break;
            }
        }

        let elapsed = now.elapsed();
        // may need to enable frame(timeout)
        log::trace!("{:?} {:?}", time::Instant::now(), elapsed);
        if elapsed < spf {
            std::thread::sleep(spf - elapsed);
        }
    }

    Ok(())
}

struct Raii {
    name: String,
    try_vram: bool,
}

impl Raii {
    fn new(name: String) -> Self {
        log::info!("new video service: {}", name);
        VIDEO_QOS.lock().unwrap().new_display(name.clone());
        Raii {
            name,
            try_vram: true,
        }
    }
}

impl Drop for Raii {
    fn drop(&mut self) {
        log::info!("stop video service: {}", self.name);
        #[cfg(feature = "vram")]
        if self.try_vram {
            VRamEncoder::set_not_use(self.name.clone(), false);
        }
        #[cfg(feature = "vram")]
        Encoder::update(scrap::codec::EncodingUpdate::Check);
        VIDEO_QOS.lock().unwrap().remove_display(&self.name);
    }
}

fn setup_encoder(
    c: &CapturerInfo,
    name: String,
    quality: f32,
    client_record: bool,
    record_incoming: bool,
    source: VideoSource,
    display_idx: usize,
) -> ResultType<(
    Encoder,
    EncoderCfg,
    CodecFormat,
    bool,
    Arc<Mutex<Option<Recorder>>>,
)> {
    let codec_format = Encoder::negotiated_codec();
    if codec_format == CodecFormat::Unknown {
        bail!("no mutually supported video codec; refusing to start video encoder");
    }
    let encoder_cfg = get_encoder_config(
        &c,
        name.to_string(),
        quality,
        client_record || record_incoming,
        source,
    );
    Encoder::set_fallback(&encoder_cfg);
    let codec_format = Encoder::negotiated_codec();
    if codec_format == CodecFormat::Unknown {
        bail!("no mutually supported video codec after fallback; refusing to start video encoder");
    }
    let recorder = get_recorder(record_incoming, display_idx, source == VideoSource::Camera);
    let use_i444 = Encoder::use_i444(&encoder_cfg);
    let encoder = Encoder::new(encoder_cfg.clone(), use_i444)?;
    Ok((encoder, encoder_cfg, codec_format, use_i444, recorder))
}

fn get_encoder_config(
    c: &CapturerInfo,
    _name: String,
    quality: f32,
    record: bool,
    _source: VideoSource,
) -> EncoderCfg {
    #[cfg(all(windows, feature = "vram"))]
    if c.is_gdi() || _source == VideoSource::Camera {
        log::info!("gdi:{}", c.is_gdi());
        VRamEncoder::set_not_use(_name, true);
    }
    #[cfg(feature = "vram")]
    Encoder::update(scrap::codec::EncodingUpdate::Check);
    // https://www.wowza.com/community/t/the-correct-keyframe-interval-in-obs-studio/95162
    let keyframe_interval = if record { Some(240) } else { None };
    let negotiated_codec = Encoder::negotiated_codec();
    match negotiated_codec {
        CodecFormat::H264 | CodecFormat::H265 => {
            #[cfg(feature = "vram")]
            if let Some(feature) = VRamEncoder::try_get(&c.device(), negotiated_codec) {
                return EncoderCfg::VRAM(VRamEncoderConfig {
                    device: c.device(),
                    width: c.width,
                    height: c.height,
                    quality,
                    feature,
                    keyframe_interval,
                });
            }
            #[cfg(feature = "hwcodec")]
            if let Some(hw) = HwRamEncoder::try_get(negotiated_codec) {
                return EncoderCfg::HWRAM(HwRamEncoderConfig {
                    name: hw.name,
                    mc_name: hw.mc_name,
                    width: c.width,
                    height: c.height,
                    quality,
                    keyframe_interval,
                });
            }
            EncoderCfg::VPX(VpxEncoderConfig {
                width: c.width as _,
                height: c.height as _,
                #[cfg(target_os = "android")]
                android_scale: c.android_scale,
                quality,
                codec: VpxVideoCodecId::VP9,
                keyframe_interval,
            })
        }
        format @ (CodecFormat::VP8 | CodecFormat::VP9) => EncoderCfg::VPX(VpxEncoderConfig {
            width: c.width as _,
            height: c.height as _,
            #[cfg(target_os = "android")]
            android_scale: c.android_scale,
            quality,
            codec: if format == CodecFormat::VP8 {
                VpxVideoCodecId::VP8
            } else {
                VpxVideoCodecId::VP9
            },
            keyframe_interval,
        }),
        CodecFormat::AV1 => EncoderCfg::VPX(VpxEncoderConfig {
            width: c.width as _,
            height: c.height as _,
            #[cfg(target_os = "android")]
            android_scale: c.android_scale,
            quality,
            codec: VpxVideoCodecId::VP9,
            keyframe_interval,
        }),
        _ => EncoderCfg::VPX(VpxEncoderConfig {
            width: c.width as _,
            height: c.height as _,
            #[cfg(target_os = "android")]
            android_scale: c.android_scale,
            quality,
            codec: VpxVideoCodecId::VP9,
            keyframe_interval,
        }),
    }
}

fn get_recorder(
    record_incoming: bool,
    display_idx: usize,
    camera: bool,
) -> Arc<Mutex<Option<Recorder>>> {
    #[cfg(windows)]
    let root = crate::platform::is_root();
    #[cfg(not(windows))]
    let root = false;
    let recorder = if record_incoming {
        // R-SV6 / R-SV1: the session-record UPLOAD egress (a reqwest POST
        // to {api-server}/api/record) is compiled out, not merely neutralized. Recording stays LOCAL
        // and is never uploaded: the upload channel is always None, so the box dials nobody (R-D6).
        let tx = None;
        Recorder::new(RecorderContext {
            server: true,
            id: Config::get_id(),
            dir: crate::ui_interface::video_save_directory(root),
            display_idx,
            camera,
            tx,
        })
        .map_or(Default::default(), |r| Arc::new(Mutex::new(Some(r))))
    } else {
        Default::default()
    };

    recorder
}

#[cfg(target_os = "android")]
fn check_change_scale(android_generation: u64, hardware: bool) -> ResultType<()> {
    use hbb_common::config::keys::OPTION_ENABLE_ANDROID_SOFTWARE_ENCODING_HALF_SCALE as SCALE_SOFT;

    // Raw-video admission is committed at the end of startCapture() in Android.
    let n = 60; // 3s
    for i in 0..n {
        if scrap::android::is_video_raw_enabled_for_generation(android_generation) {
            log::info!("raw-video generation is enabled");
            break;
        }
        log::info!("wait for start, {i}");
        std::thread::sleep(Duration::from_millis(50));
        if i == n - 1 {
            bail!("Android raw-video generation did not become active");
        }
    }
    let screen_size = scrap::android::screen_size_for_generation(android_generation)
        .ok_or_else(|| anyhow!("Android screen generation is inactive"))?;
    let scale_soft = hbb_common::config::option2bool(SCALE_SOFT, &Config::get_option(SCALE_SOFT));
    let half_scale = !hardware && scale_soft;
    log::info!("hardware: {hardware}, scale_soft: {scale_soft}, screen_size: {screen_size:?}",);
    scrap::android::call_main_service_set_half_scale_for_generation(
        android_generation,
        half_scale,
    )?;
    let old_scale = screen_size.2;
    let new_scale = scrap::android::screen_size_for_generation(android_generation)
        .ok_or_else(|| anyhow!("Android screen generation was retired during scale update"))?
        .2;
    log::info!("old_scale: {old_scale}, new_scale: {new_scale}");
    if old_scale != new_scale {
        log::info!("switch due to scale changed, {old_scale} -> {new_scale}");
        // switch is not a must, but it is better to do so.
        bail!("SWITCH");
    }
    Ok(())
}

fn check_privacy_mode_changed(
    sp: &GenericService,
    display_idx: usize,
    ci: &CapturerInfo,
    #[cfg(target_os = "android")] android_generation: u64,
) -> ResultType<()> {
    let privacy_mode_id_2 = get_privacy_mode_conn_id().unwrap_or(INVALID_PRIVACY_MODE_CONN_ID);
    if ci.privacy_mode_id != privacy_mode_id_2 {
        if privacy_mode_id_2 != INVALID_PRIVACY_MODE_CONN_ID {
            let msg_out = crate::common::make_privacy_mode_msg(
                back_notification::PrivacyModeState::PrvOnByOther,
                "".to_owned(),
            );
            sp.send_to_others(msg_out, privacy_mode_id_2);
        }
        log::info!("switch due to privacy mode changed");
        try_broadcast_display_changed(
            &sp,
            display_idx,
            ci,
            true,
            #[cfg(target_os = "android")]
            android_generation,
        )
        .ok();
        bail!("SWITCH");
    }
    Ok(())
}

#[inline]
fn handle_one_frame(
    display: usize,
    sp: &GenericService,
    frame_controller: &VideoFrameController,
    frame: EncodeInput,
    ms: i64,
    encoder: &mut Encoder,
    recorder: Arc<Mutex<Option<Recorder>>>,
    encode_fail_counter: &mut usize,
    first_frame: &mut bool,
    width: usize,
    height: usize,
) -> ResultType<()> {
    sp.snapshot(|sps| {
        // so that new sub and old sub share the same encoder after switch
        if sps.has_subscribes() {
            log::info!("switch due to new subscriber");
            bail!("SWITCH");
        }
        Ok(())
    })?;

    let first = *first_frame;
    *first_frame = false;
    match encoder.encode_to_message(frame, ms) {
        Ok(mut vf) => {
            *encode_fail_counter = 0;
            vf.display = display as _;
            let mut msg = Message::new();
            msg.set_video_frame(vf);
            recorder
                .lock()
                .unwrap()
                .as_mut()
                .map(|r| r.write_message(&msg, width, height));
            sp.send_video_frame_with_targets(msg, |connection_ids| {
                frame_controller.prepare(connection_ids);
            });
        }
        Err(e) => {
            *encode_fail_counter += 1;
            // Encoding errors are not frequent except on Android
            if !cfg!(target_os = "android") {
                log::error!("encode fail: {e:?}, times: {}", *encode_fail_counter,);
            }
            let max_fail_times = if cfg!(target_os = "android") && encoder.is_hardware() {
                9
            } else {
                3
            };
            let repeat = !encoder.latency_free();
            // repeat encoders can reach max_fail_times on the first frame
            if (first && !repeat) || *encode_fail_counter >= max_fail_times {
                *encode_fail_counter = 0;
                if encoder.is_hardware() {
                    encoder.disable();
                    log::error!("switch due to encoding fails, first frame: {first}, error: {e:?}");
                    bail!("SWITCH");
                }
            }
            match e.to_string().as_str() {
                scrap::codec::ENCODE_NEED_SWITCH => {
                    encoder.disable();
                    log::error!("switch due to encoder need switch");
                    bail!("SWITCH");
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn start_uac_elevation_check() {
    static START: Once = Once::new();
    START.call_once(|| {
        if !crate::platform::is_installed() && !crate::platform::is_root() {
            std::thread::spawn(|| loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if let Ok(uac) = is_process_consent_running() {
                    *IS_UAC_RUNNING.lock().unwrap() = uac;
                }
                if !crate::platform::is_elevated(None).unwrap_or(false) {
                    if let Ok(elevated) = crate::platform::is_foreground_window_elevated() {
                        *IS_FOREGROUND_WINDOW_ELEVATED.lock().unwrap() = elevated;
                    }
                }
            });
        }
    });
}

#[inline]
fn try_broadcast_display_changed(
    sp: &GenericService,
    display_idx: usize,
    cap: &CapturerInfo,
    refresh: bool,
    #[cfg(target_os = "android")] android_generation: u64,
) -> ResultType<()> {
    if refresh {
        // Get display information immediately.
        crate::display_service::check_displays_changed(
            #[cfg(target_os = "android")]
            android_generation,
        )
        .ok();
    }
    if let Some(display) = check_display_changed(
        cap.ndisplay,
        cap.current,
        (cap.origin.0, cap.origin.1, cap.width, cap.height),
    ) {
        log::info!("Display {} changed", display);
        if let Some(msg_out) =
            make_display_changed_msg(display_idx, Some(display), VideoSource::Monitor)
        {
            let msg_out = Arc::new(msg_out);
            sp.send_shared(msg_out.clone());
            // switch display may occur before the first video frame, add snapshot to send to new subscribers
            sp.snapshot(move |sps| {
                sps.send_shared(msg_out.clone());
                Ok(())
            })?;
            bail!("SWITCH");
        }
    }
    Ok(())
}

pub fn make_display_changed_msg(
    display_idx: usize,
    opt_display: Option<DisplayInfo>,
    source: VideoSource,
) -> Option<Message> {
    let display = match opt_display {
        Some(d) => d,
        None => match source {
            VideoSource::Monitor => display_service::get_display_info(display_idx)?,
            VideoSource::Camera => camera::Cameras::get_sync_cameras()
                .get(display_idx)?
                .clone(),
        },
    };
    let mut misc = Misc::new();
    misc.set_switch_display(SwitchDisplay {
        display: display_idx as _,
        x: display.x,
        y: display.y,
        width: display.width,
        height: display.height,
        cursor_embedded: match source {
            VideoSource::Monitor => display_service::capture_cursor_embedded(),
            VideoSource::Camera => false,
        },
        #[cfg(not(target_os = "android"))]
        resolutions: Some(SupportedResolutions {
            resolutions: match source {
                VideoSource::Monitor => {
                    if display.name.is_empty() {
                        vec![]
                    } else {
                        crate::platform::resolutions(&display.name)
                    }
                }
                VideoSource::Camera => camera::Cameras::get_camera_resolution(display_idx)
                    .ok()
                    .into_iter()
                    .collect(),
            },
            ..SupportedResolutions::default()
        })
        .into(),
        original_resolution: display.original_resolution,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_misc(misc);
    Some(msg_out)
}

fn check_qos(
    encoder: &mut Encoder,
    ratio: &mut f32,
    spf: &mut Duration,
    client_record: bool,
    send_counter: &mut usize,
    second_instant: &mut Instant,
    name: &str,
) -> ResultType<()> {
    let mut video_qos = VIDEO_QOS.lock().unwrap();
    *spf = video_qos.spf();
    if *ratio != video_qos.ratio() {
        *ratio = video_qos.ratio();
        if encoder.support_changing_quality() {
            allow_err!(encoder.set_quality(*ratio));
            video_qos.store_bitrate(encoder.bitrate());
        } else {
            // Now only vaapi doesn't support changing quality
            if !video_qos.in_vbr_state() && !video_qos.latest_quality().is_custom() {
                log::info!("switch to change quality");
                bail!("SWITCH");
            }
        }
    }
    if client_record != video_qos.record() {
        log::info!("switch due to record changed");
        bail!("SWITCH");
    }
    if second_instant.elapsed() > Duration::from_secs(1) {
        *second_instant = Instant::now();
        video_qos.update_display_data(&name, *send_counter);
        *send_counter = 0;
    }
    drop(video_qos);
    Ok(())
}

// R-S11ef/R-S19: source/display chooses the capture loop, while connection id plus the exact
// response channel owns the request. One connection may have one in-flight and one replaceable
// pending request; different connections never overwrite each other.
pub fn set_take_screenshot(
    connection_id: i32,
    source: VideoSource,
    display_idx: usize,
    sid: String,
    tx: Sender,
) -> bool {
    match SCREENSHOTS.lock().unwrap().replace(
        connection_id,
        source,
        display_idx,
        sid.clone(),
        tx.clone(),
    ) {
        Ok(()) => true,
        Err(ScreenshotAdmissionError::Capacity) => {
            log::warn!(
                "Rejecting screenshot request because {} owners are already pending",
                MAX_SCREENSHOT_REQUEST_OWNERS
            );
            send_screenshot_response(
                &tx,
                sid,
                "Too many screenshot requests are pending.".to_owned(),
                bytes::Bytes::new(),
            );
            false
        }
    }
}

pub fn cancel_take_screenshot(connection_id: i32, tx: &Sender) {
    match SCREENSHOTS.lock() {
        Ok(mut pending) => pending.cancel(connection_id, tx),
        Err(err) => log::error!("Failed to cancel screenshot request after lock poisoning: {err}"),
    }
}

// We need to this function, because the `stride` may be larger than `width * 4`.
fn get_rgba_from_pixelbuf<'a>(pixbuf: &scrap::PixelBuffer<'a>) -> ResultType<Vec<u8>> {
    let w = pixbuf.width();
    let h = pixbuf.height();
    let stride = pixbuf.stride();
    let Some(s) = stride.get(0) else {
        bail!("Invalid pixel buf stride.")
    };

    if *s == w * 4 {
        let mut rgba = vec![];
        scrap::convert(pixbuf, scrap::Pixfmt::RGBA, &mut rgba)?;
        Ok(rgba)
    } else {
        let bgra = pixbuf.data();
        let mut bit_flipped = Vec::with_capacity(w * h * 4);
        for y in 0..h {
            for x in 0..w {
                let i = s * y + 4 * x;
                bit_flipped.extend_from_slice(&[bgra[i + 2], bgra[i + 1], bgra[i], bgra[i + 3]]);
            }
        }
        Ok(bit_flipped)
    }
}

fn screenshot_dimensions_are_bounded(width: usize, height: usize) -> bool {
    width > 0
        && height > 0
        && width <= crate::peer_text::MAX_PEER_SCREENSHOT_DIMENSION as usize
        && height <= crate::peer_text::MAX_PEER_SCREENSHOT_DIMENSION as usize
        && width
            .checked_mul(height)
            .map(|pixels| pixels as u64 <= crate::peer_text::MAX_PEER_SCREENSHOT_PIXELS)
            .unwrap_or(false)
        && width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(4))
            .is_some()
}

fn send_screenshot_response(tx: &Sender, sid: String, msg: String, data: bytes::Bytes) {
    let mut response = ScreenshotResponse::new();
    response.sid = sid;
    response.msg = msg;
    response.data = data;
    let mut msg_out = Message::new();
    msg_out.set_screenshot_response(response);
    if let Err(err) = tx.send((hbb_common::tokio::time::Instant::now(), Arc::new(msg_out))) {
        log::error!("Failed to send screenshot: {err}");
    }
}

fn complete_screenshot_work(screenshot: ScreenshotWork, msg: &str, data: &bytes::Bytes) {
    send_screenshot_response(
        &screenshot.tx,
        screenshot.request.sid,
        msg.to_owned(),
        data.clone(),
    );
    SCREENSHOTS
        .lock()
        .unwrap()
        .complete(screenshot.connection_id, &screenshot.tx);
}

fn fail_screenshot_job(job: ScreenshotEncodeJob, msg: &str) {
    let empty = bytes::Bytes::new();
    for screenshot in job.screenshots {
        if SCREENSHOTS.lock().unwrap().is_in_flight(&screenshot) {
            complete_screenshot_work(screenshot, msg, &empty);
        }
    }
}

fn submit_screenshot_job(job: ScreenshotEncodeJob) {
    if job.screenshots.is_empty() {
        return;
    }
    let sender = match &*SCREENSHOT_ENCODER {
        Ok(encoder) => &encoder.sender,
        Err(err) => {
            log::error!("{err}");
            fail_screenshot_job(job, "Screenshot encoder is unavailable.");
            return;
        }
    };
    match sender.try_send(job) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full(job)) => {
            log::warn!("Screenshot encoder queue is full");
            fail_screenshot_job(job, "Screenshot encoder is busy; please try again.");
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(job)) => {
            log::error!("Screenshot encoder worker stopped");
            fail_screenshot_job(job, "Screenshot encoder is unavailable.");
        }
    }
}

fn handle_screenshot_job(mut job: ScreenshotEncodeJob) {
    {
        let pending = SCREENSHOTS.lock().unwrap();
        job.screenshots
            .retain(|screenshot| pending.is_in_flight(screenshot));
    }
    if job.screenshots.is_empty() {
        return;
    }

    if !job.msg.is_empty() {
        let msg = std::mem::take(&mut job.msg);
        fail_screenshot_job(job, &msg);
        return;
    }
    if !screenshot_dimensions_are_bounded(job.width, job.height) {
        fail_screenshot_job(job, "Screenshot dimensions exceed the safety limit.");
        return;
    }
    let Some(expected_len) = job
        .width
        .checked_mul(job.height)
        .and_then(|pixels| pixels.checked_mul(4))
    else {
        fail_screenshot_job(job, "Screenshot dimensions exceed the safety limit.");
        return;
    };
    if job.rgba.len() != expected_len {
        fail_screenshot_job(job, "Screenshot pixel data is invalid.");
        return;
    }

    let mut png = BoundedScreenshotPng::new();
    let encoded = (|| -> ResultType<()> {
        let mut encoder =
            repng::Options::smallest(job.width as _, job.height as _).build(&mut png)?;
        encoder.write(&job.rgba)?;
        encoder.finish()?;
        Ok(())
    })();
    if let Err(err) = encoded {
        log::error!("Failed to encode screenshot PNG: {err}");
        fail_screenshot_job(job, "Failed to encode screenshot.");
        return;
    }
    let png = png.into_bytes();
    if png.len() > crate::peer_text::MAX_PEER_SCREENSHOT_RESPONSE_BYTES {
        log::warn!(
            "Rejecting encoded screenshot of {} bytes (limit {})",
            png.len(),
            crate::peer_text::MAX_PEER_SCREENSHOT_RESPONSE_BYTES
        );
        fail_screenshot_job(job, "Encoded screenshot exceeds the safety limit.");
        return;
    }

    let png = bytes::Bytes::from(png);
    for screenshot in job.screenshots {
        if SCREENSHOTS.lock().unwrap().is_in_flight(&screenshot) {
            complete_screenshot_work(screenshot, "", &png);
        }
    }
}

#[cfg(test)]
mod video_frame_ack_tests {
    use super::*;

    static ACK_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn ids(values: &[i32]) -> HashSet<i32> {
        values.iter().copied().collect()
    }

    #[test]
    fn r_s11eg_monitor_and_camera_acknowledgements_are_source_exact() {
        let _test = ACK_TEST_LOCK.lock().unwrap();
        let monitor = VideoFrameController::new(VideoSource::Monitor, 10_001).unwrap();
        let camera = VideoFrameController::new(VideoSource::Camera, 10_001).unwrap();
        monitor.prepare(&ids(&[11]));
        camera.prepare(&ids(&[12]));

        notify_video_frame_fetched(VideoSource::Monitor, 10_001, 11, None);
        assert!(monitor.wait_for_all(Duration::ZERO));
        assert!(!camera.wait_for_all(Duration::ZERO));

        notify_video_frame_fetched(VideoSource::Camera, 10_001, 12, None);
        assert!(camera.wait_for_all(Duration::ZERO));
    }

    #[test]
    fn r_s11eg_only_pending_exact_connection_ids_complete_a_round() {
        let _test = ACK_TEST_LOCK.lock().unwrap();
        let controller = VideoFrameController::new(VideoSource::Monitor, 10_002).unwrap();
        controller.prepare(&ids(&[21, 22]));

        notify_video_frame_fetched(VideoSource::Monitor, 10_002, 99, None);
        notify_video_frame_fetched(VideoSource::Monitor, 10_002, 21, None);
        notify_video_frame_fetched(VideoSource::Monitor, 10_002, 21, None);
        assert!(!controller.wait_for_all(Duration::ZERO));

        notify_video_frame_fetched(VideoSource::Monitor, 10_002, 22, None);
        assert!(controller.wait_for_all(Duration::ZERO));
    }

    #[test]
    fn r_s11eg_displayless_acknowledgement_reaches_only_its_source() {
        let _test = ACK_TEST_LOCK.lock().unwrap();
        let first_monitor = VideoFrameController::new(VideoSource::Monitor, 10_003).unwrap();
        let second_monitor = VideoFrameController::new(VideoSource::Monitor, 10_004).unwrap();
        let camera = VideoFrameController::new(VideoSource::Camera, 10_003).unwrap();
        for controller in [&first_monitor, &second_monitor, &camera] {
            controller.prepare(&ids(&[31]));
        }

        notify_video_frame_fetched_by_conn_id(VideoSource::Monitor, 31, None);
        assert!(first_monitor.wait_for_all(Duration::ZERO));
        assert!(second_monitor.wait_for_all(Duration::ZERO));
        assert!(!camera.wait_for_all(Duration::ZERO));
    }

    #[test]
    fn r_s11eg_controller_registration_is_bounded_and_exactly_retired() {
        let _test = ACK_TEST_LOCK.lock().unwrap();
        let controllers = (0..MAX_VIDEO_FRAME_ACK_CONTROLLERS)
            .map(|display_idx| {
                VideoFrameController::new(VideoSource::Monitor, 20_000 + display_idx)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(VideoFrameController::new(VideoSource::Camera, 30_000).is_err());
        assert!(
            VideoFrameController::new(VideoSource::Monitor, 20_000).is_err(),
            "an active stream key must not be adopted or replaced"
        );

        drop(controllers);
        VideoFrameController::new(VideoSource::Monitor, 20_000).unwrap();
    }

    #[test]
    fn r_s11eg_acknowledgement_round_is_installed_before_frame_enqueue() {
        let _test = ACK_TEST_LOCK.lock().unwrap();
        let service = GenericService::new("ack-order-test".to_owned(), false);
        let (sender, mut receiver) = hbb_common::tokio::sync::mpsc::unbounded_channel();
        service.on_subscribe(ConnInner::new(41, Some(sender), None));

        service.send_video_frame_with_targets(Message::new(), |connection_ids| {
            assert_eq!(connection_ids, &ids(&[41]));
            assert!(
                receiver.try_recv().is_err(),
                "the frame must not be enqueued before acknowledgement ownership exists"
            );
        });
        assert!(
            receiver.try_recv().is_ok(),
            "the frame must be enqueued after exact targets are prepared"
        );
    }
}

#[cfg(test)]
mod screenshot_ownership_tests {
    use super::*;

    fn sender() -> Sender {
        let (tx, _rx) = hbb_common::tokio::sync::mpsc::unbounded_channel();
        tx
    }

    #[test]
    fn r_s11ef_concurrent_connections_keep_distinct_screenshot_requests() {
        let mut pending = PendingScreenshots::default();
        let first_tx = sender();
        let second_tx = sender();
        pending
            .replace(11, VideoSource::Monitor, 0, "first".to_owned(), first_tx)
            .unwrap();
        pending
            .replace(12, VideoSource::Monitor, 0, "second".to_owned(), second_tx)
            .unwrap();

        let mut work = pending.take_for_frame(VideoSource::Monitor, 0);
        work.sort_by_key(|screenshot| screenshot.connection_id);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].connection_id, 11);
        assert_eq!(work[0].request.sid, "first");
        assert_eq!(work[1].connection_id, 12);
        assert_eq!(work[1].request.sid, "second");
    }

    #[test]
    fn r_s11ef_in_flight_request_has_one_replaceable_successor() {
        let mut pending = PendingScreenshots::default();
        let tx = sender();
        pending
            .replace(21, VideoSource::Monitor, 1, "first".to_owned(), tx.clone())
            .unwrap();
        let mut first = pending.take_for_frame(VideoSource::Monitor, 1);
        assert_eq!(first.len(), 1);

        pending
            .replace(21, VideoSource::Monitor, 1, "second".to_owned(), tx.clone())
            .unwrap();
        pending
            .replace(21, VideoSource::Monitor, 1, "latest".to_owned(), tx.clone())
            .unwrap();
        assert!(pending.take_for_frame(VideoSource::Monitor, 1).is_empty());

        let first = first.pop().unwrap();
        pending.complete(first.connection_id, &first.tx);
        let successor = pending.take_for_frame(VideoSource::Monitor, 1);
        assert_eq!(successor.len(), 1);
        assert_eq!(successor[0].request.sid, "latest");
    }

    #[test]
    fn r_s11ef_stale_channel_cannot_cancel_reused_connection_id() {
        let mut pending = PendingScreenshots::default();
        let stale_tx = sender();
        let replacement_tx = sender();
        pending
            .replace(
                31,
                VideoSource::Monitor,
                0,
                "stale".to_owned(),
                stale_tx.clone(),
            )
            .unwrap();
        pending
            .replace(
                31,
                VideoSource::Camera,
                2,
                "replacement".to_owned(),
                replacement_tx.clone(),
            )
            .unwrap();

        pending.cancel(31, &stale_tx);
        let work = pending.take_for_frame(VideoSource::Camera, 2);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].request.sid, "replacement");
        assert!(work[0].tx.same_channel(&replacement_tx));
    }

    #[test]
    fn r_s11ef_disconnect_retires_pending_and_in_flight_authority() {
        let mut pending = PendingScreenshots::default();
        let pending_tx = sender();
        let in_flight_tx = sender();
        pending
            .replace(
                35,
                VideoSource::Monitor,
                0,
                "pending".to_owned(),
                pending_tx.clone(),
            )
            .unwrap();
        pending
            .replace(
                36,
                VideoSource::Monitor,
                0,
                "in-flight".to_owned(),
                in_flight_tx.clone(),
            )
            .unwrap();
        let work = pending.take_for_frame(VideoSource::Monitor, 0);
        assert_eq!(work.len(), 2);

        pending.cancel(35, &pending_tx);
        pending.cancel(36, &in_flight_tx);
        assert!(!pending.owners.contains_key(&35));
        assert!(!pending.owners.contains_key(&36));
        assert!(work
            .iter()
            .all(|screenshot| !pending.is_in_flight(screenshot)));
    }

    #[test]
    fn r_s11ef_texture_retry_never_overwrites_newer_pending_request() {
        let mut pending = PendingScreenshots::default();
        let tx = sender();
        pending
            .replace(41, VideoSource::Monitor, 3, "old".to_owned(), tx.clone())
            .unwrap();
        let mut old = pending.take_for_frame(VideoSource::Monitor, 3);
        pending
            .replace(41, VideoSource::Monitor, 3, "new".to_owned(), tx.clone())
            .unwrap();
        pending.retry_after_texture(old.pop().unwrap());

        let work = pending.take_for_frame(VideoSource::Monitor, 3);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].request.sid, "new");
        assert!(!work[0].request.restore_vram);
    }

    #[test]
    fn r_s11ef_texture_retry_is_owned_and_happens_only_once() {
        let mut pending = PendingScreenshots::default();
        let tx = sender();
        pending
            .replace(51, VideoSource::Monitor, 4, "retry".to_owned(), tx)
            .unwrap();
        let mut first = pending.take_for_frame(VideoSource::Monitor, 4);
        pending.retry_after_texture(first.pop().unwrap());

        let retry = pending.take_for_frame(VideoSource::Monitor, 4);
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].request.sid, "retry");
        assert!(retry[0].request.restore_vram);
    }

    #[test]
    fn r_s11ef_screenshot_owner_table_is_bounded() {
        let mut pending = PendingScreenshots::default();
        for connection_id in 0..MAX_SCREENSHOT_REQUEST_OWNERS {
            pending
                .replace(
                    connection_id as i32,
                    VideoSource::Monitor,
                    0,
                    format!("request-{connection_id}"),
                    sender(),
                )
                .unwrap();
        }
        assert_eq!(pending.owners.len(), MAX_SCREENSHOT_REQUEST_OWNERS);
        assert_eq!(
            pending.replace(
                MAX_SCREENSHOT_REQUEST_OWNERS as i32,
                VideoSource::Monitor,
                0,
                "overflow".to_owned(),
                sender(),
            ),
            Err(ScreenshotAdmissionError::Capacity)
        );
        pending
            .replace(
                0,
                VideoSource::Camera,
                1,
                "replacement".to_owned(),
                sender(),
            )
            .unwrap();
        assert_eq!(pending.owners.len(), MAX_SCREENSHOT_REQUEST_OWNERS);
    }

    #[test]
    fn r_s11ef_screenshot_dimensions_and_pixels_are_bounded() {
        assert!(screenshot_dimensions_are_bounded(1920, 1080));
        assert!(!screenshot_dimensions_are_bounded(0, 1080));
        assert!(!screenshot_dimensions_are_bounded(
            crate::peer_text::MAX_PEER_SCREENSHOT_DIMENSION as usize + 1,
            1
        ));
        assert!(!screenshot_dimensions_are_bounded(8_193, 8_193));
    }

    #[test]
    fn r_s11ef_png_writer_stops_at_encoded_byte_limit() {
        let mut png = BoundedScreenshotPng::with_limit(4);
        std::io::Write::write_all(&mut png, b"1234").unwrap();
        assert!(std::io::Write::write_all(&mut png, b"5").is_err());
        assert_eq!(png.into_bytes(), b"1234");
    }
}
