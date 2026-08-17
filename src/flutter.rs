use crate::{
    client::*,
    flutter_ffi::{EventToUI, SessionID},
    ui_session_interface::{InvokeUiSession, Session},
};
use flutter_rust_bridge::StreamSink;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::dlopen::{
    symbor::{Library, Symbol},
    Error as LibError,
};
use hbb_common::{
    anyhow::anyhow, bail, config::LocalConfig, get_version_number, log, message_proto::*,
    rendezvous_proto::ConnType, ResultType,
};
use serde::Serialize;
use serde_json::json;
#[cfg(windows)]
use std::ffi::CStr;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
#[cfg(any(target_os = "android", test))]
use std::sync::{mpsc, Condvar, Mutex};
use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    os::raw::{c_char, c_int, c_void},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

/// tag "main" for [Desktop Main Page] and [Mobile (Client and Server)] (the mobile don't need multiple windows, only one global event stream is needed)
/// tag "cm" only for [Desktop CM Page]
pub(crate) const APP_TYPE_MAIN: &str = "main";
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) const APP_TYPE_CM: &str = "cm";
#[cfg(any(target_os = "android", target_os = "ios"))]
pub(crate) const APP_TYPE_CM: &str = "main";

// Do not remove the following constants.
// Uncomment them when they are used.
// pub(crate) const APP_TYPE_DESKTOP_REMOTE: &str = "remote";
// pub(crate) const APP_TYPE_DESKTOP_FILE_TRANSFER: &str = "file transfer";
// pub(crate) const APP_TYPE_DESKTOP_PORT_FORWARD: &str = "port forward";

const MAX_REMOTE_CURSOR_PIXELS: usize = 1024 * 1024;
const MAX_REMOTE_CURSOR_RGBA_BYTES: usize = MAX_REMOTE_CURSOR_PIXELS * 4;
const CURSOR_SHAPE_CACHE_MAX_ENTRIES: usize = 64;
const CURSOR_SHAPE_CACHE_MAX_RGBA_BYTES: usize = 16 * 1024 * 1024;

pub type FlutterSession = Arc<Session<FlutterHandler>>;

lazy_static::lazy_static! {
    pub(crate) static ref CUR_SESSION_ID: RwLock<SessionID> = Default::default(); // For desktop only
    static ref GLOBAL_EVENT_STREAM: RwLock<HashMap<String, StreamSink<String>>> = Default::default(); // rust to dart event channel
}

#[cfg(any(target_os = "android", test))]
lazy_static::lazy_static! {
    static ref ANDROID_CLIENT_OWNER: RwLock<AndroidClientOwnerState> = Default::default();
}

#[derive(Default)]
struct AndroidClientOwnerState {
    generation: u64,
    session_id: Option<SessionID>,
    drain_barrier: u64,
}

impl AndroidClientOwnerState {
    fn begin(&mut self, drain_barrier: u64) -> Option<(u64, Option<SessionID>)> {
        let generation = self.generation.checked_add(1)?;
        if generation > i64::MAX as u64 {
            return None;
        }
        self.generation = generation;
        self.drain_barrier = drain_barrier;
        Some((generation, self.session_id.take()))
    }

    fn bind(&mut self, generation: u64, session_id: SessionID) -> bool {
        if generation != self.generation {
            return false;
        }
        match self.session_id {
            Some(current) => current == session_id,
            None => {
                self.session_id = Some(session_id);
                true
            }
        }
    }

    fn resume(&self, generation: u64, session_id: SessionID) -> Option<u64> {
        if generation == 0
            || generation > self.generation
            || self.session_id.as_ref() != Some(&session_id)
        {
            return None;
        }
        // The UUID names the Flutter isolate. If this is still the current isolate, return the
        // authoritative native generation even if Android interrupted the previous JNI response
        // before Kotlin recorded it; needlessly advancing here would drain this owner's sessions.
        Some(self.generation)
    }

    fn allows(&self, session_id: &SessionID) -> bool {
        self.session_id.as_ref() == Some(session_id)
    }

    fn admission_barrier(&self, session_id: &SessionID) -> Option<(u64, u64)> {
        self.allows(session_id)
            .then_some((self.generation, self.drain_barrier))
    }

    fn retire(&mut self, generation: u64, session_id: &SessionID) -> bool {
        if generation != self.generation || self.session_id.as_ref() != Some(session_id) {
            return false;
        }
        self.session_id = None;
        true
    }
}

fn remote_cursor_rgba_len(width: i32, height: i32) -> Option<usize> {
    let width = usize::try_from(width).ok()?;
    let height = usize::try_from(height).ok()?;
    if width == 0 || height == 0 {
        return None;
    }
    let pixels = width.checked_mul(height)?;
    if pixels > MAX_REMOTE_CURSOR_PIXELS {
        return None;
    }
    pixels.checked_mul(4)
}

fn remote_cursor_rgba_for_ui(cd: &CursorData) -> Option<Vec<u8>> {
    let expected = remote_cursor_rgba_len(cd.width, cd.height)?;
    if cd.hotx < 0 || cd.hoty < 0 || cd.hotx >= cd.width || cd.hoty >= cd.height {
        log::warn!(
            "dropping remote cursor with invalid hotspot before Flutter handoff: hotx={}, hoty={}, width={}, height={}",
            cd.hotx,
            cd.hoty,
            cd.width,
            cd.height
        );
        return None;
    }
    let colors = hbb_common::compress::decompress_with_limit(&cd.colors, expected);
    if colors.len() != expected || colors.len() > MAX_REMOTE_CURSOR_RGBA_BYTES {
        log::warn!(
            "dropping invalid remote cursor payload before Flutter handoff: width={}, height={}, bytes={}, expected={}, max={}",
            cd.width,
            cd.height,
            colors.len(),
            expected,
            MAX_REMOTE_CURSOR_RGBA_BYTES
        );
        return None;
    }
    Some(colors)
}

#[cfg(target_os = "windows")]
lazy_static::lazy_static! {
    pub static ref TEXTURE_RGBA_RENDERER_PLUGIN: Result<Library, LibError> = load_plugin_in_app_path("texture_rgba_renderer_plugin.dll");
}

#[cfg(target_os = "linux")]
lazy_static::lazy_static! {
    pub static ref TEXTURE_RGBA_RENDERER_PLUGIN: Result<Library, LibError> =
        load_linux_texture_plugin();
}

#[cfg(target_os = "macos")]
lazy_static::lazy_static! {
    pub static ref TEXTURE_RGBA_RENDERER_PLUGIN: Result<Library, LibError> = Library::open_self();
}

#[cfg(target_os = "linux")]
const LINUX_TEXTURE_RGBA_RENDERER_PLUGIN: &str = "libtexture_rgba_renderer_plugin.so";

#[cfg(target_os = "linux")]
fn linux_texture_plugin_path(executable: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    if !executable.is_absolute()
        || executable.file_name().is_none()
        || !executable.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(IoError::new(
            IoErrorKind::InvalidInput,
            "RustDesk executable path is not a clean absolute file path",
        ));
    }
    let parent = executable.parent().ok_or_else(|| {
        IoError::new(
            IoErrorKind::InvalidInput,
            "RustDesk executable path has no application directory",
        )
    })?;
    Ok(parent.join("lib").join(LINUX_TEXTURE_RGBA_RENDERER_PLUGIN))
}

#[cfg(target_os = "linux")]
fn load_linux_texture_plugin() -> Result<Library, LibError> {
    let executable = std::env::current_exe().map_err(LibError::OpeningLibraryError)?;
    let path = linux_texture_plugin_path(&executable).map_err(LibError::OpeningLibraryError)?;
    Library::open(path)
}

#[cfg(all(target_os = "linux", test))]
mod linux_texture_plugin_path_tests {
    use super::*;

    #[test]
    fn r_s11gf_linux_texture_plugin_is_exactly_application_relative() {
        assert_eq!(
            linux_texture_plugin_path(std::path::Path::new("/usr/share/rustdesk/rustdesk"))
                .unwrap(),
            std::path::Path::new("/usr/share/rustdesk/lib/libtexture_rgba_renderer_plugin.so")
        );
        assert_eq!(
            linux_texture_plugin_path(std::path::Path::new("/tmp/bundle/rustdesk")).unwrap(),
            std::path::Path::new("/tmp/bundle/lib/libtexture_rgba_renderer_plugin.so")
        );
    }

    #[test]
    fn r_s11gf_linux_texture_plugin_rejects_ambient_or_unclean_roots() {
        assert!(linux_texture_plugin_path(std::path::Path::new("rustdesk")).is_err());
        assert!(linux_texture_plugin_path(std::path::Path::new(
            "/usr/share/rustdesk/../attacker/rustdesk"
        ))
        .is_err());
        assert!(linux_texture_plugin_path(std::path::Path::new("/")).is_err());
    }
}

// Move this function into `src/platform/windows.rs` if there're more calls to load plugins.
// Load dll with full path.
#[cfg(target_os = "windows")]
fn load_plugin_in_app_path(dll_name: &str) -> Result<Library, LibError> {
    match std::env::current_exe() {
        Ok(exe_file) => {
            if let Some(cur_dir) = exe_file.parent() {
                let full_path = cur_dir.join(dll_name);
                if !full_path.exists() {
                    Err(LibError::OpeningLibraryError(IoError::new(
                        IoErrorKind::NotFound,
                        format!("{} not found", dll_name),
                    )))
                } else {
                    Library::open(full_path)
                }
            } else {
                Err(LibError::OpeningLibraryError(IoError::new(
                    IoErrorKind::Other,
                    format!(
                        "Invalid exe parent for {}",
                        exe_file.to_string_lossy().as_ref()
                    ),
                )))
            }
        }
        Err(e) => Err(LibError::OpeningLibraryError(e)),
    }
}

/// FFI for rustdesk core's main entry.
/// Return true if the app should continue running with UI(possibly Flutter), false if the app should exit.
#[cfg(not(windows))]
#[no_mangle]
pub extern "C" fn rustdesk_core_main() -> bool {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if crate::core_main::core_main().is_some() {
        return true;
    } else {
        #[cfg(target_os = "macos")]
        std::process::exit(0);
    }
    #[cfg(not(target_os = "macos"))]
    false
}

#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn handle_applicationShouldOpenUntitledFile() {
    crate::platform::macos::handle_application_should_open_untitled_file();
}

#[cfg(windows)]
#[no_mangle]
pub extern "C" fn rustdesk_core_main_args(args_len: *mut c_int) -> *mut *mut c_char {
    unsafe { std::ptr::write(args_len, 0) };
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        if let Some(args) = crate::core_main::core_main() {
            return rust_args_to_c_args(args, args_len);
        }
        return std::ptr::null_mut() as _;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return std::ptr::null_mut() as _;
}

#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn rustdesk_send_url_scheme(url: *const c_char) -> bool {
    if url.is_null() {
        return false;
    }
    let url = match CStr::from_ptr(url).to_str() {
        Ok(url) => url.trim(),
        Err(err) => {
            log::warn!("Rejected non-UTF-8 Windows URL IPC handoff: {}", err);
            return false;
        }
    };
    if url.is_empty() || !url.starts_with(&crate::get_uri_prefix()) {
        return false;
    }
    match crate::ipc::send_url_scheme(url.to_owned()) {
        Ok(()) => true,
        Err(err) => {
            log::debug!("Windows URL IPC handoff failed: {}", err);
            false
        }
    }
}

// https://gist.github.com/iskakaushik/1c5b8aa75c77479c33c4320913eebef6
#[cfg(windows)]
fn rust_args_to_c_args(args: Vec<String>, outlen: *mut c_int) -> *mut *mut c_char {
    let mut v = vec![];

    // Let's fill a vector with null-terminated strings
    for s in args {
        match CString::new(s) {
            Ok(s) => v.push(s),
            Err(_) => return std::ptr::null_mut() as _,
        }
    }

    // Turning each null-terminated string into a pointer.
    // `into_raw` takes ownershop, gives us the pointer and does NOT drop the data.
    let mut out = v.into_iter().map(|s| s.into_raw()).collect::<Vec<_>>();

    // Make sure we're not wasting space.
    out.shrink_to_fit();
    debug_assert!(out.len() == out.capacity());

    // Get the pointer to our vector.
    let len = out.len();
    let ptr = out.as_mut_ptr();
    std::mem::forget(out);

    // Let's write back the length the caller can expect
    unsafe { std::ptr::write(outlen, len as c_int) };

    // Finally return the data
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn free_c_args(ptr: *mut *mut c_char, len: c_int) {
    let len = len as usize;

    // Get back our vector.
    // Previously we shrank to fit, so capacity == length.
    let v = Vec::from_raw_parts(ptr, len, len);

    // Now drop one string at a time.
    for elem in v {
        let s = CString::from_raw(elem);
        std::mem::drop(s);
    }

    // Afterwards the vector will be dropped and thus freed.
}

#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn get_rustdesk_app_name(buffer: *mut u16, length: i32) -> i32 {
    let name = crate::platform::wide_string(&crate::get_app_name());
    if length > name.len() as i32 {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buffer, name.len());
        return 0;
    }
    -1
}

#[derive(Default)]
struct SessionHandler {
    event_stream: Option<StreamSink<EventToUI>>,
    // Mobile keeps one Activity/isolate owner while successive outgoing connections come and go.
    // Keep those identities separate so a delayed close for an old UI route cannot select its
    // replacement merely because both routes were created by the same isolate.
    client_owner_id: Option<SessionID>,
    // displays of current session.
    // We need this variable to check if the display is in use before pushing rgba to flutter.
    displays: Vec<usize>,
    // The first video UI route has no caller-selected display yet. Bind the peer's bounded initial
    // display to this exact handler once, before PeerInfo is consumed or published. Existing-window
    // routes arrive with an explicit display selection and never use this marker.
    awaiting_initial_display: bool,
    // Cursor movement is high-rate presentation state, not a generic unbounded Dart event. Keep
    // one exact publication and only its latest successor for this UI stream.
    cursor_position: CursorPositionMailbox,
    // Cursor shape/data follows the same exact UI stream but owns a separate low-rate mailbox so
    // decoding or registering a custom cursor cannot queue unbounded Dart-port work.
    cursor_shape: CursorShapeMailbox,
    // Only an exact Dart acknowledgement proves that this handler has decoded a shape. This
    // bounded mirror decides whether a later reference may use the ID-only typed event.
    known_cursor_shapes: CursorShapeKnowledge,
    renderer: VideoRenderer,
    // One admitted peer screenshot belongs to this exact UI session. It is cleared when a new
    // request starts, consumed only through this session's UUID, and dropped with the handler.
    screenshot: Option<OwnedScreenshot>,
}

struct OwnedScreenshot {
    request_id: String,
    data: bytes::Bytes,
}

#[derive(Clone)]
pub struct FlutterHandler {
    // ui session id -> display handler data
    session_handlers: Arc<RwLock<HashMap<SessionID, SessionHandler>>>,
    // One software-render mailbox per exact UI session and display. A Dart view may keep the
    // publication outstanding until it acknowledges that exact key, so another window must not
    // release or replace it.
    display_rgbas: Arc<RwLock<HashMap<(SessionID, usize), RgbaData>>>,
    // Tokens are never reused within this peer-session handler. They distinguish a current
    // publication from delayed completion of an older Flutter event, including across stream
    // replacement for the same UI session UUID.
    rgba_publication_counter: Arc<AtomicU64>,
    cursor_position_publication_counter: Arc<AtomicU64>,
    cursor_shape_publication_counter: Arc<AtomicU64>,
    cursor_shape_revision_counter: Arc<AtomicU64>,
    cursor_shapes: Arc<RwLock<CursorShapeCache>>,
    current_cursor: Arc<RwLock<CurrentCursorPresentation>>,
    peer_info: Arc<RwLock<PeerInfo>>,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    hooks: Arc<RwLock<HashMap<String, SessionHook>>>,
    use_texture_render: Arc<AtomicBool>,
}

impl Default for FlutterHandler {
    fn default() -> Self {
        Self {
            session_handlers: Default::default(),
            display_rgbas: Default::default(),
            rgba_publication_counter: Default::default(),
            cursor_position_publication_counter: Default::default(),
            cursor_shape_publication_counter: Default::default(),
            cursor_shape_revision_counter: Default::default(),
            cursor_shapes: Default::default(),
            current_cursor: Default::default(),
            peer_info: Default::default(),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            hooks: Default::default(),
            use_texture_render: Arc::new(
                AtomicBool::new(crate::ui_interface::use_texture_render()),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CursorPositionValue {
    x: i32,
    y: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CursorPositionPublication {
    position: CursorPositionValue,
    publication: u64,
}

#[derive(Default)]
struct CursorPositionMailbox {
    published: Option<CursorPositionPublication>,
    current: Option<CursorPositionValue>,
    delivery_failed: bool,
}

#[derive(Default)]
struct CurrentCursorPresentation {
    shape: Option<CursorShapeValue>,
    position: Option<CursorPositionValue>,
}

#[derive(Debug, Eq, PartialEq)]
enum CursorPositionOffer {
    Pending,
    Published(CursorPositionPublication),
    Exhausted,
}

#[derive(Debug, Eq, PartialEq)]
enum CursorPositionAcknowledgement {
    Ignored,
    Drained,
    Promoted(CursorPositionPublication),
    Exhausted,
}

#[derive(Debug, Eq, PartialEq)]
enum CursorPositionRearm {
    Idle,
    Rearmed(CursorPositionPublication),
    Exhausted,
}

impl CursorPositionMailbox {
    fn offer<F>(&mut self, position: CursorPositionValue, next_publication: F) -> CursorPositionOffer
    where
        F: FnOnce() -> Option<u64>,
    {
        self.current = Some(position);
        if self.published.is_some() || self.delivery_failed {
            return CursorPositionOffer::Pending;
        }
        let Some(publication) = next_publication() else {
            self.clear();
            return CursorPositionOffer::Exhausted;
        };
        let published = CursorPositionPublication {
            position,
            publication,
        };
        self.published = Some(published);
        CursorPositionOffer::Published(published)
    }

    fn acknowledge<F>(
        &mut self,
        expected: CursorPositionPublication,
        next_publication: F,
    ) -> CursorPositionAcknowledgement
    where
        F: FnOnce() -> Option<u64>,
    {
        if self.published != Some(expected) {
            return CursorPositionAcknowledgement::Ignored;
        }
        self.published = None;
        let Some(position) = self.current else {
            return CursorPositionAcknowledgement::Drained;
        };
        if position == expected.position {
            return CursorPositionAcknowledgement::Drained;
        }
        let Some(publication) = next_publication() else {
            self.clear();
            return CursorPositionAcknowledgement::Exhausted;
        };
        let published = CursorPositionPublication {
            position,
            publication,
        };
        self.published = Some(published);
        CursorPositionAcknowledgement::Promoted(published)
    }

    fn rearm<F>(&mut self, next_publication: F) -> CursorPositionRearm
    where
        F: FnOnce() -> Option<u64>,
    {
        self.delivery_failed = false;
        let Some(position) = self.current else {
            self.published = None;
            return CursorPositionRearm::Idle;
        };
        let Some(publication) = next_publication() else {
            self.clear();
            return CursorPositionRearm::Exhausted;
        };
        let published = CursorPositionPublication {
            position,
            publication,
        };
        self.published = Some(published);
        CursorPositionRearm::Rearmed(published)
    }

    fn invalidate_current(&mut self) {
        self.current = None;
    }

    fn delivery_failed(&mut self) {
        self.published = None;
        self.delivery_failed = true;
    }

    fn retain_current(&mut self, position: CursorPositionValue) {
        self.current = Some(position);
    }

    fn clear(&mut self) {
        self.published = None;
        self.current = None;
        self.delivery_failed = false;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemoteCursorShape {
    id: String,
    revision: u64,
    hotx: i32,
    hoty: i32,
    width: i32,
    height: i32,
    rgba: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CursorShapeState {
    Available(Arc<RemoteCursorShape>),
    Unavailable(String),
}

impl CursorShapeState {
    fn identity(&self) -> (&str, u64) {
        match self {
            Self::Available(shape) => (&shape.id, shape.revision),
            Self::Unavailable(id) => (id, 0),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CursorShapeValue {
    state: CursorShapeState,
    include_data: bool,
}

impl CursorShapeValue {
    fn bind_to_knowledge(mut self, known: &mut CursorShapeKnowledge) -> Self {
        if let CursorShapeState::Available(shape) = &self.state {
            self.include_data = !known.contains(shape);
        }
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CursorShapePublication {
    value: CursorShapeValue,
    publication: u64,
}

#[derive(Default)]
struct CursorShapeMailbox {
    published: Option<CursorShapePublication>,
    current: Option<CursorShapeValue>,
    delivery_failed: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum CursorShapeOffer {
    Pending,
    Published(CursorShapePublication),
    Exhausted,
}

#[derive(Debug, Eq, PartialEq)]
enum CursorShapeAcknowledgement {
    Ignored,
    Drained,
    Promoted(CursorShapePublication),
    Exhausted,
}

#[derive(Debug, Eq, PartialEq)]
enum CursorShapeRearm {
    Idle,
    Rearmed(CursorShapePublication),
    Exhausted,
}

impl CursorShapeMailbox {
    fn offer<F>(&mut self, value: CursorShapeValue, next_publication: F) -> CursorShapeOffer
    where
        F: FnOnce() -> Option<u64>,
    {
        self.current = Some(value.clone());
        if self.published.is_some() || self.delivery_failed {
            return CursorShapeOffer::Pending;
        }
        let Some(publication) = next_publication() else {
            self.clear();
            return CursorShapeOffer::Exhausted;
        };
        let published = CursorShapePublication { value, publication };
        self.published = Some(published.clone());
        CursorShapeOffer::Published(published)
    }

    fn acknowledge<F>(
        &mut self,
        id: &str,
        revision: u64,
        publication: u64,
        next_publication: F,
    ) -> CursorShapeAcknowledgement
    where
        F: FnOnce() -> Option<u64>,
    {
        let Some(published) = self.published.as_ref() else {
            return CursorShapeAcknowledgement::Ignored;
        };
        if published.value.state.identity() != (id, revision)
            || published.publication != publication
        {
            return CursorShapeAcknowledgement::Ignored;
        }
        let acknowledged = published.clone();
        self.published = None;
        let Some(current) = self.current.clone() else {
            return CursorShapeAcknowledgement::Drained;
        };
        if current == acknowledged.value {
            return CursorShapeAcknowledgement::Drained;
        }
        let Some(publication) = next_publication() else {
            self.clear();
            return CursorShapeAcknowledgement::Exhausted;
        };
        let promoted = CursorShapePublication {
            value: current,
            publication,
        };
        self.published = Some(promoted.clone());
        CursorShapeAcknowledgement::Promoted(promoted)
    }

    fn rearm<F>(&mut self, next_publication: F) -> CursorShapeRearm
    where
        F: FnOnce() -> Option<u64>,
    {
        self.delivery_failed = false;
        let Some(mut current) = self.current.clone() else {
            self.published = None;
            return CursorShapeRearm::Idle;
        };
        if matches!(&current.state, CursorShapeState::Available(_)) {
            current.include_data = true;
        }
        let Some(publication) = next_publication() else {
            self.clear();
            return CursorShapeRearm::Exhausted;
        };
        let rearmed = CursorShapePublication {
            value: current,
            publication,
        };
        self.published = Some(rearmed.clone());
        CursorShapeRearm::Rearmed(rearmed)
    }

    fn delivery_failed(&mut self) {
        self.published = None;
        self.delivery_failed = true;
    }

    fn require_data_for(&mut self, publication: &CursorShapePublication) {
        if publication.value.include_data {
            return;
        }
        if let Some(current) = self.current.as_mut() {
            if current.state == publication.value.state {
                current.include_data = true;
            }
        }
    }

    fn retain_current(&mut self, value: CursorShapeValue) {
        self.current = Some(value);
    }

    fn clear(&mut self) {
        self.published = None;
        self.current = None;
        self.delivery_failed = false;
    }
}

struct CursorShapeCacheEntry {
    shape: Arc<RemoteCursorShape>,
    rgba_bytes: usize,
    last_used: u64,
}

#[derive(Default)]
struct CursorShapeCache {
    entries: HashMap<String, CursorShapeCacheEntry>,
    rgba_bytes: usize,
    use_counter: u64,
}

struct CursorShapeKnowledgeEntry {
    revision: u64,
    rgba_bytes: usize,
    last_used: u64,
}

#[derive(Default)]
struct CursorShapeKnowledge {
    entries: HashMap<String, CursorShapeKnowledgeEntry>,
    rgba_bytes: usize,
    use_counter: u64,
}

impl CursorShapeKnowledge {
    fn clear(&mut self) {
        self.entries.clear();
        self.rgba_bytes = 0;
        self.use_counter = 0;
    }

    fn next_use(&mut self) -> u64 {
        let Some(next) = self.use_counter.checked_add(1) else {
            self.clear();
            self.use_counter = 1;
            return 1;
        };
        self.use_counter = next;
        next
    }

    fn contains(&mut self, shape: &RemoteCursorShape) -> bool {
        if !self
            .entries
            .get(&shape.id)
            .is_some_and(|entry| entry.revision == shape.revision)
        {
            return false;
        }
        let last_used = self.next_use();
        let Some(entry) = self.entries.get_mut(&shape.id) else {
            return false;
        };
        entry.last_used = last_used;
        true
    }

    fn remove(&mut self, id: &str, revision: Option<u64>) {
        let should_remove = self.entries.get(id).is_some_and(|entry| {
            revision.map_or(true, |revision| entry.revision == revision)
        });
        if !should_remove {
            return;
        }
        if let Some(removed) = self.entries.remove(id) {
            self.rgba_bytes = self.rgba_bytes.saturating_sub(removed.rgba_bytes);
        }
    }

    fn insert(&mut self, shape: &RemoteCursorShape) -> bool {
        let rgba_bytes = shape.rgba.len();
        if rgba_bytes == 0 || rgba_bytes > MAX_REMOTE_CURSOR_RGBA_BYTES {
            return false;
        }
        if let Some(previous) = self.entries.remove(&shape.id) {
            self.rgba_bytes = self.rgba_bytes.saturating_sub(previous.rgba_bytes);
        }
        let last_used = self.next_use();
        while self.entries.len() >= CURSOR_SHAPE_CACHE_MAX_ENTRIES
            || self
                .rgba_bytes
                .checked_add(rgba_bytes)
                .map_or(true, |total| total > CURSOR_SHAPE_CACHE_MAX_RGBA_BYTES)
        {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(id, _)| id.clone())
            else {
                return false;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.rgba_bytes = self.rgba_bytes.saturating_sub(removed.rgba_bytes);
            }
        }
        self.rgba_bytes = match self.rgba_bytes.checked_add(rgba_bytes) {
            Some(total) => total,
            None => return false,
        };
        self.entries.insert(
            shape.id.clone(),
            CursorShapeKnowledgeEntry {
                revision: shape.revision,
                rgba_bytes,
                last_used,
            },
        );
        true
    }
}

impl CursorShapeCache {
    fn clear(&mut self) {
        self.entries.clear();
        self.rgba_bytes = 0;
        self.use_counter = 0;
    }

    fn next_use(&mut self) -> u64 {
        let Some(next) = self.use_counter.checked_add(1) else {
            self.clear();
            self.use_counter = 1;
            return 1;
        };
        self.use_counter = next;
        next
    }

    fn get(&mut self, id: &str) -> Option<Arc<RemoteCursorShape>> {
        if !self.entries.contains_key(id) {
            return None;
        }
        let last_used = self.next_use();
        let entry = self.entries.get_mut(id)?;
        entry.last_used = last_used;
        Some(Arc::clone(&entry.shape))
    }

    fn contains(&self, shape: &RemoteCursorShape) -> bool {
        self.entries
            .get(&shape.id)
            .is_some_and(|entry| entry.shape.revision == shape.revision)
    }

    fn remove(&mut self, id: &str, revision: Option<u64>) {
        let should_remove = self.entries.get(id).is_some_and(|entry| {
            revision.map_or(true, |revision| entry.shape.revision == revision)
        });
        if !should_remove {
            return;
        }
        if let Some(removed) = self.entries.remove(id) {
            self.rgba_bytes = self.rgba_bytes.saturating_sub(removed.rgba_bytes);
        }
    }

    fn insert(&mut self, shape: Arc<RemoteCursorShape>) -> bool {
        let rgba_bytes = shape.rgba.len();
        if rgba_bytes == 0 || rgba_bytes > MAX_REMOTE_CURSOR_RGBA_BYTES {
            return false;
        }
        if let Some(previous) = self.entries.remove(&shape.id) {
            self.rgba_bytes = self.rgba_bytes.saturating_sub(previous.rgba_bytes);
        }
        let last_used = self.next_use();
        while self.entries.len() >= CURSOR_SHAPE_CACHE_MAX_ENTRIES
            || self
                .rgba_bytes
                .checked_add(rgba_bytes)
                .map_or(true, |total| total > CURSOR_SHAPE_CACHE_MAX_RGBA_BYTES)
        {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(id, _)| id.clone())
            else {
                return false;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.rgba_bytes = self.rgba_bytes.saturating_sub(removed.rgba_bytes);
            }
        }
        self.rgba_bytes = match self.rgba_bytes.checked_add(rgba_bytes) {
            Some(total) => total,
            None => return false,
        };
        self.entries.insert(
            shape.id.clone(),
            CursorShapeCacheEntry {
                shape,
                rgba_bytes,
                last_used,
            },
        );
        true
    }
}

fn is_cursor_position_topology_barrier(name: &str) -> bool {
    matches!(
        name,
        "peer_info"
            | "sync_peer_info"
            | "sync_platform_additions"
            | "switch_display"
            | "follow_current_display"
            | "use_texture_render"
    )
}

fn post_cursor_position(
    stream: &StreamSink<EventToUI>,
    publication: CursorPositionPublication,
) -> bool {
    stream.add(EventToUI::CursorPosition(
        publication.position.x,
        publication.position.y,
        publication.publication,
    ))
}

fn post_cursor_shape(
    stream: &StreamSink<EventToUI>,
    publication: &CursorShapePublication,
) -> bool {
    match &publication.value.state {
        CursorShapeState::Available(shape) if publication.value.include_data => {
            stream.add(EventToUI::CursorData(
                shape.id.clone(),
                shape.revision,
                shape.hotx,
                shape.hoty,
                shape.width,
                shape.height,
                shape.rgba.clone(),
                publication.publication,
            ))
        }
        CursorShapeState::Available(shape) => stream.add(EventToUI::CursorId(
            shape.id.clone(),
            shape.revision,
            publication.publication,
        )),
        CursorShapeState::Unavailable(id) => stream.add(EventToUI::CursorUnavailable(
            id.clone(),
            publication.publication,
        )),
    }
}

#[derive(Default)]
struct RgbaData {
    // `data` is immutable while `valid` is true. It is copied through the generated bridge under
    // the mailbox read lock, so Dart never borrows a pointer into this allocation.
    data: Vec<u8>,
    valid: bool,
    publication: u64,
    // A suspended/throttled UI retains at most the newest frame that arrived while `data` was
    // published. Replacing this slot returns its previous allocation to the decoder immediately.
    pending: Option<Vec<u8>>,
    // Empty reusable capacity from the previously published frame. This avoids allocating a third
    // frame buffer each time a delayed consumer catches up; it never represents queued work.
    spare: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
enum RgbaAcknowledgement {
    Ignored,
    Drained,
    Promoted(u64),
    Exhausted,
}

#[derive(Debug, Eq, PartialEq)]
enum RgbaRearm {
    Idle,
    Rearmed(u64),
    Exhausted,
}

impl RgbaData {
    fn offer_swap<F>(&mut self, incoming: &mut Vec<u8>, next_publication: F) -> Option<u64>
    where
        F: FnOnce() -> Option<u64>,
    {
        if !self.valid {
            let publication = next_publication()?;
            std::mem::swap(incoming, &mut self.data);
            self.valid = true;
            self.publication = publication;
            return Some(publication);
        }

        if let Some(pending) = self.pending.as_mut() {
            std::mem::swap(incoming, pending);
        } else {
            std::mem::swap(incoming, &mut self.spare);
            self.pending = Some(std::mem::take(&mut self.spare));
        }
        None
    }

    fn offer_copy<F>(&mut self, incoming: &[u8], next_publication: F) -> Option<u64>
    where
        F: FnOnce() -> Option<u64>,
    {
        if !self.valid {
            let publication = next_publication()?;
            self.valid = true;
            self.publication = publication;
            self.data.clear();
            self.data.extend_from_slice(incoming);
            return Some(publication);
        }
        if self.pending.is_none() {
            self.pending = Some(std::mem::take(&mut self.spare));
        }
        if let Some(pending) = self.pending.as_mut() {
            pending.clear();
            pending.extend_from_slice(incoming);
        }
        None
    }

    fn copy(&self, publication: u64) -> Option<Vec<u8>> {
        (self.valid && self.publication == publication).then(|| self.data.clone())
    }

    fn acknowledge<F>(&mut self, publication: u64, next_publication: F) -> RgbaAcknowledgement
    where
        F: FnOnce() -> Option<u64>,
    {
        if !self.valid || self.publication != publication {
            return RgbaAcknowledgement::Ignored;
        }
        let Some(mut latest) = self.pending.take() else {
            self.valid = false;
            self.publication = 0;
            return RgbaAcknowledgement::Drained;
        };
        let Some(publication) = next_publication() else {
            self.valid = false;
            self.publication = 0;
            return RgbaAcknowledgement::Exhausted;
        };
        std::mem::swap(&mut self.data, &mut latest);
        latest.clear();
        self.spare = latest;
        self.publication = publication;
        RgbaAcknowledgement::Promoted(publication)
    }

    fn rearm<F>(&mut self, next_publication: F) -> RgbaRearm
    where
        F: FnOnce() -> Option<u64>,
    {
        if !self.valid {
            return RgbaRearm::Idle;
        }
        let Some(publication) = next_publication() else {
            self.valid = false;
            self.publication = 0;
            self.pending = None;
            return RgbaRearm::Exhausted;
        };
        if let Some(mut latest) = self.pending.take() {
            std::mem::swap(&mut self.data, &mut latest);
            latest.clear();
            self.spare = latest;
        }
        self.publication = publication;
        RgbaRearm::Rearmed(publication)
    }
}

pub type FlutterRgbaRendererPluginTryOnRgba = unsafe extern "C" fn(
    texture_rgba: *mut c_void,
    buffer: *const u8,
    len: c_int,
    width: c_int,
    height: c_int,
    dst_rgba_stride: c_int,
) -> c_int;

pub type FlutterRgbaRendererPluginTryNotifyPending =
    unsafe extern "C" fn(texture_rgba: *mut c_void) -> c_int;

fn commit_first_texture_notification<F>(
    render_notified: &mut bool,
    frame_admitted: bool,
    notify: F,
) -> bool
where
    F: FnOnce() -> bool,
{
    if !frame_admitted || *render_notified || !notify() {
        return false;
    }
    *render_notified = true;
    true
}

pub(super) type TextureRgbaPtr = usize;

struct DisplaySessionInfo {
    // TextureRgba pointer in flutter native.
    texture_rgba_ptr: TextureRgbaPtr,
    size: (usize, usize),
    render_notified: bool,
}

// Video Texture Renderer in Flutter
#[derive(Clone)]
struct VideoRenderer {
    map_display_sessions: Arc<RwLock<HashMap<usize, DisplaySessionInfo>>>,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    on_rgba_func: Option<Symbol<'static, FlutterRgbaRendererPluginTryOnRgba>>,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    notify_pending_func: Option<Symbol<'static, FlutterRgbaRendererPluginTryNotifyPending>>,
}

impl Default for VideoRenderer {
    fn default() -> Self {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let on_rgba_func = match &*TEXTURE_RGBA_RENDERER_PLUGIN {
            Ok(lib) => {
                let find_sym_res = unsafe {
                    lib.symbol::<FlutterRgbaRendererPluginTryOnRgba>(
                        "FlutterRgbaRendererPluginTryOnRgba",
                    )
                };
                match find_sym_res {
                    Ok(sym) => Some(sym),
                    Err(e) => {
                        log::error!(
                            "Failed to find symbol FlutterRgbaRendererPluginTryOnRgba, {e}"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to load texture rgba renderer plugin, {e}");
                None
            }
        };
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let notify_pending_func = match &*TEXTURE_RGBA_RENDERER_PLUGIN {
            Ok(lib) => {
                let find_sym_res = unsafe {
                    lib.symbol::<FlutterRgbaRendererPluginTryNotifyPending>(
                        "FlutterRgbaRendererPluginTryNotifyPending",
                    )
                };
                match find_sym_res {
                    Ok(sym) => Some(sym),
                    Err(e) => {
                        log::error!(
                            "Failed to find symbol FlutterRgbaRendererPluginTryNotifyPending, {e}"
                        );
                        None
                    }
                }
            }
            Err(_) => None,
        };
        Self {
            map_display_sessions: Default::default(),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            on_rgba_func,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            notify_pending_func,
        }
    }
}

impl VideoRenderer {
    #[inline]
    fn set_size(&mut self, display: usize, width: usize, height: usize) {
        let mut sessions_lock = self.map_display_sessions.write().unwrap();
        if let Some(info) = sessions_lock.get_mut(&display) {
            info.size = (width, height);
            info.render_notified = false;
        } else {
            sessions_lock.insert(
                display,
                DisplaySessionInfo {
                    texture_rgba_ptr: usize::default(),
                    size: (width, height),
                    render_notified: false,
                },
            );
        }
    }

    fn register_pixelbuffer_texture(&self, display: usize, ptr: usize) {
        let mut sessions_lock = self.map_display_sessions.write().unwrap();
        if ptr == 0 {
            if let Some(info) = sessions_lock.get_mut(&display) {
                if info.texture_rgba_ptr != usize::default() {
                    info.texture_rgba_ptr = usize::default();
                }
            }
            sessions_lock.remove(&display);
        } else {
            if let Some(info) = sessions_lock.get_mut(&display) {
                if info.texture_rgba_ptr != usize::default()
                    && info.texture_rgba_ptr != ptr as TextureRgbaPtr
                {
                    log::warn!(
                        "texture_rgba_ptr is not null and not equal to ptr, replace {} to {}",
                        info.texture_rgba_ptr,
                        ptr
                    );
                }
                info.texture_rgba_ptr = ptr as _;
                info.render_notified = false;
            } else {
                if ptr != 0 {
                    sessions_lock.insert(
                        display,
                        DisplaySessionInfo {
                            texture_rgba_ptr: ptr as _,
                            size: (0, 0),
                            render_notified: false,
                        },
                    );
                }
            }
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn on_rgba<F>(&self, display: usize, rgba: &scrap::ImageRgb, notify: F) -> bool
    where
        F: FnOnce() -> bool,
    {
        let mut write_lock = self.map_display_sessions.write().unwrap();
        let Some(info) = write_lock.get_mut(&display) else {
            return false;
        };
        if info.texture_rgba_ptr == usize::default() {
            return false;
        }

        if info.size.0 != rgba.w || info.size.1 != rgba.h {
            log::error!(
                "width/height mismatch: ({},{}) != ({},{})",
                info.size.0,
                info.size.1,
                rgba.w,
                rgba.h
            );
            // Peer info's handling is async and may be late than video frame's handling
            // Allow peer info not set, but not allow wrong width/height for correct local cursor position
            if info.size != (0, 0) {
                return false;
            }
        }
        let Some(func) = &self.on_rgba_func else {
            return false;
        };
        let frame_admitted = unsafe {
            func(
                info.texture_rgba_ptr as _,
                rgba.raw.as_ptr() as _,
                rgba.raw.len() as _,
                rgba.w as _,
                rgba.h as _,
                rgba.align() as _,
            ) != 0
        };
        commit_first_texture_notification(&mut info.render_notified, frame_admitted, notify)
    }

    pub fn reset_all_display_notification(&self) {
        let mut write_lock = self.map_display_sessions.write().unwrap();
        write_lock
            .values_mut()
            .map(|v| v.render_notified = false)
            .count();
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn notify_pending_frame(&self, display: usize) -> ResultType<()> {
        let sessions = self.map_display_sessions.read().unwrap();
        let Some(info) = sessions.get(&display) else {
            return Ok(());
        };
        if info.texture_rgba_ptr == usize::default() {
            return Ok(());
        }
        let Some(func) = &self.notify_pending_func else {
            bail!("desktop texture pending-frame notifier is unavailable");
        };
        if unsafe { func(info.texture_rgba_ptr as _) } == 0 {
            bail!("desktop texture pending-frame notification failed");
        }
        Ok(())
    }
}

impl FlutterHandler {
    fn session_handler_for_cursor_state(
        client_owner_id: SessionID,
        current: &CurrentCursorPresentation,
    ) -> SessionHandler {
        let mut handler = SessionHandler {
            client_owner_id: Some(client_owner_id),
            ..Default::default()
        };
        if let Some(shape) = current.shape.clone() {
            handler.cursor_shape.retain_current(shape);
        }
        if let Some(position) = current.position {
            handler.cursor_position.retain_current(position);
        }
        handler
    }

    fn set_exact_owned_display_size(
        &self,
        session_id: &SessionID,
        client_owner_id: &SessionID,
        display: usize,
        width: usize,
        height: usize,
    ) -> Option<bool> {
        let mut handlers = self.session_handlers.write().unwrap();
        let handler = handlers.get_mut(session_id)?;
        if handler.client_owner_id.as_ref() != Some(client_owner_id) {
            return Some(false);
        }
        Some(handler.set_owned_display_size(display, width, height))
    }

    fn with_exact_ui_owner_renderer<F>(
        &self,
        session_id: &SessionID,
        client_owner_id: &SessionID,
        operation: F,
    ) -> Option<bool>
    where
        F: FnOnce(&VideoRenderer),
    {
        let handlers = self.session_handlers.read().unwrap();
        let handler = handlers.get(session_id)?;
        if handler.client_owner_id.as_ref() != Some(client_owner_id) {
            return Some(false);
        }
        operation(&handler.renderer);
        Some(true)
    }

    fn register_pixelbuffer_texture(
        &self,
        session_id: &SessionID,
        client_owner_id: &SessionID,
        display: usize,
        ptr: usize,
    ) -> Option<bool> {
        self.with_exact_ui_owner_renderer(session_id, client_owner_id, |renderer| {
            renderer.register_pixelbuffer_texture(display, ptr);
        })
    }
}

impl SessionHandler {
    pub fn on_waiting_for_image_dialog_show(&self) {
        self.renderer.reset_all_display_notification();
        // rgba array render will notify every frame
    }

    fn set_owned_display_size(
        &mut self,
        display: usize,
        width: usize,
        height: usize,
    ) -> bool {
        if !self.displays.contains(&display) {
            return false;
        }
        self.renderer.set_size(display, width, height);
        true
    }
}

fn bind_initial_display_owner(
    handlers: &mut HashMap<SessionID, SessionHandler>,
    current_display: i32,
    display_count: usize,
) -> ResultType<()> {
    let display = usize::try_from(current_display)
        .map_err(|_| anyhow!("initial peer display is negative"))?;
    if display >= display_count {
        bail!(
            "initial peer display {display} is outside the peer inventory of {}",
            display_count
        );
    }
    if handlers
        .values()
        .flat_map(|handler| handler.displays.iter())
        .any(|owned_display| *owned_display >= display_count)
    {
        bail!("an explicit UI display owner is outside the new peer inventory");
    }
    let pending = handlers
        .iter()
        .filter_map(|(session_id, handler)| {
            handler.awaiting_initial_display.then_some(*session_id)
        })
        .collect::<Vec<_>>();
    if pending.len() > 1 {
        bail!("more than one UI owner is awaiting the initial peer display");
    }
    let Some(session_id) = pending.first() else {
        if handlers.is_empty() || handlers.values().any(|handler| handler.displays.is_empty()) {
            bail!("no explicit UI owner exists for the initial peer display");
        }
        // A reconnect or an already-connected existing-window route retains explicit native
        // display ownership. Validate the new round's raw peer claim above, but never overwrite
        // that committed UI selection implicitly.
        return Ok(());
    };
    if handlers.iter().any(|(other_session_id, handler)| {
        other_session_id != session_id && handler.displays.is_empty()
    }) {
        bail!("an unmarked UI owner has no explicit initial display selection");
    }
    let handler = handlers
        .get_mut(session_id)
        .ok_or_else(|| anyhow!("initial peer display owner disappeared"))?;
    if !handler.displays.is_empty() {
        bail!("initial peer display owner already has an explicit display selection");
    }
    handler.displays.push(display);
    handler.awaiting_initial_display = false;
    Ok(())
}

impl FlutterHandler {
    /// Push an event to all the event queues.
    /// An event is stored as json in the event queues.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the event.
    /// * `event` - Fields of the event content.
    pub fn push_event<V>(&self, name: &str, event: &[(&str, V)], excludes: &[&SessionID])
    where
        V: Sized + Serialize + Clone,
    {
        self.push_event_(name, event, &[], excludes);
    }

    pub fn push_event_to<V>(&self, name: &str, event: &[(&str, V)], include: &[&SessionID])
    where
        V: Sized + Serialize + Clone,
    {
        self.push_event_(name, event, include, &[]);
    }

    pub fn push_event_<V>(
        &self,
        name: &str,
        event: &[(&str, V)],
        includes: &[&SessionID],
        excludes: &[&SessionID],
    ) where
        V: Sized + Serialize + Clone,
    {
        let mut h: HashMap<&str, serde_json::Value> =
            event.iter().map(|(k, v)| (*k, json!(*v))).collect();
        debug_assert!(h.get("name").is_none());
        h.insert("name", json!(name));
        let out = serde_json::ser::to_string(&h).unwrap_or("".to_owned());
        let should_push = |sid: &SessionID| {
            if includes.is_empty() {
                !excludes.contains(&sid)
            } else {
                includes.contains(&sid)
            }
        };
        if is_cursor_position_topology_barrier(name) {
            let mut current_cursor = self.current_cursor.write().unwrap();
            current_cursor.position = None;
            let mut sessions = self.session_handlers.write().unwrap();
            for (sid, session) in sessions.iter_mut() {
                if should_push(sid) {
                    // A retained cursor sample observed before this topology event cannot be
                    // published afterward and interpreted against the new geometry.
                    session.cursor_position.invalidate_current();
                    if let Some(stream) = &session.event_stream {
                        stream.add(EventToUI::Event(out.clone()));
                    }
                }
            }
            drop(sessions);
            drop(current_cursor);
        } else {
            for (sid, session) in self.session_handlers.read().unwrap().iter() {
                if should_push(sid) {
                    if let Some(stream) = &session.event_stream {
                        stream.add(EventToUI::Event(out.clone()));
                    }
                }
            }
        }
    }

    fn next_cursor_position_publication(&self) -> Option<u64> {
        self.cursor_position_publication_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current
                    .checked_add(1)
                    .filter(|next| *next <= i64::MAX as u64)
            })
            .ok()
            .and_then(|previous| previous.checked_add(1))
    }

    fn next_cursor_shape_publication(&self) -> Option<u64> {
        self.cursor_shape_publication_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current
                    .checked_add(1)
                    .filter(|next| *next <= i64::MAX as u64)
            })
            .ok()
            .and_then(|previous| previous.checked_add(1))
    }

    fn next_cursor_shape_revision(&self) -> Option<u64> {
        self.cursor_shape_revision_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current
                    .checked_add(1)
                    .filter(|next| *next <= i64::MAX as u64)
            })
            .ok()
            .and_then(|previous| previous.checked_add(1))
    }

    fn take_cursor_position(
        &self,
        session_id: &SessionID,
        client_owner_id: &SessionID,
        expected: CursorPositionPublication,
    ) -> bool {
        let mut handlers = self.session_handlers.write().unwrap();
        let Some(handler) = handlers
            .get_mut(session_id)
            .filter(|handler| handler.client_owner_id.as_ref() == Some(client_owner_id))
        else {
            return false;
        };
        match handler.cursor_position.acknowledge(expected, || {
            self.next_cursor_position_publication()
        }) {
            CursorPositionAcknowledgement::Ignored => false,
            CursorPositionAcknowledgement::Drained => true,
            CursorPositionAcknowledgement::Promoted(next) => {
                if let Some(stream) = &handler.event_stream {
                    if !post_cursor_position(stream, next) {
                        handler.cursor_position.delivery_failed();
                    }
                }
                true
            }
            CursorPositionAcknowledgement::Exhausted => {
                log::error!("cursor-position publication space exhausted");
                true
            }
        }
    }

    fn take_cursor_shape(
        &self,
        session_id: &SessionID,
        client_owner_id: &SessionID,
        id: &str,
        revision: u64,
        publication: u64,
        accepted: bool,
    ) -> bool {
        let mut handlers = self.session_handlers.write().unwrap();
        let Some(handler) = handlers
            .get_mut(session_id)
            .filter(|handler| handler.client_owner_id.as_ref() == Some(client_owner_id))
        else {
            return false;
        };
        let Some(acknowledged) = handler
            .cursor_shape
            .published
            .as_ref()
            .filter(|published| {
                published.value.state.identity() == (id, revision)
                    && published.publication == publication
            })
            .cloned()
        else {
            return false;
        };
        match &acknowledged.value.state {
            CursorShapeState::Available(shape) if accepted => {
                if !handler.known_cursor_shapes.insert(shape) {
                    log::warn!("cursor-shape knowledge cache refused a bounded entry");
                }
            }
            CursorShapeState::Available(shape) => {
                handler
                    .known_cursor_shapes
                    .remove(&shape.id, Some(shape.revision));
                handler.cursor_shape.require_data_for(&acknowledged);
            }
            CursorShapeState::Unavailable(unavailable_id) => {
                handler.known_cursor_shapes.remove(unavailable_id, None);
            }
        }
        match handler.cursor_shape.acknowledge(
            id,
            revision,
            publication,
            || self.next_cursor_shape_publication(),
        ) {
            CursorShapeAcknowledgement::Ignored => false,
            CursorShapeAcknowledgement::Drained => true,
            CursorShapeAcknowledgement::Promoted(mut next) => {
                next.value = next
                    .value
                    .bind_to_knowledge(&mut handler.known_cursor_shapes);
                if let Some(stream) = &handler.event_stream {
                    if !post_cursor_shape(stream, &next) {
                        handler.cursor_shape.delivery_failed();
                    }
                }
                true
            }
            CursorShapeAcknowledgement::Exhausted => {
                log::error!("cursor-shape publication space exhausted");
                true
            }
        }
    }

    fn offer_cursor_shape(&self, value: CursorShapeValue) {
        let mut current_cursor = self.current_cursor.write().unwrap();
        current_cursor.shape = Some(value.clone());
        for handler in self.session_handlers.write().unwrap().values_mut() {
            let value = value
                .clone()
                .bind_to_knowledge(&mut handler.known_cursor_shapes);
            let Some(stream) = handler.event_stream.as_ref() else {
                handler.cursor_shape.retain_current(value);
                continue;
            };
            match handler
                .cursor_shape
                .offer(value, || self.next_cursor_shape_publication())
            {
                CursorShapeOffer::Pending => {}
                CursorShapeOffer::Published(publication) => {
                    if !post_cursor_shape(stream, &publication) {
                        handler.cursor_shape.delivery_failed();
                    }
                }
                CursorShapeOffer::Exhausted => {
                    log::error!("cursor-shape publication space exhausted");
                    handler.cursor_shape.clear();
                }
            }
        }
        drop(current_cursor);
    }

    pub(crate) fn close_event_stream(&self, session_id: SessionID) {
        // to-do: Make sure the following logic is correct.
        // No need to remove the display handler, because it will be removed when the connection is closed.
        if let Some(session) = self.session_handlers.write().unwrap().get_mut(&session_id) {
            try_send_close_event(&session.event_stream);
        }
    }

    pub(crate) fn begin_screenshot_request(&self, session_id: &SessionID) -> bool {
        let mut handlers = self.session_handlers.write().unwrap();
        let Some(handler) = handlers.get_mut(session_id) else {
            return false;
        };
        handler.screenshot = None;
        true
    }

    pub(crate) fn take_screenshot(
        &self,
        session_id: &SessionID,
        request_id: &str,
    ) -> Option<bytes::Bytes> {
        let mut handlers = self.session_handlers.write().unwrap();
        let handler = handlers.get_mut(session_id)?;
        if handler
            .screenshot
            .as_ref()
            .map(|screenshot| screenshot.request_id.as_str())
            != Some(request_id)
        {
            return None;
        }
        handler.screenshot.take().map(|screenshot| screenshot.data)
    }

    fn make_displays_msg(displays: &Vec<DisplayInfo>) -> String {
        let mut msg_vec = Vec::new();
        for ref d in displays.iter() {
            let mut h: HashMap<&str, i32> = Default::default();
            h.insert("x", d.x);
            h.insert("y", d.y);
            h.insert("width", d.width);
            h.insert("height", d.height);
            h.insert("cursor_embedded", if d.cursor_embedded { 1 } else { 0 });
            if let Some(original_resolution) = d.original_resolution.as_ref() {
                h.insert("original_width", original_resolution.width);
                h.insert("original_height", original_resolution.height);
            }
            // Don't convert scale (x 100) to i32 directly.
            // (d.scale * 100.0f64) as i32 may produces inaccuracies.
            //
            // Example: GNOME Wayland with Fractional Scaling enabled:
            // - Physical resolution: 2560x1600
            // - Logical resolution: 1074x1065
            // - Scale factor: 150%
            // Passing physical dimensions and scale factor prevents accurate logical resolution calculation
            // since 2560/1.5 = 1706.666... (rounded to 1706.67) and 1600/1.5 = 1066.666... (rounded to 1066.67)
            // h.insert("scale", (d.scale * 100.0f64) as i32);

            // Send scaled_width for accurate logical scale calculation.
            if d.scale > 0.0 {
                let scaled_width = (d.width as f64 / d.scale).round() as i32;
                h.insert("scaled_width", scaled_width);
            }
            msg_vec.push(h);
        }
        serde_json::ser::to_string(&msg_vec).unwrap_or("".to_owned())
    }

    pub fn update_use_texture_render(&self) {
        self.use_texture_render
            .store(crate::ui_interface::use_texture_render(), Ordering::Relaxed);
        self.display_rgbas.write().unwrap().clear();
    }

    fn next_rgba_publication(&self) -> Option<u64> {
        self.rgba_publication_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current
                    .checked_add(1)
                    .filter(|next| *next <= i64::MAX as u64)
            })
            .ok()
            .and_then(|previous| previous.checked_add(1))
    }

    fn offer_rgba_to_sessions(
        &self,
        session_ids: &[SessionID],
        display: usize,
        incoming: &mut Vec<u8>,
    ) -> Vec<(SessionID, u64)> {
        let Some((last, preceding)) = session_ids.split_last() else {
            return Vec::new();
        };
        let mut mailboxes = self.display_rgbas.write().unwrap();
        let mut notify = Vec::new();
        for session_id in preceding {
            if let Some(publication) = mailboxes
                .entry((*session_id, display))
                .or_default()
                .offer_copy(incoming, || self.next_rgba_publication())
            {
                notify.push((*session_id, publication));
            }
        }
        if let Some(publication) = mailboxes
            .entry((*last, display))
            .or_default()
            .offer_swap(incoming, || self.next_rgba_publication())
        {
            notify.push((*last, publication));
        }
        notify
    }

    fn copy_rgba(
        &self,
        session_id: &SessionID,
        display: usize,
        publication: u64,
    ) -> Option<Vec<u8>> {
        self.display_rgbas
            .read()
            .unwrap()
            .get(&(*session_id, display))
            .and_then(|rgba| rgba.copy(publication))
    }

    fn next_rgba(&self, session_id: &SessionID, display: usize, publication: u64) {
        let acknowledgement = {
            let mut mailboxes = self.display_rgbas.write().unwrap();
            let Some(mailbox) = mailboxes.get_mut(&(*session_id, display)) else {
                return;
            };
            let result = mailbox.acknowledge(publication, || self.next_rgba_publication());
            if result == RgbaAcknowledgement::Exhausted {
                mailboxes.remove(&(*session_id, display));
            }
            result
        };
        let RgbaAcknowledgement::Promoted(next_publication) = acknowledgement else {
            return;
        };
        let stream = self
            .session_handlers
            .read()
            .unwrap()
            .get(session_id)
            .and_then(|handler| handler.event_stream.as_ref())
            .map_or(false, |stream| {
                stream.add(EventToUI::Rgba(display, next_publication))
            });
        if !stream {
            self.display_rgbas
                .write()
                .unwrap()
                .remove(&(*session_id, display));
        }
    }

    fn ready_rgba_publications(&self, session_id: &SessionID) -> Vec<(usize, u64)> {
        self.display_rgbas
            .read()
            .unwrap()
            .iter()
            .filter_map(|((owner, display), rgba)| {
                (owner == session_id && rgba.valid).then_some((*display, rgba.publication))
            })
            .collect()
    }

    fn replay_ready_rgba(
        &self,
        session_id: &SessionID,
        client_owner_id: &SessionID,
    ) -> bool {
        let publications = self.ready_rgba_publications(session_id);
        if publications.is_empty() {
            return self
                .session_handlers
                .read()
                .unwrap()
                .get(session_id)
                .and_then(|handler| handler.client_owner_id.as_ref())
                == Some(client_owner_id);
        }
        let handlers = self.session_handlers.read().unwrap();
        let Some(stream) = handlers
            .get(session_id)
            .filter(|handler| handler.client_owner_id.as_ref() == Some(client_owner_id))
            .and_then(|handler| handler.event_stream.as_ref())
        else {
            return false;
        };
        publications
            .into_iter()
            .all(|(display, publication)| stream.add(EventToUI::Rgba(display, publication)))
    }

    fn rearm_rgba_for_presentation_recovery(
        &self,
        session_id: &SessionID,
        display: usize,
        event_stream: Option<&StreamSink<EventToUI>>,
    ) -> ResultType<()> {
        let rearm = {
            let mut mailboxes = self.display_rgbas.write().unwrap();
            let Some(mailbox) = mailboxes.get_mut(&(*session_id, display)) else {
                return Ok(());
            };
            let result = mailbox.rearm(|| self.next_rgba_publication());
            if result == RgbaRearm::Exhausted {
                mailboxes.remove(&(*session_id, display));
            }
            result
        };
        let RgbaRearm::Rearmed(publication) = rearm else {
            if rearm == RgbaRearm::Exhausted {
                bail!("software RGBA presentation publication is exhausted");
            }
            return Ok(());
        };
        let delivered = event_stream.map_or(false, |stream| {
            stream.add(EventToUI::Rgba(display, publication))
        });
        if delivered {
            return Ok(());
        }
        self.display_rgbas
            .write()
            .unwrap()
            .remove(&(*session_id, display));
        bail!("software RGBA presentation re-arm was rejected by its exact UI stream")
    }

    fn retire_rgba_session(&self, session_id: &SessionID) {
        self.display_rgbas
            .write()
            .unwrap()
            .retain(|(owner, _), _| owner != session_id);
    }

    fn retire_rgba_displays_except(&self, session_id: &SessionID, displays: &[i32]) {
        self.display_rgbas
            .write()
            .unwrap()
            .retain(|(owner, display), _| {
                owner != session_id
                    || displays
                        .iter()
                        .filter_map(|kept| usize::try_from(*kept).ok())
                        .any(|kept| kept == *display)
            });
    }
}

impl InvokeUiSession for FlutterHandler {
    fn set_cursor_data(&self, cd: CursorData) {
        let id = cd.id.to_string();
        let Some(colors) = remote_cursor_rgba_for_ui(&cd) else {
            self.cursor_shapes.write().unwrap().remove(&id, None);
            self.offer_cursor_shape(CursorShapeValue {
                state: CursorShapeState::Unavailable(id),
                include_data: false,
            });
            return;
        };
        let Some(revision) = self.next_cursor_shape_revision() else {
            log::error!("cursor-shape revision space exhausted");
            self.cursor_shapes.write().unwrap().clear();
            self.offer_cursor_shape(CursorShapeValue {
                state: CursorShapeState::Unavailable(id),
                include_data: false,
            });
            return;
        };
        let shape = Arc::new(RemoteCursorShape {
            id,
            revision,
            hotx: cd.hotx,
            hoty: cd.hoty,
            width: cd.width,
            height: cd.height,
            rgba: colors,
        });
        if !self.cursor_shapes.write().unwrap().insert(Arc::clone(&shape)) {
            log::warn!("cursor-shape cache refused a bounded entry");
            self.offer_cursor_shape(CursorShapeValue {
                state: CursorShapeState::Unavailable(shape.id.clone()),
                include_data: false,
            });
            return;
        }
        self.offer_cursor_shape(CursorShapeValue {
            state: CursorShapeState::Available(shape),
            include_data: true,
        });
    }

    fn set_cursor_id(&self, id: String) {
        let shape = self.cursor_shapes.write().unwrap().get(&id);
        self.offer_cursor_shape(CursorShapeValue {
            state: match shape {
                Some(shape) => CursorShapeState::Available(shape),
                None => CursorShapeState::Unavailable(id),
            },
            include_data: false,
        });
    }

    fn set_cursor_position(&self, cp: CursorPosition) {
        let position = CursorPositionValue { x: cp.x, y: cp.y };
        let mut current_cursor = self.current_cursor.write().unwrap();
        current_cursor.position = Some(position);
        for handler in self.session_handlers.write().unwrap().values_mut() {
            let Some(stream) = handler.event_stream.as_ref() else {
                handler.cursor_position.retain_current(position);
                continue;
            };
            match handler.cursor_position.offer(position, || {
                self.next_cursor_position_publication()
            }) {
                CursorPositionOffer::Pending => {}
                CursorPositionOffer::Published(publication) => {
                    if !post_cursor_position(stream, publication) {
                        handler.cursor_position.delivery_failed();
                    }
                }
                CursorPositionOffer::Exhausted => {
                    log::error!("cursor-position publication space exhausted");
                    handler.cursor_position.clear();
                }
            }
        }
        drop(current_cursor);
    }

    /// unused in flutter, use switch_display or set_peer_info
    fn set_display(&self, _x: i32, _y: i32, _w: i32, _h: i32, _cursor_embedded: bool, _scale: f64) {
    }

    fn update_privacy_mode(&self) {
        self.push_event::<&str>("update_privacy_mode", &[], &[]);
    }

    fn set_permission(&self, name: &str, value: bool) {
        self.push_event("permission", &[(name, &value.to_string())], &[]);
    }

    // unused in flutter
    fn close_success(&self) {}

    fn update_quality_status(&self, status: QualityStatus) {
        const NULL: String = String::new();
        self.push_event(
            "update_quality_status",
            &[
                ("speed", &status.speed.map_or(NULL, |it| it)),
                (
                    "fps",
                    &serde_json::ser::to_string(&status.fps).unwrap_or(NULL.to_owned()),
                ),
                ("delay", &status.delay.map_or(NULL, |it| it.to_string())),
                (
                    "target_bitrate",
                    &status.target_bitrate.map_or(NULL, |it| it.to_string()),
                ),
                (
                    "codec_format",
                    &status.codec_format.map_or(NULL, |it| it.to_string()),
                ),
                ("chroma", &status.chroma.map_or(NULL, |it| it.to_string())),
            ],
            &[],
        );
    }

    fn set_connection_type(&self, stream_type: &str) {
        // R-G3 (Tier-4): the peer's secure/direct wire flags are dropped — the channel is ALWAYS
        // PAKE-keyed + direct, so the viewer consumes only the stream-type badge suffix.
        self.push_event(
            "connection_ready",
            &[("stream_type", &stream_type.to_string())],
            &[],
        );
    }

    fn job_error(&self, id: i32, err: String, file_num: i32) {
        self.push_event(
            "job_error",
            &[
                ("id", &id.to_string()),
                ("err", &err),
                ("file_num", &file_num.to_string()),
            ],
            &[],
        );
    }

    fn job_done(&self, id: i32, file_num: i32) {
        self.push_event(
            "job_done",
            &[("id", &id.to_string()), ("file_num", &file_num.to_string())],
            &[],
        );
    }

    // unused in flutter
    fn clear_all_jobs(&self) {}

    fn load_last_job(&self, _cnt: i32, job_json: &str, _auto_start: bool) {
        self.push_event("load_last_job", &[("value", job_json)], &[]);
    }

    fn update_folder_files(
        &self,
        id: i32,
        entries: &Vec<FileEntry>,
        path: String,
        #[allow(unused_variables)] is_local: bool,
        only_count: bool,
    ) {
        // TODO opt
        if only_count {
            self.push_event(
                "update_folder_files",
                &[("info", &make_fd_flutter(id, entries, only_count))],
                &[],
            );
        } else {
            self.push_event(
                "file_dir",
                &[
                    ("is_local", "false"),
                    ("value", &crate::common::make_fd_to_json(id, path, entries)),
                ],
                &[],
            );
        }
    }

    fn update_empty_dirs(&self, res: ReadEmptyDirsResponse) {
        self.push_event(
            "empty_dirs",
            &[
                ("is_local", "false"),
                (
                    "value",
                    &crate::common::make_empty_dirs_response_to_json(&res),
                ),
            ],
            &[],
        );
    }

    // unused in flutter
    fn update_transfer_list(&self) {}

    // unused in flutter // TEST flutter
    fn confirm_delete_files(&self, _id: i32, _i: i32, _name: String) {}

    fn override_file_confirm(
        &self,
        id: i32,
        file_num: i32,
        to: String,
        is_upload: bool,
        is_identical: bool,
    ) {
        self.push_event(
            "override_file_confirm",
            &[
                ("id", &id.to_string()),
                ("file_num", &file_num.to_string()),
                ("read_path", &to),
                ("is_upload", &is_upload.to_string()),
                ("is_identical", &is_identical.to_string()),
            ],
            &[],
        );
    }

    fn job_progress(&self, id: i32, file_num: i32, speed: f64, finished_size: f64) {
        self.push_event(
            "job_progress",
            &[
                ("id", &id.to_string()),
                ("file_num", &file_num.to_string()),
                ("speed", &speed.to_string()),
                ("finished_size", &finished_size.to_string()),
            ],
            &[],
        );
    }

    // unused in flutter
    fn adapt_size(&self) {}

    #[inline]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn on_rgba(&self, display: usize, rgba: &mut scrap::ImageRgb) {
        let use_texture_render = self.use_texture_render.load(Ordering::Relaxed);
        self.on_rgba_flutter_texture_render(use_texture_render, display, rgba);
        if !use_texture_render {
            self.on_rgba_soft_render(display, rgba);
        }
    }

    #[inline]
    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn on_rgba(&self, display: usize, rgba: &mut scrap::ImageRgb) {
        self.on_rgba_soft_render(display, rgba);
    }

    fn bind_initial_display_owner(
        &self,
        current_display: i32,
        display_count: usize,
    ) -> ResultType<()> {
        bind_initial_display_owner(
            &mut self.session_handlers.write().unwrap(),
            current_display,
            display_count,
        )
    }

    fn set_peer_info(&self, pi: &PeerInfo) {
        let displays = Self::make_displays_msg(&pi.displays);
        let mut features: HashMap<&str, bool> = Default::default();
        for ref f in pi.features.iter() {
            features.insert("privacy_mode", f.privacy_mode);
        }
        // compatible with 1.1.9
        if get_version_number(&pi.version) < get_version_number("1.2.0") {
            features.insert("privacy_mode", false);
        }
        let features = serde_json::ser::to_string(&features).unwrap_or("".to_owned());
        let resolutions = serialize_resolutions(&pi.resolutions.resolutions);
        *self.peer_info.write().unwrap() = pi.clone();
        self.push_event(
            "peer_info",
            &[
                ("username", &pi.username),
                ("hostname", &pi.hostname),
                ("platform", &pi.platform),
                ("sas_enabled", &pi.sas_enabled.to_string()),
                ("displays", &displays),
                ("version", &pi.version),
                ("features", &features),
                ("current_display", &pi.current_display.to_string()),
                ("resolutions", &resolutions),
                ("platform_additions", &pi.platform_additions),
            ],
            &[],
        );
    }

    fn set_displays(&self, displays: &Vec<DisplayInfo>) {
        self.peer_info.write().unwrap().displays = displays.clone();
        self.push_event(
            "sync_peer_info",
            &[("displays", &Self::make_displays_msg(displays))],
            &[],
        );
    }

    fn set_platform_additions(&self, data: &str) {
        self.push_event(
            "sync_platform_additions",
            &[("platform_additions", &data)],
            &[],
        )
    }

    fn set_multiple_windows_session(&self, sessions: Vec<WindowsSession>) {
        let mut msg_vec = Vec::new();
        let mut sessions = sessions;
        for d in sessions.drain(..) {
            let mut h: HashMap<&str, String> = Default::default();
            h.insert("sid", d.sid.to_string());
            h.insert("name", d.name);
            msg_vec.push(h);
        }
        self.push_event(
            "set_multiple_windows_session",
            &[(
                "windows_sessions",
                &serde_json::ser::to_string(&msg_vec).unwrap_or("".to_owned()),
            )],
            &[],
        );
    }

    fn is_multi_ui_session(&self) -> bool {
        self.session_handlers.read().unwrap().len() > 1
    }

    fn set_current_display(&self, disp_idx: i32) {
        if self.is_multi_ui_session() {
            return;
        }
        self.push_event(
            "follow_current_display",
            &[("display_idx", &disp_idx.to_string())],
            &[],
        );
    }

    fn on_connected(&self, _conn_type: ConnType) {}

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, link: &str, retry: bool) {
        let has_retry = if retry { "true" } else { "" };
        self.push_event(
            "msgbox",
            &[
                ("type", msgtype),
                ("title", title),
                ("text", text),
                ("link", link),
                ("hasRetry", has_retry),
            ],
            &[],
        );
    }

    fn cancel_msgbox(&self, tag: &str) {
        self.push_event("cancel_msgbox", &[("tag", tag)], &[]);
    }

    fn new_message(&self, msg: String) {
        self.push_event("chat_client_mode", &[("text", &msg)], &[]);
    }

    fn switch_display(&self, display: &SwitchDisplay) {
        let resolutions = serialize_resolutions(&display.resolutions.resolutions);
        self.push_event(
            "switch_display",
            &[
                ("display", &display.display.to_string()),
                ("x", &display.x.to_string()),
                ("y", &display.y.to_string()),
                ("width", &display.width.to_string()),
                ("height", &display.height.to_string()),
                (
                    "cursor_embedded",
                    &{
                        if display.cursor_embedded {
                            1
                        } else {
                            0
                        }
                    }
                    .to_string(),
                ),
                ("resolutions", &resolutions),
                (
                    "original_width",
                    &display.original_resolution.width.to_string(),
                ),
                (
                    "original_height",
                    &display.original_resolution.height.to_string(),
                ),
            ],
            &[],
        );
    }

    fn update_block_input_state(&self, on: bool) {
        self.push_event(
            "update_block_input_state",
            &[("input_state", if on { "on" } else { "off" })],
            &[],
        );
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn clipboard(&self, content: String) {
        self.push_event("clipboard", &[("content", &content)], &[]);
    }

    fn on_voice_call_started(&self) {
        self.push_event::<&str>("on_voice_call_started", &[], &[]);
    }

    fn on_voice_call_closed(&self, reason: &str) {
        let _res = self.push_event("on_voice_call_closed", &[("reason", reason)], &[]);
    }

    fn on_voice_call_waiting(&self) {
        self.push_event::<&str>("on_voice_call_waiting", &[], &[]);
    }

    fn on_voice_call_incoming(&self) {
        self.push_event::<&str>("on_voice_call_incoming", &[], &[]);
    }

    fn update_record_status(&self, start: bool) {
        self.push_event("record_status", &[("start", &start.to_string())], &[]);
    }

    fn handle_screenshot_resp(
        &self,
        sid: String,
        request_id: String,
        data: Option<bytes::Bytes>,
        msg: String,
    ) {
        match SessionID::from_str(&sid) {
            Ok(sid) => {
                {
                    let mut handlers = self.session_handlers.write().unwrap();
                    let Some(handler) = handlers.get_mut(&sid) else {
                        log::debug!("dropping screenshot response for retired UI session {sid}");
                        return;
                    };
                    handler.screenshot = data.map(|data| OwnedScreenshot {
                        request_id: request_id.clone(),
                        data,
                    });
                }
                self.push_event_to(
                    "screenshot",
                    &[("msg", json!(msg)), ("screenshot_id", json!(request_id))],
                    &[&sid],
                );
            }
            Err(e) => {
                // Unreachable!
                log::error!("Failed to parse sid \"{}\", {}", sid, e);
            }
        }
    }

    fn handle_terminal_response(&self, response: TerminalResponse) {
        use hbb_common::message_proto::terminal_response::Union;

        match response.union {
            Some(Union::Opened(opened)) => {
                let mut event_data: Vec<(&str, serde_json::Value)> = vec![
                    ("type", json!("opened")),
                    ("terminal_id", json!(opened.terminal_id)),
                    ("success", json!(opened.success)),
                    ("message", json!(&opened.message)),
                    ("pid", json!(opened.pid)),
                    ("service_id", json!(&opened.service_id)),
                    (
                        "replay_terminal_output",
                        json!(opened.replay_terminal_output),
                    ),
                ];
                if !opened.persistent_sessions.is_empty() {
                    event_data.push(("persistent_sessions", json!(opened.persistent_sessions)));
                }
                self.push_event_("terminal_response", &event_data, &[], &[]);
            }
            Some(Union::Data(data)) => {
                // Decompress data if needed
                let output_data = if data.compressed {
                    hbb_common::compress::decompress(&data.data)
                } else {
                    data.data.to_vec()
                };

                let encoded = crate::encode64(&output_data);
                let event_data: Vec<(&str, serde_json::Value)> = vec![
                    ("type", json!("data")),
                    ("terminal_id", json!(data.terminal_id)),
                    ("data", json!(&encoded)),
                ];
                self.push_event_("terminal_response", &event_data, &[], &[]);
            }
            Some(Union::Closed(closed)) => {
                let event_data: Vec<(&str, serde_json::Value)> = vec![
                    ("type", json!("closed")),
                    ("terminal_id", json!(closed.terminal_id)),
                    ("exit_code", json!(closed.exit_code)),
                ];
                self.push_event_("terminal_response", &event_data, &[], &[]);
            }
            Some(Union::Error(error)) => {
                let event_data: Vec<(&str, serde_json::Value)> = vec![
                    ("type", json!("error")),
                    ("terminal_id", json!(error.terminal_id)),
                    ("message", json!(&error.message)),
                ];
                self.push_event_("terminal_response", &event_data, &[], &[]);
            }
            None => {}
            Some(_) => {
                log::warn!("Unhandled terminal response type");
            }
        }
    }
}

impl FlutterHandler {
    #[inline]
    fn on_rgba_soft_render(&self, display: usize, rgba: &mut scrap::ImageRgb) {
        // Give a chance for plugins or etc to hook a rgba data.
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        for (key, hook) in self.hooks.read().unwrap().iter() {
            match hook {
                SessionHook::OnSessionRgba(cb) => {
                    cb(key.to_owned(), rgba);
                }
            }
        }
        let handlers = self.session_handlers.read().unwrap();
        let session_ids = handlers
            .iter()
            .filter_map(|(session_id, handler)| {
                // The soft renderer does not support multi-displays session for now.
                if handler.displays.len() > 1 {
                    return None;
                }
                // A decoded frame is presentation-authorized only for an exact handler that owns
                // this display, regardless of handler count or peer version.
                if !handler.displays.contains(&display) {
                    return None;
                }
                handler.event_stream.as_ref().map(|_| *session_id)
            })
            .collect::<Vec<_>>();
        let notifications = self.offer_rgba_to_sessions(&session_ids, display, &mut rgba.raw);
        if notifications.is_empty() {
            return;
        }

        let mut failed = Vec::new();
        for (session_id, publication) in notifications {
            let Some(stream) = handlers
                .get(&session_id)
                .and_then(|handler| handler.event_stream.as_ref())
            else {
                failed.push(session_id);
                continue;
            };
            if !stream.add(EventToUI::Rgba(display, publication)) {
                failed.push(session_id);
            }
        }
        drop(handlers);
        if !failed.is_empty() {
            let mut mailboxes = self.display_rgbas.write().unwrap();
            for session_id in failed {
                mailboxes.remove(&(session_id, display));
            }
        }
    }

    #[inline]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn on_rgba_flutter_texture_render(
        &self,
        use_texture_render: bool,
        display: usize,
        rgba: &mut scrap::ImageRgb,
    ) {
        for (_, session) in self.session_handlers.read().unwrap().iter() {
            if !session.displays.contains(&display) {
                continue;
            }
            if use_texture_render || session.displays.len() > 1 {
                let Some(stream) = &session.event_stream else {
                    continue;
                };
                session
                    .renderer
                    .on_rgba(display, rgba, || stream.add(EventToUI::Texture(display)));
            }
        }
    }
}

// This function is only used for the default connection session.
pub fn session_add_existed(
    peer_id: String,
    session_id: SessionID,
    client_owner_id: SessionID,
    displays: Vec<i32>,
    is_view_camera: bool,
) -> ResultType<()> {
    #[cfg(target_os = "android")]
    let owner_admission = acquire_android_client_owner(&client_owner_id)?;

    let conn_type = if is_view_camera {
        ConnType::VIEW_CAMERA
    } else {
        ConnType::DEFAULT_CONN
    };
    let result = sessions::replace_peer_session_display_owner(
        peer_id,
        conn_type,
        session_id,
        client_owner_id,
        displays,
    );
    #[cfg(target_os = "android")]
    drop(owner_admission);
    result
}

/// Create a new remote session with the given id.
///
/// # Arguments
///
/// * `id` - The identifier of the remote session with prefix. Regex: [\w]*[\_]*[\d]+
/// * `is_file_transfer` - If the session is used for file transfer.
/// * `is_view_camera` - If the session is used for view camera.
/// * `is_port_forward` - If the session is used for port forward.
pub fn session_add(
    session_id: &SessionID,
    client_owner_id: &SessionID,
    id: &str,
    is_file_transfer: bool,
    is_view_camera: bool,
    is_port_forward: bool,
    is_rdp: bool,
    is_terminal: bool,
    password: String,
    is_shared_password: bool,
    conn_token: Option<String>,
) -> ResultType<FlutterSession> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    if is_port_forward || is_rdp {
        bail!("Port forwarding is unavailable on mobile");
    }

    let conn_type = if is_file_transfer {
        ConnType::FILE_TRANSFER
    } else if is_view_camera {
        ConnType::VIEW_CAMERA
    } else if is_terminal {
        ConnType::TERMINAL
    } else if is_port_forward {
        if is_rdp {
            ConnType::RDP
        } else {
            ConnType::PORT_FORWARD
        }
    } else {
        ConnType::DEFAULT_CONN
    };

    // Mobile has one isolate-wide owner UUID but every outgoing connection has its own UUID.
    // Android's foreground service deliberately keeps the Rust process alive when the Flutter
    // Activity/task goes away, and Flutter does not await State.dispose(). Retire every prior
    // mobile connection before insertion. A late close still carries the retired connection UUID
    // and therefore cannot select the replacement connection.
    #[cfg(target_os = "android")]
    let previous_mobile_client_sessions =
        take_previous_android_mobile_client_sessions(client_owner_id, session_id)?;
    #[cfg(target_os = "ios")]
    let previous_mobile_client_sessions =
        sessions::take_mobile_sessions_except(client_owner_id, session_id);
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let (peer_count, ui_count) = close_client_owner_drain(previous_mobile_client_sessions);
        if peer_count != 0 {
            log::warn!(
                "Closed {peer_count} prior mobile client peer session(s) ({ui_count} UI handler(s)) before starting a replacement connection"
            );
        }
    }

    // Android may change Activity authority while the off-component preparation above waits for
    // exact predecessor finality. Reacquire and revalidate only after that wait, then keep the
    // read guard through insertion so a lifecycle transition cannot cross the new live session.
    #[cfg(target_os = "android")]
    let owner_admission = acquire_android_client_owner(client_owner_id)?;

    // to-do: check the same id session.
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        if session.lc.read().unwrap().conn_type != conn_type {
            bail!("same session id is found with different conn type?");
        }
        // The same session is added before?
        bail!("same session id is found");
    }

    LocalConfig::set_remote_id(&id);

    let mut preset_password = password.clone();
    let shared_password = if is_shared_password {
        // To achieve a flexible password application order, we don't treat shared password as a preset password.
        preset_password = Default::default();
        Some(password)
    } else {
        None
    };

    let session: Session<FlutterHandler> = Session {
        password: preset_password,
        server_keyboard_enabled: Arc::new(RwLock::new(true)),
        server_file_transfer_enabled: Arc::new(RwLock::new(true)),
        server_clipboard_enabled: Arc::new(RwLock::new(true)),
        reconnect_count: Arc::new(AtomicUsize::new(0)),
        ..Default::default()
    };

    session
        .lc
        .write()
        .unwrap()
        .initialize(id.to_owned(), conn_type, shared_password, conn_token);

    let session = Arc::new(session.clone());
    sessions::insert_session(
        session_id.to_owned(),
        *client_owner_id,
        conn_type,
        session.clone(),
    );

    #[cfg(target_os = "android")]
    drop(owner_admission);
    Ok(session)
}

fn admit_session_start(
    is_video_session: bool,
    has_ui_stream: bool,
    is_first_ui_session: bool,
    is_unselected_ui_session: bool,
    is_awaiting_initial_display: bool,
) -> ResultType<bool> {
    let starts_peer_connection = !has_ui_stream
        && is_first_ui_session
        && is_unselected_ui_session
        && !is_awaiting_initial_display;
    if is_video_session
        && is_unselected_ui_session
        && !starts_peer_connection
        && !is_awaiting_initial_display
    {
        bail!("Outgoing video UI session has no explicit display owner");
    }
    Ok(starts_peer_connection)
}

/// start a session with the given id.
///
/// # Arguments
///
/// * `id` - The identifier of the remote session with prefix. Regex: [\w]*[\_]*[\d]+
/// * `events2ui` - The events channel to ui.
pub fn session_start_(
    session_id: &SessionID,
    client_owner_id: &SessionID,
    id: &str,
    event_stream: StreamSink<EventToUI>,
) -> ResultType<()> {
    #[cfg(target_os = "android")]
    let owner_admission = acquire_android_client_owner(client_owner_id)?;

    if !sessions::session_has_client_owner(session_id, client_owner_id) {
        bail!("Outgoing session is not owned by the active mobile/desktop client owner");
    }

    let mut is_found = false;
    let mut start_failure = None;
    for s in sessions::get_sessions() {
        // This unlocked association probe is only a routing optimization. The exact owner is
        // rechecked after taking the worker slot and handler-owner guard below.
        if !s
            .session_handlers
            .read()
            .unwrap()
            .contains_key(session_id)
        {
            continue;
        }
        let is_video_session =
            !s.is_file_transfer() && !s.is_port_forward() && !s.is_terminal();
        // Reconnect/final teardown also owns this slot while it joins the old worker. Take it
        // before the handler map so that worker event delivery can never invert these locks.
        let mut thread_lock = s.thread.lock().unwrap();
        let mut handlers = s.session_handlers.write().unwrap();
        let is_first_ui_session = handlers.len() == 1;
        if let Some(h) = handlers.get_mut(session_id) {
            if h.client_owner_id.as_ref() != Some(client_owner_id) {
                bail!("Outgoing session is not owned by the active mobile/desktop client owner");
            }
            let starts_peer_connection = match admit_session_start(
                is_video_session,
                h.event_stream.is_some(),
                is_first_ui_session,
                h.displays.is_empty(),
                h.awaiting_initial_display,
            ) {
                Ok(starts_peer_connection) => starts_peer_connection,
                Err(error) => {
                    start_failure = Some(error);
                    is_found = true;
                    break;
                }
            };
            try_send_close_event(&h.event_stream);
            h.event_stream = Some(event_stream);
            h.known_cursor_shapes.clear();
            match h
                .cursor_shape
                .rearm(|| s.ui_handler.next_cursor_shape_publication())
            {
                CursorShapeRearm::Idle => {}
                CursorShapeRearm::Rearmed(publication) => {
                    let delivered = h
                        .event_stream
                        .as_ref()
                        .is_some_and(|stream| post_cursor_shape(stream, &publication));
                    if !delivered {
                        h.cursor_shape.delivery_failed();
                        start_failure = Some(anyhow!(
                            "Outgoing session event stream rejected current cursor shape"
                        ));
                    }
                }
                CursorShapeRearm::Exhausted => {
                    start_failure = Some(anyhow!(
                        "Outgoing session cursor-shape publication is exhausted"
                    ));
                }
            }
            if start_failure.is_none() {
                match h.cursor_position.rearm(|| {
                    s.ui_handler.next_cursor_position_publication()
                }) {
                    CursorPositionRearm::Idle => {}
                    CursorPositionRearm::Rearmed(publication) => {
                        let delivered = h
                            .event_stream
                            .as_ref()
                            .is_some_and(|stream| post_cursor_position(stream, publication));
                        if !delivered {
                            h.cursor_position.delivery_failed();
                            start_failure = Some(anyhow!(
                                "Outgoing session event stream rejected current cursor position"
                            ));
                        }
                    }
                    CursorPositionRearm::Exhausted => {
                        start_failure = Some(anyhow!(
                            "Outgoing session cursor-position publication is exhausted"
                        ));
                    }
                }
            }
            if start_failure.is_none() && starts_peer_connection && is_video_session {
                h.awaiting_initial_display = true;
            }
            if start_failure.is_none() && starts_peer_connection {
                log::info!(
                    "Session {} start, use texture render: {}",
                    id,
                    s.use_texture_render.load(Ordering::Relaxed)
                );
                match s.start_io_thread_with_lock(&mut thread_lock) {
                    Ok(true) => {}
                    Ok(false) => {
                        start_failure = Some(anyhow!(
                            "Outgoing viewer session is already active or has retired"
                        ));
                    }
                    Err(error) => start_failure = Some(error.into()),
                }
            }
            is_found = true;
            break;
        }
    }
    if !is_found {
        bail!(
            "No session with peer id {}, session id: {}",
            id,
            session_id.to_string()
        );
    }
    if let Some(error) = start_failure {
        rollback_failed_session_start(session_id, client_owner_id);
        return Err(error);
    }

    if let Some(session) = sessions::get_session_by_session_id(session_id) {
        if !session
            .ui_handler
            .replay_ready_rgba(session_id, client_owner_id)
        {
            rollback_failed_session_start(session_id, client_owner_id);
            bail!("Outgoing session event stream rejected pending video");
        }
        #[cfg(target_os = "android")]
        drop(owner_admission);
        Ok(())
    } else {
        bail!("No session with peer id {}", id)
    }
}

fn rollback_failed_session_start(session_id: &SessionID, client_owner_id: &SessionID) {
    if let Some(session) =
        sessions::remove_failed_start_by_exact_ui_owner(session_id, client_owner_id)
    {
        session.close_and_join();
    }
}

#[inline]
fn try_send_close_event(event_stream: &Option<StreamSink<EventToUI>>) {
    if let Some(stream) = &event_stream {
        stream.add(EventToUI::Event("close".to_owned()));
    }
}

#[cfg(not(target_os = "ios"))]
pub fn update_text_clipboard_required() {
    let is_required = sessions::get_sessions()
        .iter()
        .any(|s| s.is_text_clipboard_required());
    #[cfg(target_os = "android")]
    let _ = scrap::android::ffi::call_clipboard_manager_enable_client_clipboard(is_required);
    Client::set_is_text_clipboard_required(is_required);
}

#[cfg(feature = "unix-file-copy-paste")]
pub fn update_file_clipboard_required() {
    let is_required = sessions::get_sessions()
        .iter()
        .any(|s| s.is_file_clipboard_required());
    Client::set_is_file_clipboard_required(is_required);
}

#[cfg(not(target_os = "ios"))]
pub fn send_clipboard_msg(msg: Message, _is_file: bool) {
    for s in sessions::get_sessions() {
        #[cfg(feature = "unix-file-copy-paste")]
        if _is_file {
            if crate::is_support_file_copy_paste_num(s.lc.read().unwrap().version)
                && s.is_file_clipboard_required()
            {
                s.send(Data::Message(msg.clone()));
            }
            continue;
        }
        if s.is_text_clipboard_required() {
            // Check if the client supports multi clipboards
            if let Some(message::Union::MultiClipboards(multi_clipboards)) = &msg.union {
                let version = s.ui_handler.peer_info.read().unwrap().version.clone();
                let platform = s.ui_handler.peer_info.read().unwrap().platform.clone();
                if let Some(msg_out) = crate::clipboard::get_msg_if_not_support_multi_clip(
                    &version,
                    &platform,
                    multi_clipboards,
                ) {
                    s.send(Data::Message(msg_out));
                    continue;
                }
            }
            s.send(Data::Message(msg.clone()));
        }
    }
}

// Server Side
#[cfg(not(any(target_os = "ios")))]
pub mod connection_manager {
    use std::collections::HashMap;

    #[cfg(any(target_os = "android"))]
    use hbb_common::log;
    #[cfg(any(target_os = "android"))]
    use scrap::android::call_main_service_set_by_name_for_generation;
    use serde_json::json;

    use crate::ui_cm_interface::InvokeUiCM;

    use super::GLOBAL_EVENT_STREAM;

    #[derive(Clone)]
    struct FlutterHandler {
        #[cfg(target_os = "android")]
        service_generation: u64,
    }

    impl InvokeUiCM for FlutterHandler {
        //TODO port_forward
        fn add_connection(&self, client: &crate::ui_cm_interface::Client) {
            let client_json = serde_json::to_string(&client).unwrap_or("".into());
            // send to Android service, active notification no matter UI is shown or not.
            #[cfg(target_os = "android")]
            if let Err(e) = call_main_service_set_by_name_for_generation(
                self.service_generation,
                "add_connection",
                Some(&client_json),
                None,
            ) {
                log::debug!("call_main_service_set_by_name fail,{}", e);
            }
            // send to UI, refresh widget
            self.push_event("add_connection", &[("client", &client_json)]);
        }

        fn remove_connection(&self, id: i32, close: bool) {
            #[cfg(target_os = "android")]
            {
                let id = id.to_string();
                if let Err(e) = call_main_service_set_by_name_for_generation(
                    self.service_generation,
                    "remove_connection",
                    Some(&id),
                    None,
                ) {
                    log::debug!("call_main_service_set_by_name fail,{}", e);
                }
            }
            self.push_event(
                "on_client_remove",
                &[("id", &id.to_string()), ("close", &close.to_string())],
            );
        }

        fn new_message(&self, id: i32, text: String) {
            self.push_event(
                "chat_server_mode",
                &[("id", &id.to_string()), ("text", &text)],
            );
        }

        fn change_theme(&self, dark: String) {
            self.push_event("theme", &[("dark", &dark)]);
        }

        fn change_language(&self) {
            self.push_event::<&str>("language", &[]);
        }

        fn update_voice_call_state(&self, client: &crate::ui_cm_interface::Client) {
            let client_json = serde_json::to_string(&client).unwrap_or("".into());
            // send to Android service, active notification no matter UI is shown or not.
            #[cfg(target_os = "android")]
            if let Err(e) = call_main_service_set_by_name_for_generation(
                self.service_generation,
                "update_voice_call_state",
                Some(&client_json),
                None,
            ) {
                log::debug!("call_main_service_set_by_name fail,{}", e);
            }
            self.push_event("update_voice_call_state", &[("client", &client_json)]);
        }

        fn file_transfer_log(&self, action: &str, log: &str) {
            self.push_event("cm_file_transfer_log", &[(action, log)]);
        }
    }

    impl FlutterHandler {
        fn push_event<V>(&self, name: &str, event: &[(&str, V)])
        where
            V: Sized + serde::Serialize + Clone,
        {
            let mut h: HashMap<&str, serde_json::Value> =
                event.iter().map(|(k, v)| (*k, json!(*v))).collect();
            debug_assert!(h.get("name").is_none());
            h.insert("name", json!(name));

            if let Some(s) = GLOBAL_EVENT_STREAM.read().unwrap().get(super::APP_TYPE_CM) {
                s.add(serde_json::ser::to_string(&h).unwrap_or("".to_owned()));
            } else {
                println!(
                    "Push event {} failed. No {} event stream found.",
                    name,
                    super::APP_TYPE_CM
                );
            };
        }
    }

    #[inline]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn start_cm_no_ui() {
        crate::ui_cm_interface::set_exit_on_idle(true);
        start_listen_ipc(false);
    }

    #[inline]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn start_listen_ipc_thread() {
        start_listen_ipc(true);
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn start_listen_ipc(new_thread: bool) {
        use crate::ui_cm_interface::{start_ipc, ConnectionManager};

        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);

        let cm = ConnectionManager {
            ui_handler: FlutterHandler {
                #[cfg(target_os = "android")]
                service_generation: 0,
            },
        };
        if new_thread {
            std::thread::spawn(move || start_ipc(cm));
        } else {
            start_ipc(cm);
        }
    }

    #[inline]
    pub fn cm_init() {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        start_listen_ipc_thread();
    }

    #[cfg(target_os = "android")]
    use hbb_common::tokio::sync::mpsc::Receiver;

    #[cfg(target_os = "android")]
    pub fn start_channel(
        rx: Receiver<crate::ipc::Data>,
        terminal: hbb_common::tokio::sync::oneshot::Receiver<
            crate::ui_cm_interface::CmConnectionTerminal,
        >,
        tx: crate::ui_cm_interface::CmEgressSender,
        service_generation: u64,
    ) {
        use crate::ui_cm_interface::start_listen;
        let cm = crate::ui_cm_interface::ConnectionManager {
            ui_handler: FlutterHandler { service_generation },
        };
        std::thread::spawn(move || start_listen(cm, rx, terminal, tx));
    }
}

pub fn make_fd_flutter(id: i32, entries: &Vec<FileEntry>, only_count: bool) -> String {
    let mut m = serde_json::Map::new();
    m.insert("id".into(), json!(id));
    let mut a = vec![];
    let mut n: u64 = 0;
    for entry in entries {
        n += entry.size;
        if only_count {
            continue;
        }
        let mut e = serde_json::Map::new();
        e.insert("name".into(), json!(entry.name.to_owned()));
        let tmp = entry.entry_type.value();
        e.insert("type".into(), json!(if tmp == 0 { 1 } else { tmp }));
        e.insert("time".into(), json!(entry.modified_time as f64));
        e.insert("size".into(), json!(entry.size as f64));
        a.push(e);
    }
    if only_count {
        m.insert("num_entries".into(), json!(entries.len() as i32));
    } else {
        m.insert("entries".into(), json!(a));
    }
    m.insert("total_size".into(), json!(n as f64));
    serde_json::to_string(&m).unwrap_or("".into())
}

pub fn get_cur_session_id() -> SessionID {
    CUR_SESSION_ID.read().unwrap().clone()
}

pub fn get_cur_peer_id() -> String {
    sessions::get_peer_id_by_session_id(&get_cur_session_id(), ConnType::DEFAULT_CONN)
        .unwrap_or("".to_string())
}

pub fn set_cur_session_id(session_id: SessionID) {
    if get_cur_session_id() != session_id {
        *CUR_SESSION_ID.write().unwrap() = session_id;
    }
}

#[inline]
fn serialize_resolutions(resolutions: &Vec<Resolution>) -> String {
    #[derive(Debug, serde::Serialize)]
    struct ResolutionSerde {
        width: i32,
        height: i32,
    }

    let mut v = vec![];
    resolutions
        .iter()
        .map(|r| {
            v.push(ResolutionSerde {
                width: r.width,
                height: r.height,
            })
        })
        .count();
    serde_json::ser::to_string(&v).unwrap_or("".to_string())
}

pub fn session_copy_rgba(
    session_id: SessionID,
    display: usize,
    publication: u64,
) -> Option<Vec<u8>> {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        return session
            .ui_handler
            .copy_rgba(&session_id, display, publication);
    }
    None
}

pub fn session_next_rgba(session_id: SessionID, display: usize, publication: u64) {
    if let Some(s) = sessions::get_session_by_session_id(&session_id) {
        s.ui_handler.next_rgba(&session_id, display, publication);
    }
}

pub fn session_take_cursor_position(
    session_id: SessionID,
    client_owner_id: SessionID,
    x: i32,
    y: i32,
    publication: u64,
) -> bool {
    sessions::get_session_by_session_id(&session_id).is_some_and(|session| {
        session.ui_handler.take_cursor_position(
            &session_id,
            &client_owner_id,
            CursorPositionPublication {
                position: CursorPositionValue { x, y },
                publication,
            },
        )
    })
}

pub fn session_take_cursor_shape(
    session_id: SessionID,
    client_owner_id: SessionID,
    id: String,
    revision: u64,
    publication: u64,
    accepted: bool,
) -> bool {
    sessions::get_session_by_session_id(&session_id).is_some_and(|session| {
        session.ui_handler.take_cursor_shape(
            &session_id,
            &client_owner_id,
            &id,
            revision,
            publication,
            accepted,
        )
    })
}

#[inline]
pub fn session_set_size(
    session_id: SessionID,
    client_owner_id: SessionID,
    display: usize,
    width: usize,
    height: usize,
) -> ResultType<()> {
    for s in sessions::get_sessions() {
        if let Some(admitted) = s.ui_handler.set_exact_owned_display_size(
            &session_id,
            &client_owner_id,
            display,
            width,
            height,
        ) {
            if admitted {
                return Ok(());
            }
            bail!(
                "renderer size is not owned by this UI client or display for session {session_id}"
            );
        }
    }
    bail!("renderer-size session {session_id} is no longer active")
}

#[inline]
pub fn session_register_pixelbuffer_texture(
    session_id: SessionID,
    client_owner_id: SessionID,
    display: usize,
    ptr: usize,
) {
    for s in sessions::get_sessions() {
        if let Some(admitted) =
            s.ui_handler
                .register_pixelbuffer_texture(&session_id, &client_owner_id, display, ptr)
        {
            if !admitted {
                log::debug!(
                    "Ignoring pixelbuffer texture operation from a retired UI owner for session {session_id}"
                );
            }
            break;
        }
    }
}

#[inline]
pub fn push_session_event(session_id: &SessionID, name: &str, event: Vec<(&str, &str)>) {
    if let Some(s) = sessions::get_session_by_session_id(session_id) {
        s.push_event(name, &event, &[]);
    }
}

#[inline]
pub fn push_global_event(channel: &str, event: String) -> Option<bool> {
    Some(GLOBAL_EVENT_STREAM.read().unwrap().get(channel)?.add(event))
}

#[inline]
pub fn get_global_event_channels() -> Vec<String> {
    GLOBAL_EVENT_STREAM
        .read()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

pub fn start_global_event_stream(s: StreamSink<String>, app_type: String) -> ResultType<()> {
    let app_type_values = app_type.split(",").collect::<Vec<&str>>();
    let mut lock = GLOBAL_EVENT_STREAM.write().unwrap();
    if !lock.contains_key(app_type_values[0]) {
        lock.insert(app_type_values[0].to_string(), s);
    } else {
        if let Some(_) = lock.insert(app_type.clone(), s) {
            log::warn!(
                "Global event stream of type {} is started before, but now removed",
                app_type
            );
        }
    }
    Ok(())
}

pub fn stop_global_event_stream(app_type: String) {
    let _ = GLOBAL_EVENT_STREAM.write().unwrap().remove(&app_type);
}

#[inline]
fn session_send_touch_scale(
    session_id: SessionID,
    v: &serde_json::Value,
    alt: bool,
    ctrl: bool,
    shift: bool,
    command: bool,
) {
    match v.get("v").and_then(|s| s.as_i64()) {
        Some(scale) => {
            if let Some(session) = sessions::get_session_by_session_id(&session_id) {
                session.send_touch_scale(scale as _, alt, ctrl, shift, command);
            }
        }
        None => {}
    }
}

#[inline]
fn session_send_touch_pan(
    session_id: SessionID,
    v: &serde_json::Value,
    pan_event: &str,
    alt: bool,
    ctrl: bool,
    shift: bool,
    command: bool,
) {
    match v.get("v") {
        Some(v) => match (
            v.get("x").and_then(|x| x.as_i64()),
            v.get("y").and_then(|y| y.as_i64()),
        ) {
            (Some(x), Some(y)) => {
                if let Some(session) = sessions::get_session_by_session_id(&session_id) {
                    session
                        .send_touch_pan_event(pan_event, x as _, y as _, alt, ctrl, shift, command);
                }
            }
            _ => {}
        },
        _ => {}
    }
}

fn session_send_touch_event(
    session_id: SessionID,
    v: &serde_json::Value,
    alt: bool,
    ctrl: bool,
    shift: bool,
    command: bool,
) {
    match v.get("t").and_then(|t| t.as_str()) {
        Some("scale") => session_send_touch_scale(session_id, v, alt, ctrl, shift, command),
        Some(pan_event) => {
            session_send_touch_pan(session_id, v, pan_event, alt, ctrl, shift, command)
        }
        _ => {}
    }
}

pub fn session_send_pointer(session_id: SessionID, msg: String) {
    if let Ok(m) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&msg) {
        let alt = m.get("alt").is_some();
        let ctrl = m.get("ctrl").is_some();
        let shift = m.get("shift").is_some();
        let command = m.get("command").is_some();
        match (m.get("k"), m.get("v")) {
            (Some(k), Some(v)) => match k.as_str() {
                Some("touch") => session_send_touch_event(session_id, v, alt, ctrl, shift, command),
                _ => {}
            },
            _ => {}
        }
    }
}

#[inline]
pub fn session_on_waiting_for_image_dialog_show(session_id: SessionID) {
    for s in sessions::get_sessions() {
        if let Some(h) = s.session_handlers.write().unwrap().get_mut(&session_id) {
            h.on_waiting_for_image_dialog_show();
        }
    }
}

/// Hooks for session.
#[derive(Clone)]
pub enum SessionHook {
    OnSessionRgba(fn(String, &mut scrap::ImageRgb)),
}

#[inline]
pub fn get_cur_session() -> Option<FlutterSession> {
    sessions::get_session_by_session_id(&*CUR_SESSION_ID.read().unwrap())
}

#[inline]
pub fn try_sync_peer_option(
    session: &FlutterSession,
    cur_id: &SessionID,
    key: &str,
    _value: Option<serde_json::Value>,
) {
    let mut event = Vec::new();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if key == "view-only" {
        event = vec![
            ("k", json!(key.to_string())),
            ("v", json!(session.lc.read().unwrap().view_only.v)),
        ];
    }
    if ["keyboard_mode", "input_source"].contains(&key) {
        event = vec![("k", json!(key.to_string())), ("v", json!(""))];
    }
    if !event.is_empty() {
        session.push_event("sync_peer_option", &event, &[cur_id]);
    }
}

pub(super) fn session_update_virtual_display(session: &FlutterSession, index: i32, on: bool) {
    let virtual_display_key = "virtual-display";
    let displays = session.get_option(virtual_display_key.to_owned());
    if !on {
        if index == -1 {
            if !displays.is_empty() {
                session.set_option(virtual_display_key.to_owned(), "".to_owned());
            }
        } else {
            let mut vdisplays = displays.split(',').collect::<Vec<_>>();
            let len = vdisplays.len();
            if index == 0 {
                // 0 means we can't toggle the virtual display by index.
                vdisplays.remove(vdisplays.len() - 1);
            } else {
                if let Some(i) = vdisplays.iter().position(|&x| x == index.to_string()) {
                    vdisplays.remove(i);
                }
            }
            if vdisplays.len() != len {
                session.set_option(
                    virtual_display_key.to_owned(),
                    vdisplays.join(",").to_owned(),
                );
            }
        }
    } else {
        let mut vdisplays = displays
            .split(',')
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        let len = vdisplays.len();
        if index == 0 {
            vdisplays.push(index.to_string());
        } else {
            if !vdisplays.iter().any(|x| *x == index.to_string()) {
                vdisplays.push(index.to_string());
            }
        }
        if vdisplays.len() != len {
            session.set_option(
                virtual_display_key.to_owned(),
                vdisplays.join(",").to_owned(),
            );
        }
    }
}

// sessions mod is used to avoid the big lock of sessions' map.
pub mod sessions {

    use super::*;

    pub(super) struct ClientOwnerDrain {
        pub(super) sessions: Vec<FlutterSession>,
        pub(super) handlers: Vec<SessionHandler>,
    }

    lazy_static::lazy_static! {
        // peer -> peer session, peer session -> ui sessions
        static ref SESSIONS: RwLock<HashMap<(String, ConnType), FlutterSession>> = Default::default();
    }

    #[inline]
    pub fn get_session_count(peer_id: String, conn_type: ConnType) -> usize {
        SESSIONS
            .read()
            .unwrap()
            .get(&(peer_id, conn_type))
            .map(|s| s.ui_handler.session_handlers.read().unwrap().len())
            .unwrap_or(0)
    }

    #[inline]
    pub fn get_peer_id_by_session_id(id: &SessionID, conn_type: ConnType) -> Option<String> {
        SESSIONS
            .read()
            .unwrap()
            .iter()
            .find_map(|((peer_id, t), s)| {
                if *t == conn_type
                    && s.ui_handler
                        .session_handlers
                        .read()
                        .unwrap()
                        .contains_key(id)
                {
                    Some(peer_id.clone())
                } else {
                    None
                }
            })
    }

    #[inline]
    pub fn get_session_by_session_id(id: &SessionID) -> Option<FlutterSession> {
        SESSIONS
            .read()
            .unwrap()
            .values()
            .find(|s| {
                s.ui_handler
                    .session_handlers
                    .read()
                    .unwrap()
                    .contains_key(id)
            })
            .cloned()
    }

    #[inline]
    pub fn get_session_by_peer_id(peer_id: String, conn_type: ConnType) -> Option<FlutterSession> {
        SESSIONS.read().unwrap().get(&(peer_id, conn_type)).cloned()
    }

    #[inline]
    pub fn remove_session_by_session_id(id: &SessionID) -> Option<FlutterSession> {
        let mut remove_peer_key = None;
        for (peer_key, s) in SESSIONS.write().unwrap().iter_mut() {
            let mut write_lock = s.ui_handler.session_handlers.write().unwrap();
            let remove_ret = write_lock.remove(id);
            match remove_ret {
                Some(_) => {
                    s.ui_handler.retire_rgba_session(id);
                    if write_lock.is_empty() {
                        remove_peer_key = Some(peer_key.clone());
                    } else {
                        check_remove_unused_displays(None, s, &write_lock);
                    }
                    break;
                }
                None => {}
            }
        }
        let s = SESSIONS.write().unwrap().remove(&remove_peer_key?);
        s
    }

    pub(super) fn remove_failed_start_by_exact_ui_owner(
        id: &SessionID,
        client_owner_id: &SessionID,
    ) -> Option<FlutterSession> {
        let mut remove_peer_key = None;
        for (peer_key, session) in SESSIONS.write().unwrap().iter_mut() {
            let mut handlers = session.ui_handler.session_handlers.write().unwrap();
            let Some(handler) = handlers.get(id) else {
                continue;
            };
            if handler.client_owner_id.as_ref() != Some(client_owner_id) {
                return None;
            }
            if handlers.remove(id).is_none() {
                return None;
            }
            session.ui_handler.retire_rgba_session(id);
            if handlers.is_empty() {
                remove_peer_key = Some(peer_key.clone());
            } else {
                check_remove_unused_displays(None, session, &handlers);
            }
            break;
        }
        SESSIONS.write().unwrap().remove(&remove_peer_key?)
    }

    /// Check if removing a session by session_id would result in removing the entire peer.
    ///
    /// Returns:
    /// - `true`: The session exists and removing it would leave the peer with no other sessions,
    ///           so the entire peer would be removed (equivalent to `remove_session_by_session_id` returning `Some`)
    /// - `false`: The session doesn't exist, or it exists but the peer has other sessions,
    ///            so the peer would not be removed (equivalent to `remove_session_by_session_id` returning `None`)
    #[inline]
    pub fn would_remove_peer_by_session_id(id: &SessionID) -> bool {
        for (_peer_key, s) in SESSIONS.read().unwrap().iter() {
            let read_lock = s.ui_handler.session_handlers.read().unwrap();
            if read_lock.contains_key(id) {
                // Found the session, check if it's the only one for this peer
                return read_lock.len() == 1;
            }
        }
        // Session not found
        false
    }

    pub(super) fn remaining_displays(
        excluded: Option<&SessionID>,
        handlers: &HashMap<SessionID, SessionHandler>,
    ) -> ResultType<Vec<i32>> {
        let mut remains_displays = HashSet::new();
        for (k, h) in handlers.iter() {
            if excluded == Some(k) {
                continue;
            }
            remains_displays.extend(h.displays.iter().copied());
        }
        let mut remains_displays = remains_displays
            .into_iter()
            .map(|display| {
                i32::try_from(display)
                    .map_err(|_| anyhow!("viewer display index does not fit the peer protocol"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        remains_displays.sort_unstable();
        Ok(remains_displays)
    }

    fn check_remove_unused_displays(
        excluded_session_id: Option<&SessionID>,
        session: &FlutterSession,
        handlers: &HashMap<SessionID, SessionHandler>,
    ) {
        // Set capture displays if some are not used any more.
        let remains_displays = match remaining_displays(excluded_session_id, handlers) {
            Ok(displays) => displays,
            Err(err) => {
                log::error!("failed to derive the remaining display capture set: {err}");
                return;
            }
        };
        if !remains_displays.is_empty() {
            if let Err(error) = session.try_capture_displays(remains_displays) {
                log::error!("failed to admit the remaining display capture set: {error}");
            }
        }
    }

    fn validate_display_selection(
        session: &FlutterSession,
        value: &[i32],
    ) -> ResultType<Vec<usize>> {
        if value.is_empty() {
            bail!("viewer display selection is empty");
        }
        let peer_info = session.ui_handler.peer_info.read().unwrap();
        let display_count = peer_info.displays.len();
        if value.len() > display_count {
            bail!(
                "viewer display selection has {} entries for an inventory of {display_count}",
                value.len()
            );
        }
        let mut seen = HashSet::with_capacity(value.len());
        value
            .iter()
            .map(|display| {
                let display = usize::try_from(*display)
                    .map_err(|_| anyhow!("viewer display selection is negative"))?;
                if display >= display_count {
                    bail!(
                        "viewer display selection {display} is outside the peer inventory of {display_count}"
                    );
                }
                if !seen.insert(display) {
                    bail!("viewer display selection repeats display {display}");
                }
                Ok(display)
            })
            .collect()
    }

    pub(super) fn ordered_display_selection_refresh(
        session: &FlutterSession,
        displays: &[usize],
    ) -> DisplaySelectionRefresh {
        if crate::common::is_support_multi_ui_session_num(session.lc.read().unwrap().version) {
            DisplaySelectionRefresh::Displays(displays.to_vec().into_boxed_slice())
        } else {
            DisplaySelectionRefresh::All
        }
    }

    pub fn session_switch_display(
        session_id: SessionID,
        client_owner_id: SessionID,
        value: Vec<i32>,
    ) -> ResultType<()> {
        for s in SESSIONS.read().unwrap().values() {
            let mut write_lock = s.ui_handler.session_handlers.write().unwrap();
            if let Some(handler) = write_lock.get(&session_id) {
                if handler.client_owner_id.as_ref() != Some(&client_owner_id) {
                    bail!("viewer display selection is not owned by this UI client");
                }
                let displays = validate_display_selection(s, &value)?;

                let switch_display = (value.len() == 1).then_some(value[0]);
                // Capture ownership follows the native session inventory on every
                // platform; a caller-supplied platform flag must not be able to drop
                // displays retained by another live UI owner.
                let mut capture_set = remaining_displays(Some(&session_id), &write_lock)?;
                capture_set.extend(value.iter().copied());
                capture_set.sort_unstable();
                capture_set.dedup();
                // When switching display, we also need to send "Refresh display" message.
                // On the controlled side:
                // 1. If this display is not currently captured -> Refresh -> Message "Refresh display" is not required.
                // One more key frame (first frame) will be sent because the refresh message.
                // 2. If this display is currently captured -> Not refresh -> Message "Refresh display" is required.
                // Without the message, the control side cannot see the latest display image.
                let refresh = ordered_display_selection_refresh(s, &displays);

                let handler = write_lock
                    .get_mut(&session_id)
                    .ok_or_else(|| anyhow!("viewer display selection owner disappeared"))?;
                // Reserve the exact command round first, commit local renderer
                // ownership while the command is still invisible, then publish it.
                s.try_select_displays(switch_display, capture_set, refresh, || {
                    handler.displays = displays;
                    s.ui_handler
                        .retire_rgba_displays_except(&session_id, &value);
                })?;
                return Ok(());
            }
        }
        bail!("viewer display selection session is no longer active")
    }

    #[inline]
    pub fn insert_session(
        session_id: SessionID,
        client_owner_id: SessionID,
        conn_type: ConnType,
        session: FlutterSession,
    ) {
        let mut sessions = SESSIONS.write().unwrap();
        let peer_session = sessions
            .entry((session.get_id(), conn_type))
            .or_insert(session);
        let current_cursor = peer_session.ui_handler.current_cursor.read().unwrap();
        let handler = FlutterHandler::session_handler_for_cursor_state(
            client_owner_id,
            &current_cursor,
        );
        peer_session
            .session_handlers
            .write()
            .unwrap()
            .insert(session_id, handler);
        drop(current_cursor);
    }

    #[inline]
    pub fn replace_peer_session_display_owner(
        peer_id: String,
        conn_type: ConnType,
        session_id: SessionID,
        client_owner_id: SessionID,
        displays: Vec<i32>,
    ) -> ResultType<()> {
        if let Some(s) = SESSIONS.read().unwrap().get(&(peer_id, conn_type)) {
            let validated_displays = validate_display_selection(s, &displays)?;
            let current_cursor = s.ui_handler.current_cursor.read().unwrap();
            let mut h = FlutterHandler::session_handler_for_cursor_state(
                client_owner_id,
                &current_cursor,
            );
            let mut handlers = s.ui_handler.session_handlers.write().unwrap();
            let mut capture_set = remaining_displays(Some(&session_id), &handlers)?;
            capture_set.extend(displays.iter().copied());
            capture_set.sort_unstable();
            capture_set.dedup();
            let refresh = ordered_display_selection_refresh(s, &validated_displays);
            h.displays = validated_displays;
            s.try_select_displays(None, capture_set, refresh, || {
                handlers.insert(session_id, h);
                s.ui_handler
                    .retire_rgba_displays_except(&session_id, &displays);
            })?;
            drop(handlers);
            drop(current_cursor);
            Ok(())
        } else {
            bail!("existing viewer peer session is no longer active")
        }
    }

    #[inline]
    pub fn get_sessions() -> Vec<FlutterSession> {
        SESSIONS.read().unwrap().values().cloned().collect()
    }

    #[inline]
    pub fn session_has_client_owner(session_id: &SessionID, client_owner_id: &SessionID) -> bool {
        SESSIONS.read().unwrap().values().any(|session| {
            session
                .session_handlers
                .read()
                .unwrap()
                .get(session_id)
                .and_then(|handler| handler.client_owner_id.as_ref())
                == Some(client_owner_id)
        })
    }

    pub fn request_video_refresh_for_exact_ui_owner(
        session_id: &SessionID,
        client_owner_id: &SessionID,
    ) -> ResultType<()> {
        let sessions = SESSIONS.read().unwrap();
        for session in sessions.values() {
            let handlers = session.ui_handler.session_handlers.read().unwrap();
            if let Some(handler) = handlers.get(session_id) {
                if handler.client_owner_id.as_ref() != Some(client_owner_id) {
                    bail!("viewer video refresh is not owned by this UI client");
                }
                // Keep the exact UI-owner read guard until nonblocking admission has
                // linearized. Concurrent replacement therefore wins wholly before or after
                // this request; a stale owner cannot select its successor.
                if handler.displays.is_empty() {
                    bail!("viewer video refresh has no exact UI-owner displays");
                }
                for display in &handler.displays {
                    session.ui_handler.rearm_rgba_for_presentation_recovery(
                        session_id,
                        *display,
                        handler.event_stream.as_ref(),
                    )?;
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    handler.renderer.notify_pending_frame(*display)?;
                }
                for display in &handler.displays {
                    let display = i32::try_from(*display)
                        .map_err(|_| anyhow!("viewer video refresh display is invalid"))?;
                    session.refresh_video(display)?;
                }
                return Ok(());
            }
        }
        bail!("viewer video refresh session is no longer active")
    }

    #[inline]
    pub(super) fn take_mobile_sessions_except(
        client_owner_id: &SessionID,
        session_id: &SessionID,
    ) -> ClientOwnerDrain {
        let mut sessions = SESSIONS.write().unwrap();
        let mut removed_keys = Vec::new();
        let mut removed_handlers = Vec::new();

        for (key, session) in sessions.iter() {
            let mut handlers = session.session_handlers.write().unwrap();
            let stale_handler_ids = handlers
                .iter()
                .filter_map(|(handler_session_id, handler)| {
                    (handler_session_id != session_id
                        || handler.client_owner_id.as_ref() != Some(client_owner_id))
                    .then_some(*handler_session_id)
                })
                .collect::<Vec<_>>();
            for stale_handler_id in stale_handler_ids {
                if let Some(handler) = handlers.remove(&stale_handler_id) {
                    session.ui_handler.retire_rgba_session(&stale_handler_id);
                    removed_handlers.push(handler);
                }
            }
            if handlers.is_empty() {
                removed_keys.push(key.clone());
            } else {
                check_remove_unused_displays(None, session, &handlers);
            }
        }

        let removed_sessions = removed_keys
            .into_iter()
            .filter_map(|key| sessions.remove(&key))
            .collect();
        ClientOwnerDrain {
            sessions: removed_sessions,
            handlers: removed_handlers,
        }
    }

    #[inline]
    pub(super) fn take_sessions_owned_by(client_owner_id: &SessionID) -> ClientOwnerDrain {
        let mut sessions = SESSIONS.write().unwrap();
        let mut removed_keys = Vec::new();
        let mut removed_handlers = Vec::new();

        for (key, session) in sessions.iter() {
            let mut handlers = session.session_handlers.write().unwrap();
            let owned_handler_ids = handlers
                .iter()
                .filter_map(|(session_id, handler)| {
                    (handler.client_owner_id.as_ref() == Some(client_owner_id))
                        .then_some(*session_id)
                })
                .collect::<Vec<_>>();
            for owned_handler_id in &owned_handler_ids {
                if let Some(handler) = handlers.remove(owned_handler_id) {
                    session.ui_handler.retire_rgba_session(owned_handler_id);
                    removed_handlers.push(handler);
                }
            }
            if owned_handler_ids.is_empty() {
                continue;
            }
            if handlers.is_empty() {
                removed_keys.push(key.clone());
            } else {
                check_remove_unused_displays(None, session, &handlers);
            }
        }

        let removed_sessions = removed_keys
            .into_iter()
            .filter_map(|key| sessions.remove(&key))
            .collect();
        ClientOwnerDrain {
            sessions: removed_sessions,
            handlers: removed_handlers,
        }
    }

    #[cfg(test)]
    pub(super) fn contains_peer(peer_id: &str, conn_type: ConnType) -> bool {
        SESSIONS
            .read()
            .unwrap()
            .contains_key(&(peer_id.to_owned(), conn_type))
    }

    #[cfg(test)]
    pub(super) fn insert_test_session(
        session_id: SessionID,
        peer_id: &str,
        conn_type: ConnType,
    ) -> FlutterSession {
        let session: FlutterSession = Arc::new(Session::default());
        session.session_handlers.write().unwrap().insert(
            session_id,
            SessionHandler {
                client_owner_id: Some(session_id),
                ..Default::default()
            },
        );
        SESSIONS
            .write()
            .unwrap()
            .insert((peer_id.to_owned(), conn_type), session.clone());
        session
    }

    #[cfg(test)]
    pub(super) fn insert_test_session_for_owner(
        session_id: SessionID,
        client_owner_id: SessionID,
        peer_id: &str,
        conn_type: ConnType,
    ) -> FlutterSession {
        let session: FlutterSession = Arc::new(Session::default());
        session.session_handlers.write().unwrap().insert(
            session_id,
            SessionHandler {
                client_owner_id: Some(client_owner_id),
                ..Default::default()
            },
        );
        SESSIONS
            .write()
            .unwrap()
            .insert((peer_id.to_owned(), conn_type), session.clone());
        session
    }

    #[cfg(test)]
    pub(super) fn clear_for_test() {
        for session in std::mem::take(&mut *SESSIONS.write().unwrap()).into_values() {
            session.close_and_join();
        }
    }
}

fn close_client_owner_drain(
    sessions::ClientOwnerDrain { sessions, handlers }: sessions::ClientOwnerDrain,
) -> (usize, usize) {
    let peer_count = sessions.len();
    let ui_count = handlers.len();

    for handler in handlers {
        try_send_close_event(&handler.event_stream);
    }
    for session in sessions {
        session.close_and_join();
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    if ui_count != 0 {
        crate::keyboard::release_remote_keys("map");
    }

    (peer_count, ui_count)
}

#[cfg(any(target_os = "android", test))]
const ANDROID_CLIENT_DRAIN_QUEUE_CAPACITY: usize = 1;

#[cfg(any(target_os = "android", test))]
#[derive(Default)]
struct AndroidClientDrainProgress {
    issued: u64,
    completed: u64,
}

#[cfg(any(target_os = "android", test))]
struct AndroidClientDrainRequest {
    ticket: u64,
    drain: sessions::ClientOwnerDrain,
}

#[cfg(any(target_os = "android", test))]
struct AndroidClientDrainCoordinator {
    sender: mpsc::SyncSender<AndroidClientDrainRequest>,
    progress: Arc<(Mutex<AndroidClientDrainProgress>, Condvar)>,
    _worker: std::thread::JoinHandle<()>,
}

#[cfg(any(target_os = "android", test))]
impl AndroidClientDrainCoordinator {
    fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(ANDROID_CLIENT_DRAIN_QUEUE_CAPACITY);
        let progress = Arc::new((
            Mutex::new(AndroidClientDrainProgress::default()),
            Condvar::new(),
        ));
        let worker_progress = Arc::clone(&progress);
        let worker = match std::thread::Builder::new()
            .name("rustdesk-android-client-drain".to_owned())
            .spawn(move || run_android_client_drain_worker(receiver, worker_progress))
        {
            Ok(worker) => worker,
            Err(error) => {
                log::error!("failed to create Android client drain worker: {error}");
                std::process::abort();
            }
        };
        Self {
            sender,
            progress,
            _worker: worker,
        }
    }

    fn lock_progress(&self) -> std::sync::MutexGuard<'_, AndroidClientDrainProgress> {
        match self.progress.0.lock() {
            Ok(progress) => progress,
            Err(_) => {
                log::error!("Android client drain progress lock was poisoned");
                std::process::abort();
            }
        }
    }

    fn latest_ticket(&self) -> u64 {
        self.lock_progress().issued
    }

    fn handoff(&self, drain: sessions::ClientOwnerDrain) -> ((usize, usize), u64) {
        let counts = (drain.sessions.len(), drain.handlers.len());
        if counts == (0, 0) {
            return (counts, self.latest_ticket());
        }

        let ticket = {
            let mut progress = self.lock_progress();
            let Some(ticket) = progress.issued.checked_add(1) else {
                log::error!("Android client drain ticket space exhausted");
                std::process::abort();
            };
            progress.issued = ticket;
            ticket
        };
        if self
            .sender
            .try_send(AndroidClientDrainRequest { ticket, drain })
            .is_err()
        {
            log::error!("Android client drain ownership handoff failed");
            std::process::abort();
        }
        (counts, ticket)
    }

    fn wait(&self, ticket: u64) -> ResultType<()> {
        let (progress_lock, completed) = &*self.progress;
        let mut progress = match progress_lock.lock() {
            Ok(progress) => progress,
            Err(_) => {
                log::error!("Android client drain progress lock was poisoned");
                std::process::abort();
            }
        };
        if ticket > progress.issued {
            bail!("Android client drain barrier is not owned by this process");
        }
        while progress.completed < ticket {
            progress = match completed.wait(progress) {
                Ok(progress) => progress,
                Err(_) => {
                    log::error!("Android client drain progress lock was poisoned");
                    std::process::abort();
                }
            };
        }
        Ok(())
    }
}

#[cfg(any(target_os = "android", test))]
fn run_android_client_drain_worker(
    receiver: mpsc::Receiver<AndroidClientDrainRequest>,
    progress: Arc<(Mutex<AndroidClientDrainProgress>, Condvar)>,
) -> ! {
    loop {
        let request = match receiver.recv() {
            Ok(request) => request,
            Err(_) => {
                log::error!("Android client drain worker lost its process-lifetime owner");
                std::process::abort();
            }
        };
        let ticket = request.ticket;
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            close_client_owner_drain(request.drain)
        }))
        .is_err()
        {
            log::error!("Android client drain worker panicked before exact finality");
            std::process::abort();
        }

        let (progress_lock, completed) = &*progress;
        let mut progress = match progress_lock.lock() {
            Ok(progress) => progress,
            Err(_) => {
                log::error!("Android client drain progress lock was poisoned");
                std::process::abort();
            }
        };
        if progress.completed.checked_add(1) != Some(ticket) || ticket > progress.issued {
            log::error!("Android client drain completion order was corrupted");
            std::process::abort();
        }
        progress.completed = ticket;
        completed.notify_all();
    }
}

#[cfg(any(target_os = "android", test))]
lazy_static::lazy_static! {
    static ref ANDROID_CLIENT_DRAIN_COORDINATOR: AndroidClientDrainCoordinator =
        AndroidClientDrainCoordinator::new();
}

#[cfg(any(target_os = "android", test))]
fn take_previous_android_mobile_client_sessions(
    client_owner_id: &SessionID,
    session_id: &SessionID,
) -> ResultType<sessions::ClientOwnerDrain> {
    let owner_admission = acquire_android_client_owner(client_owner_id)?;
    let drain = sessions::take_mobile_sessions_except(client_owner_id, session_id);
    drop(owner_admission);
    Ok(drain)
}

#[cfg(test)]
fn close_previous_mobile_client_sessions(
    client_owner_id: &SessionID,
    session_id: &SessionID,
) -> (usize, usize) {
    close_client_owner_drain(sessions::take_mobile_sessions_except(
        client_owner_id,
        session_id,
    ))
}

#[cfg(test)]
fn close_sessions_owned_by(client_owner_id: &SessionID) -> (usize, usize) {
    close_client_owner_drain(sessions::take_sessions_owned_by(client_owner_id))
}

#[cfg(any(target_os = "android", test))]
pub fn begin_android_client_owner() -> Option<u64> {
    let drain_coordinator = &*ANDROID_CLIENT_DRAIN_COORDINATOR;
    // Admission takes the owner and session-table locks in this order. Keep the owner write lock
    // through exact table removal and bounded handoff so no obsolete add/start can land after the
    // transition and no replacement can observe an unregistered predecessor drain.
    let mut owner = ANDROID_CLIENT_OWNER.write().unwrap();
    let (generation, previous_owner) = owner.begin(drain_coordinator.latest_ticket())?;
    if let Some(previous_owner) = previous_owner {
        let previous_drain = sessions::take_sessions_owned_by(&previous_owner);
        let ((peer_count, ui_count), drain_barrier) = drain_coordinator.handoff(previous_drain);
        owner.drain_barrier = drain_barrier;
        if peer_count != 0 || ui_count != 0 {
            log::info!(
                "Retired {peer_count} superseded Android client peer session(s) ({ui_count} UI handler(s)) into exact drain ticket {drain_barrier} before creating Activity owner generation {generation}"
            );
        }
    }
    drop(owner);
    Some(generation)
}

#[cfg(any(target_os = "android", test))]
pub fn bind_android_client_owner(generation: u64, session_id: SessionID) -> bool {
    ANDROID_CLIENT_OWNER
        .write()
        .unwrap()
        .bind(generation, session_id)
}

#[cfg(any(target_os = "android", test))]
pub fn resume_android_client_owner(generation: u64, session_id: SessionID) -> Option<u64> {
    // A stopped Activity can remain in Android's back stack while another MainActivity becomes the
    // owner. Resuming that obsolete Activity must not drain or replace the current isolate. Only the
    // already-current UUID may reconcile a JNI response that Kotlin did not record.
    ANDROID_CLIENT_OWNER
        .read()
        .unwrap()
        .resume(generation, session_id)
}

#[cfg(any(target_os = "android", test))]
fn acquire_android_client_owner(
    session_id: &SessionID,
) -> ResultType<std::sync::RwLockReadGuard<'static, AndroidClientOwnerState>> {
    let owner = ANDROID_CLIENT_OWNER.read().unwrap();
    if !owner.allows(session_id) {
        bail!("Android client session owner is no longer active");
    }
    Ok(owner)
}

#[cfg(any(target_os = "android", test))]
pub fn wait_for_android_client_owner_drain(session_id: &SessionID) -> ResultType<()> {
    let (generation, drain_barrier) = ANDROID_CLIENT_OWNER
        .read()
        .unwrap()
        .admission_barrier(session_id)
        .ok_or_else(|| anyhow!("Android client session owner is no longer active"))?;

    ANDROID_CLIENT_DRAIN_COORDINATOR.wait(drain_barrier)?;

    let owner = ANDROID_CLIENT_OWNER.read().unwrap();
    if owner.generation != generation
        || owner.admission_barrier(session_id) != Some((generation, drain_barrier))
    {
        bail!("Android client session owner changed while its predecessor drained");
    }
    Ok(())
}

#[cfg(any(target_os = "android", test))]
pub fn retire_android_client_owner(generation: u64, session_id: &SessionID) -> (usize, usize) {
    let drain_coordinator = &*ANDROID_CLIENT_DRAIN_COORDINATOR;
    let mut owner = ANDROID_CLIENT_OWNER.write().unwrap();
    if !owner.retire(generation, session_id) {
        return (0, 0);
    }
    let retired_drain = sessions::take_sessions_owned_by(session_id);
    let (retired, _) = drain_coordinator.handoff(retired_drain);
    drop(owner);
    retired
}

#[cfg(test)]
mod mobile_session_lifecycle_tests {
    use super::*;
    use crate::client::io_loop::{viewer_video_refresh_channel, ViewerVideoRefreshRequest};
    use std::sync::{atomic::AtomicBool, Arc};
    use std::time::Duration;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11go_display_selection_is_exact_owned_ordered_and_commit_after_admission() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let session_id = SessionID::new_v4();
        let current_owner = SessionID::new_v4();
        let stale_owner = SessionID::new_v4();
        let session = sessions::insert_test_session_for_owner(
            session_id,
            current_owner,
            "display-selection-host",
            ConnType::DEFAULT_CONN,
        );
        let mut peer_info = PeerInfo::new();
        peer_info.version = "1.4.7".to_owned();
        peer_info.displays = (0..3).map(|_| DisplayInfo::new()).collect();
        *session.ui_handler.peer_info.write().unwrap() = peer_info.clone();
        {
            let mut lc = session.lc.write().unwrap();
            lc.version = hbb_common::get_version_number("1.4.7");
            // Live topology belongs to FlutterHandler::peer_info. Keep the
            // login snapshot deliberately stale so the regression proves
            // display selection does not validate against it.
            lc.peer_info = Some(PeerInfo::new());
        }

        let mut old_frame = vec![1; 4];
        session
            .ui_handler
            .offer_rgba_to_sessions(&[session_id], 0, &mut old_frame);
        let mut selected_frame = vec![2; 4];
        session
            .ui_handler
            .offer_rgba_to_sessions(&[session_id], 1, &mut selected_frame);

        assert!(sessions::session_switch_display(session_id, stale_owner, vec![1]).is_err());
        assert!(sessions::session_switch_display(session_id, current_owner, vec![-1]).is_err());
        assert!(sessions::session_switch_display(session_id, current_owner, vec![1, 1],).is_err());
        assert!(sessions::session_switch_display(session_id, current_owner, vec![3]).is_err());
        assert!(sessions::session_switch_display(session_id, current_owner, vec![1]).is_err());
        {
            let handlers = session.ui_handler.session_handlers.read().unwrap();
            assert!(handlers.get(&session_id).unwrap().displays.is_empty());
        }
        {
            let mailboxes = session.ui_handler.display_rgbas.read().unwrap();
            assert!(mailboxes.contains_key(&(session_id, 0)));
            assert!(mailboxes.contains_key(&(session_id, 1)));
        }

        let (sender, mut receiver) = viewer_command_channel();
        *session.sender.write().unwrap() = Some(sender);
        sessions::session_switch_display(session_id, current_owner, vec![1])
            .expect("the exact current owner may admit one ordered display selection");

        let command = receiver
            .recv()
            .await
            .expect("the admitted display selection remains owned by its round")
            .expect("the viewer command round remains healthy");
        let Data::DisplaySelection(command) = command else {
            panic!("display selection must use its typed ordered command");
        };
        let (switch_display, capture_set, refresh) = command.into_parts();
        assert_eq!(switch_display.map(DisplaySelectionSwitch::display), Some(1));
        assert_eq!(&*capture_set, &[1]);
        assert!(matches!(
            refresh,
            Some(DisplaySelectionRefresh::Displays(displays)) if &*displays == [1]
        ));
        {
            let handlers = session.ui_handler.session_handlers.read().unwrap();
            assert_eq!(handlers.get(&session_id).unwrap().displays, vec![1]);
        }
        {
            let mailboxes = session.ui_handler.display_rgbas.read().unwrap();
            assert!(!mailboxes.contains_key(&(session_id, 0)));
            assert!(mailboxes.contains_key(&(session_id, 1)));
        }

        let second_session_id = SessionID::new_v4();
        let second_owner = SessionID::new_v4();
        let invalid_session_id = SessionID::new_v4();
        let replacement_owner = SessionID::new_v4();
        let admitted_sender = session
            .sender
            .write()
            .unwrap()
            .take()
            .expect("the test round sender is installed");
        assert!(session_add_existed(
            "display-selection-host".to_owned(),
            session_id,
            replacement_owner,
            vec![2],
            false,
        )
        .is_err());
        {
            let handlers = session.ui_handler.session_handlers.read().unwrap();
            let handler = handlers.get(&session_id).unwrap();
            assert_eq!(handler.client_owner_id, Some(current_owner));
            assert_eq!(handler.displays, vec![1]);
        }
        *session.sender.write().unwrap() = Some(admitted_sender);
        assert!(session_add_existed(
            "display-selection-host".to_owned(),
            invalid_session_id,
            second_owner,
            vec![-1],
            false,
        )
        .is_err());
        session_add_existed(
            "display-selection-host".to_owned(),
            second_session_id,
            second_owner,
            vec![2],
            false,
        )
        .expect("a valid second exact UI owner may admit its startup capture");
        assert!(sessions::session_switch_display(second_session_id, stale_owner, vec![2]).is_err());

        let command = receiver
            .recv()
            .await
            .expect("the ordered capture selection remains owned by its round")
            .expect("the viewer command round remains healthy");
        let Data::DisplaySelection(command) = command else {
            panic!("startup capture selection must use its typed ordered command");
        };
        let (switch_display, capture_set, refresh) = command.into_parts();
        assert!(switch_display.is_none());
        assert_eq!(&*capture_set, &[1, 2]);
        assert!(matches!(
            refresh,
            Some(DisplaySelectionRefresh::Displays(displays)) if &*displays == [2]
        ));
        {
            let handlers = session.ui_handler.session_handlers.read().unwrap();
            assert!(!handlers.contains_key(&invalid_session_id));
            assert_eq!(handlers.get(&second_session_id).unwrap().displays, vec![2]);
        }

        session.lc.write().unwrap().version = 0;
        assert_eq!(
            sessions::ordered_display_selection_refresh(&session, &[2]),
            DisplaySelectionRefresh::All
        );

        sessions::clear_for_test();
    }

    #[test]
    fn r_s11gt_initial_peer_info_binds_one_exact_display_owner_once() {
        let initial_session = SessionID::new_v4();
        let explicit_session = SessionID::new_v4();
        let mut handlers = HashMap::new();
        handlers.insert(
            initial_session,
            SessionHandler {
                awaiting_initial_display: true,
                ..Default::default()
            },
        );
        handlers.insert(
            explicit_session,
            SessionHandler {
                displays: vec![0],
                ..Default::default()
            },
        );
        let mut peer_info = PeerInfo::new();
        peer_info.displays = (0..3).map(|_| DisplayInfo::new()).collect();
        peer_info.current_display = 2;

        bind_initial_display_owner(
            &mut handlers,
            peer_info.current_display,
            peer_info.displays.len(),
        )
        .expect("the bounded initial display binds to the sole marked UI owner");
        assert_eq!(handlers.get(&initial_session).unwrap().displays, vec![2]);
        assert!(!handlers
            .get(&initial_session)
            .unwrap()
            .awaiting_initial_display);
        assert_eq!(handlers.get(&explicit_session).unwrap().displays, vec![0]);

        peer_info.current_display = 1;
        bind_initial_display_owner(
            &mut handlers,
            peer_info.current_display,
            peer_info.displays.len(),
        )
        .expect("a reconnect preserves every already-explicit native display owner");
        assert_eq!(handlers.get(&initial_session).unwrap().displays, vec![2]);
        assert_eq!(handlers.get(&explicit_session).unwrap().displays, vec![0]);
    }

    #[test]
    fn r_s11gt_initial_display_binding_refuses_ambiguous_or_invalid_authority() {
        let first = SessionID::new_v4();
        let second = SessionID::new_v4();
        let mut peer_info = PeerInfo::new();
        peer_info.displays = (0..2).map(|_| DisplayInfo::new()).collect();

        let mut ambiguous = HashMap::new();
        for session_id in [first, second] {
            ambiguous.insert(
                session_id,
                SessionHandler {
                    awaiting_initial_display: true,
                    ..Default::default()
                },
            );
        }
        assert!(bind_initial_display_owner(
            &mut ambiguous,
            peer_info.current_display,
            peer_info.displays.len(),
        )
        .is_err());
        assert!(ambiguous.values().all(|handler| handler.displays.is_empty()));

        let mut missing = HashMap::from([(first, SessionHandler::default())]);
        assert!(bind_initial_display_owner(
            &mut missing,
            peer_info.current_display,
            peer_info.displays.len(),
        )
        .is_err());
        assert!(missing.get(&first).unwrap().displays.is_empty());

        let mut stale_explicit = HashMap::from([(
            first,
            SessionHandler {
                displays: vec![2],
                ..Default::default()
            },
        )]);
        assert!(bind_initial_display_owner(
            &mut stale_explicit,
            peer_info.current_display,
            peer_info.displays.len(),
        )
        .is_err());
        assert_eq!(stale_explicit.get(&first).unwrap().displays, vec![2]);

        let mut unmarked_empty = HashMap::from([
            (
                first,
                SessionHandler {
                    awaiting_initial_display: true,
                    ..Default::default()
                },
            ),
            (second, SessionHandler::default()),
        ]);
        assert!(bind_initial_display_owner(
            &mut unmarked_empty,
            peer_info.current_display,
            peer_info.displays.len(),
        )
        .is_err());
        assert!(unmarked_empty
            .values()
            .all(|handler| handler.displays.is_empty()));

        let mut outside_inventory = HashMap::new();
        outside_inventory.insert(
            first,
            SessionHandler {
                awaiting_initial_display: true,
                ..Default::default()
            },
        );
        peer_info.current_display = 2;
        assert!(bind_initial_display_owner(
            &mut outside_inventory,
            peer_info.current_display,
            peer_info.displays.len(),
        )
        .is_err());
        assert!(outside_inventory.get(&first).unwrap().displays.is_empty());

        let mut negative = HashMap::new();
        negative.insert(
            first,
            SessionHandler {
                awaiting_initial_display: true,
                ..Default::default()
            },
        );
        assert!(
            bind_initial_display_owner(&mut negative, -1, peer_info.displays.len()).is_err()
        );
        assert!(negative.get(&first).unwrap().displays.is_empty());

        let mut conflicting = HashMap::new();
        conflicting.insert(
            first,
            SessionHandler {
                displays: vec![0],
                awaiting_initial_display: true,
                ..Default::default()
            },
        );
        peer_info.current_display = 0;
        assert!(bind_initial_display_owner(
            &mut conflicting,
            peer_info.current_display,
            peer_info.displays.len(),
        )
        .is_err());
        assert_eq!(conflicting.get(&first).unwrap().displays, vec![0]);
    }

    #[test]
    fn r_s11gt_reconnect_preserves_explicit_display_owners_without_rebinding() {
        let first = SessionID::new_v4();
        let second = SessionID::new_v4();
        let mut handlers = HashMap::from([
            (
                first,
                SessionHandler {
                    displays: vec![2],
                    ..Default::default()
                },
            ),
            (
                second,
                SessionHandler {
                    displays: vec![0, 1],
                    ..Default::default()
                },
            ),
        ]);

        bind_initial_display_owner(&mut handlers, 1, 3)
            .expect("a reconnect with complete explicit ownership is admissible");
        assert_eq!(handlers.get(&first).unwrap().displays, vec![2]);
        assert_eq!(handlers.get(&second).unwrap().displays, vec![0, 1]);
        assert!(handlers
            .values()
            .all(|handler| !handler.awaiting_initial_display));
    }

    #[test]
    fn r_s11gt_session_start_requires_fresh_or_explicit_display_authority() {
        assert!(admit_session_start(true, false, true, true, false)
            .expect("a first fresh video UI route starts the peer connection"));
        assert!(!admit_session_start(true, true, true, true, true)
            .expect("a marker-bearing pre-PeerInfo stream replacement may attach"));
        assert!(!admit_session_start(true, false, true, true, true)
            .expect("a marker-bearing streamless attachment cannot restart peer I/O"));
        assert!(!admit_session_start(true, false, false, true, true)
            .expect("a pending initial owner remains attachable beside an explicit owner"));
        assert!(!admit_session_start(true, false, false, false, false)
            .expect("an explicitly selected existing video UI route may attach"));
        assert!(admit_session_start(true, false, false, true, false).is_err());
        assert!(admit_session_start(true, true, true, true, false).is_err());
        assert!(!admit_session_start(false, false, false, true, false)
            .expect("a second nonvideo UI route does not require display ownership"));
    }

    #[test]
    fn r_s11gt_capture_authority_excludes_renderer_resource_keys() {
        let session_id = SessionID::new_v4();
        let mut handler = SessionHandler {
            displays: vec![1],
            ..Default::default()
        };
        assert!(!handler.set_owned_display_size(4, 640, 480));
        assert!(handler
            .renderer
            .map_display_sessions
            .read()
            .unwrap()
            .is_empty());
        handler.renderer.register_pixelbuffer_texture(4, 41);
        let handlers = HashMap::from([(session_id, handler)]);

        assert_eq!(
            sessions::remaining_displays(None, &handlers)
                .expect("the exact native handler display set is protocol-representable"),
            vec![1]
        );
    }

    #[test]
    fn r_s11gt_renderer_size_requires_exact_current_ui_owner() {
        let flutter = FlutterHandler::default();
        let session_id = SessionID::new_v4();
        let current_owner = SessionID::new_v4();
        let stale_owner = SessionID::new_v4();
        flutter.session_handlers.write().unwrap().insert(
            session_id,
            SessionHandler {
                client_owner_id: Some(current_owner),
                displays: vec![1],
                ..Default::default()
            },
        );

        assert_eq!(
            flutter.set_exact_owned_display_size(&session_id, &stale_owner, 1, 320, 240),
            Some(false)
        );
        assert_eq!(
            flutter.set_exact_owned_display_size(&session_id, &current_owner, 4, 320, 240),
            Some(false)
        );
        assert!(flutter
            .session_handlers
            .read()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .renderer
            .map_display_sessions
            .read()
            .unwrap()
            .is_empty());

        assert_eq!(
            flutter.set_exact_owned_display_size(&session_id, &current_owner, 1, 640, 480),
            Some(true)
        );
        assert_eq!(
            flutter.set_exact_owned_display_size(&session_id, &stale_owner, 1, 800, 600),
            Some(false)
        );
        let handlers = flutter.session_handlers.read().unwrap();
        let renderer = handlers
            .get(&session_id)
            .unwrap()
            .renderer
            .map_display_sessions
            .read()
            .unwrap();
        assert_eq!(renderer.get(&1).unwrap().size, (640, 480));
    }

    #[test]
    fn r_s11ff_r_s11gs_video_refresh_derives_the_current_exact_ui_owner_displays() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let session_id = SessionID::new_v4();
        let current_owner = SessionID::new_v4();
        let stale_owner = SessionID::new_v4();
        let session = sessions::insert_test_session_for_owner(
            session_id,
            current_owner,
            "refresh-host",
            ConnType::DEFAULT_CONN,
        );
        {
            let mut peer_info = PeerInfo::new();
            peer_info.displays = (0..5).map(|_| DisplayInfo::new()).collect();
            let mut lc = session.lc.write().unwrap();
            lc.version = hbb_common::get_version_number("1.4.7");
            lc.peer_info = Some(peer_info);
        }
        let (sender, receiver) = viewer_video_refresh_channel();
        *session.video_refresh_sender.write().unwrap() = Some(sender);

        assert!(sessions::request_video_refresh_for_exact_ui_owner(
            &session_id,
            &stale_owner,
        )
        .is_err());
        assert_eq!(receiver.try_recv(), None);

        assert!(sessions::request_video_refresh_for_exact_ui_owner(
            &session_id,
            &current_owner,
        )
        .is_err());
        assert_eq!(receiver.try_recv(), None);

        {
            let mut handlers = session.ui_handler.session_handlers.write().unwrap();
            handlers.get_mut(&session_id).unwrap().displays = vec![5];
        }
        assert!(sessions::request_video_refresh_for_exact_ui_owner(
            &session_id,
            &current_owner,
        )
        .is_err());
        assert_eq!(receiver.try_recv(), None);

        {
            let mut handlers = session.ui_handler.session_handlers.write().unwrap();
            handlers.get_mut(&session_id).unwrap().displays = vec![1, 4];
        }
        sessions::request_video_refresh_for_exact_ui_owner(&session_id, &current_owner)
            .expect("the current exact UI owner may admit a refresh");
        assert_eq!(
            receiver.try_recv(),
            Some(ViewerVideoRefreshRequest::Display(1))
        );
        assert_eq!(
            receiver.try_recv(),
            Some(ViewerVideoRefreshRequest::Display(4))
        );

        sessions::clear_for_test();
    }

    #[test]
    fn r_s11fc_texture_notification_commits_only_after_native_and_ui_admission() {
        let mut render_notified = false;
        let mut notification_attempts = 0;

        assert!(!commit_first_texture_notification(
            &mut render_notified,
            false,
            || {
                notification_attempts += 1;
                true
            },
        ));
        assert!(!render_notified);
        assert_eq!(notification_attempts, 0);

        assert!(!commit_first_texture_notification(
            &mut render_notified,
            true,
            || {
                notification_attempts += 1;
                false
            },
        ));
        assert!(!render_notified);
        assert_eq!(notification_attempts, 1);

        assert!(commit_first_texture_notification(
            &mut render_notified,
            true,
            || {
                notification_attempts += 1;
                true
            },
        ));
        assert!(render_notified);
        assert_eq!(notification_attempts, 2);

        assert!(!commit_first_texture_notification(
            &mut render_notified,
            true,
            || {
                notification_attempts += 1;
                true
            },
        ));
        assert_eq!(notification_attempts, 2);
    }

    #[test]
    fn r_s11gu_cursor_position_mailbox_retains_one_publication_and_only_the_latest_successor() {
        let first = CursorPositionValue { x: 10, y: 20 };
        let second = CursorPositionValue { x: 30, y: 40 };
        let latest = CursorPositionValue { x: 50, y: 60 };
        let mut mailbox = CursorPositionMailbox::default();

        let CursorPositionOffer::Published(first_publication) =
            mailbox.offer(first, || Some(1))
        else {
            panic!("first cursor position was not published");
        };
        assert_eq!(mailbox.offer(second, || Some(2)), CursorPositionOffer::Pending);
        assert_eq!(mailbox.offer(latest, || Some(3)), CursorPositionOffer::Pending);
        assert_eq!(mailbox.published, Some(first_publication));
        assert_eq!(mailbox.current, Some(latest));

        assert_eq!(
            mailbox.acknowledge(
                CursorPositionPublication {
                    position: second,
                    publication: 1,
                },
                || Some(2),
            ),
            CursorPositionAcknowledgement::Ignored
        );
        assert_eq!(
            mailbox.acknowledge(
                CursorPositionPublication {
                    position: first,
                    publication: first_publication.publication + 1,
                },
                || Some(2),
            ),
            CursorPositionAcknowledgement::Ignored
        );
        let CursorPositionAcknowledgement::Promoted(latest_publication) =
            mailbox.acknowledge(first_publication, || Some(2))
        else {
            panic!("latest cursor position was not promoted");
        };
        assert_eq!(latest_publication.position, latest);
        assert_eq!(latest_publication.publication, 2);
        assert_eq!(
            mailbox.acknowledge(latest_publication, || Some(3)),
            CursorPositionAcknowledgement::Drained
        );
        assert!(mailbox.published.is_none());
        assert_eq!(mailbox.current, Some(latest));
        let CursorPositionRearm::Rearmed(replayed) = mailbox.rearm(|| Some(3)) else {
            panic!("the acknowledged current position was not replayed");
        };
        assert_eq!(replayed.position, latest);
        assert_eq!(replayed.publication, 3);
    }

    #[test]
    fn r_s11gu_cursor_topology_barrier_discards_only_pre_topology_pending_state() {
        let before = CursorPositionValue { x: 10, y: 20 };
        let pre_topology_pending = CursorPositionValue { x: 30, y: 40 };
        let after = CursorPositionValue { x: 50, y: 60 };
        let mut mailbox = CursorPositionMailbox::default();
        let CursorPositionOffer::Published(before_publication) =
            mailbox.offer(before, || Some(1))
        else {
            panic!("first cursor position was not published");
        };
        assert_eq!(
            mailbox.offer(pre_topology_pending, || Some(2)),
            CursorPositionOffer::Pending
        );
        mailbox.invalidate_current();
        assert_eq!(mailbox.published, Some(before_publication));
        assert!(mailbox.current.is_none());

        assert_eq!(mailbox.offer(after, || Some(2)), CursorPositionOffer::Pending);
        let CursorPositionAcknowledgement::Promoted(after_publication) =
            mailbox.acknowledge(before_publication, || Some(2))
        else {
            panic!("post-topology cursor position was not promoted");
        };
        assert_eq!(after_publication.position, after);
        assert!(is_cursor_position_topology_barrier("peer_info"));
        assert!(is_cursor_position_topology_barrier("switch_display"));
        assert!(!is_cursor_position_topology_barrier("clipboard"));
    }

    #[test]
    fn r_s11gu_cursor_stream_rearm_replaces_the_token_and_keeps_only_latest_state() {
        let first = CursorPositionValue { x: 10, y: 20 };
        let latest = CursorPositionValue { x: 50, y: 60 };
        let mut mailbox = CursorPositionMailbox::default();
        let CursorPositionOffer::Published(first_publication) =
            mailbox.offer(first, || Some(1))
        else {
            panic!("first cursor position was not published");
        };
        assert_eq!(mailbox.offer(latest, || Some(2)), CursorPositionOffer::Pending);
        let CursorPositionRearm::Rearmed(rearmed) = mailbox.rearm(|| Some(2)) else {
            panic!("cursor position was not re-armed for the replacement stream");
        };
        assert_eq!(rearmed.position, latest);
        assert_eq!(rearmed.publication, 2);
        assert_eq!(
            mailbox.acknowledge(first_publication, || Some(3)),
            CursorPositionAcknowledgement::Ignored
        );
        assert_eq!(
            mailbox.acknowledge(rearmed, || Some(3)),
            CursorPositionAcknowledgement::Drained
        );
        assert_eq!(mailbox.current, Some(latest));

        let CursorPositionRearm::Rearmed(replayed_after_drain) =
            mailbox.rearm(|| Some(3))
        else {
            panic!("the current cursor position was not replayed after acknowledgement");
        };
        assert_eq!(replayed_after_drain.position, latest);
        assert_eq!(
            mailbox.acknowledge(replayed_after_drain, || Some(4)),
            CursorPositionAcknowledgement::Drained
        );

        let CursorPositionOffer::Published(exhausted_publication) =
            mailbox.offer(first, || Some(4))
        else {
            panic!("cursor position was not republished after drain");
        };
        assert_eq!(mailbox.offer(latest, || Some(4)), CursorPositionOffer::Pending);
        assert_eq!(
            mailbox.acknowledge(exhausted_publication, || None),
            CursorPositionAcknowledgement::Exhausted
        );
        assert!(mailbox.published.is_none());
        assert!(mailbox.current.is_none());

        assert_eq!(
            mailbox.offer(first, || None),
            CursorPositionOffer::Exhausted
        );
        assert!(mailbox.published.is_none());
        assert!(mailbox.current.is_none());

        let CursorPositionOffer::Published(_) =
            mailbox.offer(first, || Some(4))
        else {
            panic!("cursor position was not published before re-arm exhaustion");
        };
        assert_eq!(
            mailbox.offer(latest, || Some(5)),
            CursorPositionOffer::Pending
        );
        assert_eq!(
            mailbox.rearm(|| None),
            CursorPositionRearm::Exhausted
        );
        assert!(mailbox.published.is_none());
        assert!(mailbox.current.is_none());
    }

    fn test_cursor_shape(id: &str, revision: u64, byte: u8) -> Arc<RemoteCursorShape> {
        Arc::new(RemoteCursorShape {
            id: id.to_owned(),
            revision,
            hotx: 0,
            hoty: 0,
            width: 1,
            height: 1,
            rgba: vec![byte; 4],
        })
    }

    #[test]
    fn r_s11gv_cursor_shape_mailbox_is_exact_latest_wins_and_replayable() {
        let first = test_cursor_shape("1", 1, 1);
        let superseded = test_cursor_shape("2", 2, 2);
        let latest = test_cursor_shape("3", 3, 3);
        let mut mailbox = CursorShapeMailbox::default();
        let CursorShapeOffer::Published(first_publication) = mailbox.offer(
            CursorShapeValue {
                state: CursorShapeState::Available(Arc::clone(&first)),
                include_data: true,
            },
            || Some(1),
        ) else {
            panic!("the first cursor shape was not published");
        };
        assert_eq!(
            mailbox.offer(
                CursorShapeValue {
                    state: CursorShapeState::Available(superseded),
                    include_data: true,
                },
                || Some(2),
            ),
            CursorShapeOffer::Pending
        );
        assert_eq!(
            mailbox.offer(
                CursorShapeValue {
                    state: CursorShapeState::Available(Arc::clone(&latest)),
                    include_data: false,
                },
                || Some(3),
            ),
            CursorShapeOffer::Pending
        );
        assert_eq!(
            mailbox.acknowledge("2", 1, first_publication.publication, || Some(2)),
            CursorShapeAcknowledgement::Ignored
        );
        assert_eq!(
            mailbox.acknowledge("1", 1, first_publication.publication + 1, || Some(2)),
            CursorShapeAcknowledgement::Ignored
        );
        let CursorShapeAcknowledgement::Promoted(latest_publication) = mailbox.acknowledge(
            "1",
            1,
            first_publication.publication,
            || Some(2),
        ) else {
            panic!("the latest cursor shape was not promoted");
        };
        assert_eq!(latest_publication.value.state.identity(), ("3", 3));
        assert!(!latest_publication.value.include_data);
        assert_eq!(
            mailbox.acknowledge("3", 3, latest_publication.publication, || Some(3)),
            CursorShapeAcknowledgement::Drained
        );
        assert!(mailbox.published.is_none());

        let CursorShapeRearm::Rearmed(replayed) = mailbox.rearm(|| Some(3)) else {
            panic!("the acknowledged cursor shape was not replayed");
        };
        assert_eq!(replayed.value.state.identity(), ("3", 3));
        assert!(replayed.value.include_data);
        assert_eq!(
            mailbox.acknowledge("3", 3, replayed.publication, || Some(4)),
            CursorShapeAcknowledgement::Drained
        );
        assert_eq!(
            mailbox.current.as_ref().map(|value| value.state.identity()),
            Some(("3", 3))
        );
    }

    #[test]
    fn r_s11gv_cursor_shape_mailbox_bounds_failure_unavailable_and_exhaustion() {
        let shape = test_cursor_shape("1", 1, 1);
        let mut mailbox = CursorShapeMailbox::default();
        let CursorShapeOffer::Published(first) = mailbox.offer(
            CursorShapeValue {
                state: CursorShapeState::Available(shape),
                include_data: true,
            },
            || Some(1),
        ) else {
            panic!("the cursor shape was not published");
        };
        mailbox.delivery_failed();
        assert!(mailbox.published.is_none());
        assert!(mailbox.current.is_some());
        assert_eq!(
            mailbox.acknowledge("1", 1, first.publication, || Some(2)),
            CursorShapeAcknowledgement::Ignored
        );
        assert_eq!(
            mailbox.offer(
                CursorShapeValue {
                    state: CursorShapeState::Unavailable("missing".to_owned()),
                    include_data: false,
                },
                || Some(2),
            ),
            CursorShapeOffer::Pending
        );
        let CursorShapeRearm::Rearmed(unavailable) = mailbox.rearm(|| Some(2)) else {
            panic!("the latest unavailable cursor state was not rearmed");
        };
        assert_eq!(unavailable.value.state.identity(), ("missing", 0));
        assert_eq!(
            mailbox.acknowledge("missing", 0, unavailable.publication, || None),
            CursorShapeAcknowledgement::Drained
        );
        assert_eq!(mailbox.rearm(|| None), CursorShapeRearm::Exhausted);
        assert!(mailbox.current.is_none());
    }

    #[test]
    fn r_s11gv_negative_id_ack_republishes_full_data_exactly_once() {
        let shape = test_cursor_shape("known", 7, 7);
        let mut mailbox = CursorShapeMailbox::default();
        let CursorShapeOffer::Published(id_only) = mailbox.offer(
            CursorShapeValue {
                state: CursorShapeState::Available(shape),
                include_data: false,
            },
            || Some(1),
        ) else {
            panic!("the ID-only cursor shape was not published");
        };
        mailbox.require_data_for(&id_only);
        let CursorShapeAcknowledgement::Promoted(full_data) = mailbox.acknowledge(
            "known",
            7,
            id_only.publication,
            || Some(2),
        ) else {
            panic!("the rejected ID-only shape was not repaired with full data");
        };
        assert!(full_data.value.include_data);
        assert_eq!(
            mailbox.acknowledge("known", 7, full_data.publication, || Some(3)),
            CursorShapeAcknowledgement::Drained
        );
    }

    #[test]
    fn r_s11gv_cursor_shape_cache_evicts_by_count_bytes_and_recency() {
        let mut cache = CursorShapeCache::default();
        for revision in 1..=CURSOR_SHAPE_CACHE_MAX_ENTRIES as u64 {
            let id = revision.to_string();
            assert!(cache.insert(test_cursor_shape(&id, revision, revision as u8)));
        }
        assert_eq!(cache.entries.len(), CURSOR_SHAPE_CACHE_MAX_ENTRIES);
        assert!(cache.get("1").is_some());
        assert!(cache.insert(test_cursor_shape("replacement", 65, 65)));
        assert!(cache.get("2").is_none());
        assert!(cache.get("1").is_some());
        assert!(cache.get("replacement").is_some());
        assert_eq!(cache.entries.len(), CURSOR_SHAPE_CACHE_MAX_ENTRIES);
        assert_eq!(cache.rgba_bytes, CURSOR_SHAPE_CACHE_MAX_ENTRIES * 4);

        cache.use_counter = u64::MAX;
        assert!(cache.get("1").is_none());
        assert!(cache.entries.is_empty());
        assert_eq!(cache.rgba_bytes, 0);
    }

    #[test]
    fn r_s11gv_cursor_shape_id_is_used_only_after_exact_decoded_knowledge() {
        let shape = test_cursor_shape("known", 7, 7);
        let id_reference = CursorShapeValue {
            state: CursorShapeState::Available(Arc::clone(&shape)),
            include_data: false,
        };
        let mut known = CursorShapeKnowledge::default();

        assert!(id_reference
            .clone()
            .bind_to_knowledge(&mut known)
            .include_data);
        assert!(known.insert(&shape));
        assert!(!id_reference
            .clone()
            .bind_to_knowledge(&mut known)
            .include_data);

        known.remove(&shape.id, Some(shape.revision + 1));
        assert!(!id_reference
            .clone()
            .bind_to_knowledge(&mut known)
            .include_data);
        known.remove(&shape.id, Some(shape.revision));
        assert!(id_reference.bind_to_knowledge(&mut known).include_data);
    }

    #[test]
    fn r_s11gv_cursor_shape_knowledge_is_metadata_only_and_bounded() {
        let mut known = CursorShapeKnowledge::default();
        for revision in 1..=CURSOR_SHAPE_CACHE_MAX_ENTRIES as u64 {
            let shape = RemoteCursorShape {
                id: revision.to_string(),
                revision,
                hotx: 0,
                hoty: 0,
                width: 1,
                height: 1,
                rgba: vec![revision as u8; 4],
            };
            assert!(known.insert(&shape));
        }
        assert_eq!(known.entries.len(), CURSOR_SHAPE_CACHE_MAX_ENTRIES);
        assert_eq!(known.rgba_bytes, CURSOR_SHAPE_CACHE_MAX_ENTRIES * 4);

        let first = RemoteCursorShape {
            id: "1".to_owned(),
            revision: 1,
            hotx: 0,
            hoty: 0,
            width: 1,
            height: 1,
            rgba: vec![1; 4],
        };
        assert!(known.contains(&first));

        let replacement = RemoteCursorShape {
            id: "replacement".to_owned(),
            revision: 65,
            hotx: 0,
            hoty: 0,
            width: 1,
            height: 1,
            rgba: vec![65; 4],
        };
        assert!(known.insert(&replacement));
        assert!(known.entries.contains_key("1"));
        assert!(!known.entries.contains_key("2"));
        assert!(known.contains(&replacement));
        assert_eq!(known.entries.len(), CURSOR_SHAPE_CACHE_MAX_ENTRIES);
        assert_eq!(known.rgba_bytes, CURSOR_SHAPE_CACHE_MAX_ENTRIES * 4);
    }

    #[test]
    fn r_s11gv_new_ui_handler_inherits_current_shape_and_position_for_replay() {
        let flutter = FlutterHandler::default();
        let shape = test_cursor_shape("current", 9, 9);
        let mut current = flutter.current_cursor.write().unwrap();
        current.shape = Some(CursorShapeValue {
            state: CursorShapeState::Available(Arc::clone(&shape)),
            include_data: false,
        });
        current.position = Some(CursorPositionValue { x: 31, y: 47 });

        let owner = SessionID::new_v4();
        let mut handler =
            FlutterHandler::session_handler_for_cursor_state(owner, &current);
        drop(current);
        assert_eq!(handler.client_owner_id, Some(owner));
        assert_eq!(
            handler
                .cursor_shape
                .current
                .as_ref()
                .map(|value| value.state.identity()),
            Some(("current", 9))
        );
        assert!(handler
            .cursor_shape
            .current
            .as_ref()
            .is_some_and(|value| !value.include_data));
        assert_eq!(
            handler.cursor_position.current,
            Some(CursorPositionValue { x: 31, y: 47 })
        );

        let CursorShapeRearm::Rearmed(replayed_shape) =
            handler.cursor_shape.rearm(|| Some(1))
        else {
            panic!("the inherited cursor shape was not replayable");
        };
        assert!(replayed_shape.value.include_data);
        let CursorPositionRearm::Rearmed(replayed_position) =
            handler.cursor_position.rearm(|| Some(2))
        else {
            panic!("the inherited cursor position was not replayable");
        };
        assert_eq!(replayed_position.position, CursorPositionValue { x: 31, y: 47 });
    }

    #[test]
    fn r_s11ew_rgba_mailbox_keeps_published_frame_stable_and_promotes_only_latest() {
        let mut mailbox = RgbaData::default();
        let mut first = vec![1; 16];
        assert_eq!(mailbox.offer_swap(&mut first, || Some(1)), Some(1));
        assert_eq!(mailbox.data, vec![1; 16]);
        let published_ptr = mailbox.data.as_ptr();

        let mut second = vec![2; 16];
        assert_eq!(mailbox.offer_swap(&mut second, || Some(2)), None);
        let mut latest = vec![3; 16];
        assert_eq!(mailbox.offer_swap(&mut latest, || Some(3)), None);
        assert_eq!(mailbox.data.as_ptr(), published_ptr);
        assert_eq!(mailbox.data, vec![1; 16]);
        assert_eq!(mailbox.pending.as_deref(), Some(&[3; 16][..]));
        assert_eq!(mailbox.copy(2), None);
        assert_eq!(mailbox.copy(1), Some(vec![1; 16]));

        assert_eq!(
            mailbox.acknowledge(1, || Some(2)),
            RgbaAcknowledgement::Promoted(2)
        );
        assert_eq!(mailbox.data, vec![3; 16]);
        assert!(mailbox.valid);
        assert!(mailbox.pending.is_none());
        assert!(mailbox.spare.is_empty());
        assert_eq!(
            mailbox.acknowledge(1, || Some(3)),
            RgbaAcknowledgement::Ignored
        );
        assert!(mailbox.valid);

        assert_eq!(
            mailbox.acknowledge(2, || Some(3)),
            RgbaAcknowledgement::Drained
        );
        assert!(!mailbox.valid);
    }

    #[test]
    fn r_s11fr_rgba_rearm_replaces_the_token_and_promotes_only_the_latest_frame() {
        let mut mailbox = RgbaData::default();
        let mut first = vec![1; 16];
        assert_eq!(mailbox.offer_swap(&mut first, || Some(1)), Some(1));

        assert_eq!(mailbox.rearm(|| Some(2)), RgbaRearm::Rearmed(2));
        assert_eq!(mailbox.copy(1), None);
        assert_eq!(mailbox.copy(2), Some(vec![1; 16]));

        let mut second = vec![2; 16];
        assert_eq!(mailbox.offer_swap(&mut second, || Some(3)), None);
        let mut latest = vec![3; 16];
        assert_eq!(mailbox.offer_swap(&mut latest, || Some(4)), None);
        assert_eq!(mailbox.rearm(|| Some(3)), RgbaRearm::Rearmed(3));
        assert_eq!(mailbox.data, vec![3; 16]);
        assert!(mailbox.pending.is_none());
        assert_eq!(
            mailbox.acknowledge(2, || Some(4)),
            RgbaAcknowledgement::Ignored
        );
        assert_eq!(
            mailbox.acknowledge(3, || Some(4)),
            RgbaAcknowledgement::Drained
        );
    }

    #[test]
    fn r_s11fr_rgba_rearm_is_idle_without_a_publication_and_fails_closed_on_exhaustion() {
        let mut mailbox = RgbaData::default();
        let mut publication_requested = false;
        assert_eq!(
            mailbox.rearm(|| {
                publication_requested = true;
                Some(1)
            }),
            RgbaRearm::Idle
        );
        assert!(!publication_requested);

        let mut first = vec![1; 8];
        assert_eq!(mailbox.offer_swap(&mut first, || Some(1)), Some(1));
        let mut pending = vec![2; 8];
        assert_eq!(mailbox.offer_swap(&mut pending, || Some(2)), None);
        assert_eq!(mailbox.rearm(|| None), RgbaRearm::Exhausted);
        assert!(!mailbox.valid);
        assert_eq!(mailbox.publication, 0);
        assert!(mailbox.pending.is_none());
        assert_eq!(mailbox.copy(1), None);
    }

    #[test]
    fn r_s11fr_failed_rgba_rearm_retires_the_exact_mailbox() {
        let handler = FlutterHandler::default();
        let session_id = SessionID::new_v4();
        let mut frame = vec![1; 8];
        assert_eq!(
            handler
                .offer_rgba_to_sessions(&[session_id], 4, &mut frame)
                .len(),
            1
        );

        assert!(handler
            .rearm_rgba_for_presentation_recovery(&session_id, 4, None)
            .is_err());
        assert!(!handler
            .display_rgbas
            .read()
            .unwrap()
            .contains_key(&(session_id, 4)));
    }

    #[test]
    fn r_s11ew_rgba_mailboxes_are_exact_per_ui_session_and_display() {
        let handler = FlutterHandler::default();
        let first = SessionID::new_v4();
        let second = SessionID::new_v4();
        let mut initial = vec![10; 8];
        let publications = handler.offer_rgba_to_sessions(&[first, second], 4, &mut initial);
        assert_eq!(
            publications
                .iter()
                .map(|(session_id, _)| *session_id)
                .collect::<Vec<_>>(),
            vec![first, second]
        );
        let first_publication = publications[0].1;
        let second_publication = publications[1].1;
        assert_eq!(
            handler.copy_rgba(&first, 4, first_publication),
            Some(vec![10; 8])
        );
        assert_eq!(
            handler.copy_rgba(&second, 4, second_publication),
            Some(vec![10; 8])
        );
        assert_eq!(
            handler.copy_rgba(&SessionID::new_v4(), 4, first_publication),
            None
        );

        let mut replacement = vec![20; 8];
        assert!(handler
            .offer_rgba_to_sessions(&[first, second], 4, &mut replacement)
            .is_empty());
        {
            let mut mailboxes = handler.display_rgbas.write().unwrap();
            let first_mailbox = mailboxes
                .get_mut(&(first, 4))
                .expect("first exact RGBA mailbox");
            assert!(matches!(
                first_mailbox.acknowledge(first_publication, || Some(3)),
                RgbaAcknowledgement::Promoted(_)
            ));
            assert_eq!(first_mailbox.data, vec![20; 8]);

            let second_mailbox = mailboxes
                .get(&(second, 4))
                .expect("second exact RGBA mailbox");
            assert_eq!(second_mailbox.data, vec![10; 8]);
            assert_eq!(second_mailbox.pending.as_deref(), Some(&[20; 8][..]));
        }

        handler.retire_rgba_session(&first);
        assert_eq!(handler.copy_rgba(&first, 4, first_publication), None);
        let mailboxes = handler.display_rgbas.read().unwrap();
        assert!(!mailboxes.contains_key(&(first, 4)));
        assert!(mailboxes.contains_key(&(second, 4)));
    }

    #[test]
    fn r_s11ew_rgba_without_a_live_consumer_retains_no_frame() {
        let handler = FlutterHandler::default();
        let mut incoming = vec![7; 8];
        assert!(handler
            .offer_rgba_to_sessions(&[], 0, &mut incoming)
            .is_empty());
        assert_eq!(incoming, vec![7; 8]);
        assert!(handler.display_rgbas.read().unwrap().is_empty());
    }

    #[test]
    fn r_s11ew_display_switch_retires_only_obsolete_exact_mailboxes() {
        let handler = FlutterHandler::default();
        let current = SessionID::new_v4();
        let other = SessionID::new_v4();
        let mut frame = vec![1; 4];
        handler.offer_rgba_to_sessions(&[current], 0, &mut frame);
        let mut frame = vec![2; 4];
        handler.offer_rgba_to_sessions(&[current], 1, &mut frame);
        let mut frame = vec![3; 4];
        handler.offer_rgba_to_sessions(&[other], 0, &mut frame);

        handler.retire_rgba_displays_except(&current, &[1]);
        let mailboxes = handler.display_rgbas.read().unwrap();
        assert!(!mailboxes.contains_key(&(current, 0)));
        assert!(mailboxes.contains_key(&(current, 1)));
        assert!(mailboxes.contains_key(&(other, 0)));
    }

    #[test]
    fn r_s11ex_retired_desktop_ui_owner_cannot_replace_or_clear_texture() {
        let handler = FlutterHandler::default();
        let session_id = SessionID::new_v4();
        let old_owner = SessionID::new_v4();
        let replacement_owner = SessionID::new_v4();
        {
            let mut handlers = handler.session_handlers.write().unwrap();
            handlers.insert(
                session_id,
                SessionHandler {
                    client_owner_id: Some(old_owner),
                    ..Default::default()
                },
            );
        }
        assert_eq!(
            handler.register_pixelbuffer_texture(&session_id, &old_owner, 0, 41),
            Some(true)
        );

        // Tab-to-window transfer reuses the connection UUID but replaces the
        // exact UI owner and its renderer.
        {
            let mut handlers = handler.session_handlers.write().unwrap();
            handlers.insert(
                session_id,
                SessionHandler {
                    client_owner_id: Some(replacement_owner),
                    ..Default::default()
                },
            );
        }
        assert_eq!(
            handler.register_pixelbuffer_texture(&session_id, &replacement_owner, 0, 84),
            Some(true)
        );
        assert_eq!(
            handler.register_pixelbuffer_texture(&session_id, &old_owner, 0, 99),
            Some(false),
            "a late old create must not replace the new texture"
        );
        assert_eq!(
            handler.register_pixelbuffer_texture(&session_id, &old_owner, 0, 0),
            Some(false),
            "a late old teardown must not clear the new texture"
        );

        let handlers = handler.session_handlers.read().unwrap();
        let current = handlers.get(&session_id).unwrap();
        let displays = current.renderer.map_display_sessions.read().unwrap();
        assert_eq!(displays.get(&0).unwrap().texture_rgba_ptr, 84);
    }

    #[test]
    fn r_s11ew_rgba_publication_exhaustion_fails_closed() {
        let mut mailbox = RgbaData::default();
        let mut frame = vec![1; 4];
        assert_eq!(mailbox.offer_swap(&mut frame, || None), None);
        assert!(!mailbox.valid);
        assert!(mailbox.data.is_empty());

        assert_eq!(mailbox.offer_swap(&mut frame, || Some(1)), Some(1));
        let mut pending = vec![2; 4];
        assert_eq!(mailbox.offer_swap(&mut pending, || Some(2)), None);
        assert_eq!(
            mailbox.acknowledge(1, || None),
            RgbaAcknowledgement::Exhausted
        );
        assert!(!mailbox.valid);
        assert_eq!(mailbox.publication, 0);
        assert!(mailbox.pending.is_none());
    }

    #[test]
    fn r_s11e149_screenshot_data_is_owned_by_the_exact_ui_session() {
        let handler = FlutterHandler::default();
        let first = SessionID::new_v4();
        let second = SessionID::new_v4();
        {
            let mut handlers = handler.session_handlers.write().unwrap();
            handlers.insert(first, SessionHandler::default());
            handlers.insert(second, SessionHandler::default());
        }

        let first_data = bytes::Bytes::from_static(b"first-session-screenshot");
        handler.handle_screenshot_resp(
            first.to_string(),
            "first-request".to_owned(),
            Some(first_data.clone()),
            String::new(),
        );
        assert!(
            handler.take_screenshot(&second, "first-request").is_none(),
            "another live UI session must not consume the first session's screenshot"
        );
        assert!(
            handler.take_screenshot(&first, "wrong-request").is_none(),
            "a stale callback must not consume the exact session's replacement screenshot"
        );
        assert_eq!(
            handler.take_screenshot(&first, "first-request"),
            Some(first_data)
        );
        assert!(
            handler.take_screenshot(&first, "first-request").is_none(),
            "the exact session may consume an admitted screenshot only once"
        );

        handler.handle_screenshot_resp(
            first.to_string(),
            "stale-request".to_owned(),
            Some(bytes::Bytes::from_static(b"stale-screenshot")),
            String::new(),
        );
        assert!(handler.begin_screenshot_request(&first));
        assert!(
            handler.take_screenshot(&first, "stale-request").is_none(),
            "a new exact-session request must retire its previous screenshot"
        );

        handler.handle_screenshot_resp(
            first.to_string(),
            "retired-request".to_owned(),
            Some(bytes::Bytes::from_static(b"retired-screenshot")),
            String::new(),
        );
        handler.session_handlers.write().unwrap().remove(&first);
        assert!(
            handler.take_screenshot(&first, "retired-request").is_none(),
            "removing the exact UI session must destroy its screenshot authority"
        );
    }

    #[test]
    fn new_mobile_owner_closes_stale_peer_before_reusing_it() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let stale_session_id = SessionID::new_v4();
        let stale_owner_id = SessionID::new_v4();
        let stale = sessions::insert_test_session_for_owner(
            stale_session_id,
            stale_owner_id,
            "host-a",
            ConnType::DEFAULT_CONN,
        );
        let replacement_owner_id = SessionID::new_v4();
        let replacement_session_id = SessionID::new_v4();
        assert_eq!(
            close_previous_mobile_client_sessions(&replacement_owner_id, &replacement_session_id),
            (1, 1)
        );
        assert!(!sessions::contains_peer("host-a", ConnType::DEFAULT_CONN));
        assert!(stale.close_requested.load(Ordering::Acquire));
        sessions::clear_for_test();
    }

    #[test]
    fn mobile_cleanup_preserves_only_the_exact_current_connection() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let current_owner = SessionID::new_v4();
        let current_session = SessionID::new_v4();
        let current = sessions::insert_test_session_for_owner(
            current_session,
            current_owner,
            "host-a",
            ConnType::DEFAULT_CONN,
        );
        let stale_files = sessions::insert_test_session_for_owner(
            SessionID::new_v4(),
            current_owner,
            "host-b",
            ConnType::FILE_TRANSFER,
        );
        let stale_control = sessions::insert_test_session_for_owner(
            SessionID::new_v4(),
            SessionID::new_v4(),
            "host-c",
            ConnType::DEFAULT_CONN,
        );

        assert_eq!(
            close_previous_mobile_client_sessions(&current_owner, &current_session),
            (2, 2)
        );
        assert!(sessions::contains_peer("host-a", ConnType::DEFAULT_CONN));
        assert!(!sessions::contains_peer("host-b", ConnType::FILE_TRANSFER));
        assert!(!sessions::contains_peer("host-c", ConnType::DEFAULT_CONN));
        assert!(!current.close_requested.load(Ordering::Acquire));
        assert!(stale_files.close_requested.load(Ordering::Acquire));
        assert!(stale_control.close_requested.load(Ordering::Acquire));
        assert_eq!(close_sessions_owned_by(&current_owner), (1, 1));
        sessions::clear_for_test();
    }

    #[test]
    fn stale_mobile_session_close_cannot_select_replacement_from_same_owner() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let client_owner_id = SessionID::new_v4();
        let stale_session_id = SessionID::new_v4();
        let replacement_session_id = SessionID::new_v4();
        let stale = sessions::insert_test_session_for_owner(
            stale_session_id,
            client_owner_id,
            "same-host",
            ConnType::DEFAULT_CONN,
        );

        assert_eq!(
            close_previous_mobile_client_sessions(&client_owner_id, &replacement_session_id),
            (1, 1)
        );
        assert!(stale.close_requested.load(Ordering::Acquire));

        let replacement = sessions::insert_test_session_for_owner(
            replacement_session_id,
            client_owner_id,
            "same-host",
            ConnType::DEFAULT_CONN,
        );
        assert!(sessions::remove_session_by_session_id(&stale_session_id).is_none());
        assert!(sessions::contains_peer("same-host", ConnType::DEFAULT_CONN));
        assert!(!replacement.close_requested.load(Ordering::Acquire));
        assert!(sessions::session_has_client_owner(
            &replacement_session_id,
            &client_owner_id
        ));

        sessions::clear_for_test();
    }

    #[test]
    fn android_lifecycle_retirement_is_nonblocking_and_replacement_waits_for_exact_drain() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let generation = begin_android_client_owner().unwrap();
        let owner = SessionID::new_v4();
        assert!(bind_android_client_owner(generation, owner));
        let session_id = SessionID::new_v4();
        let session = sessions::insert_test_session_for_owner(
            session_id,
            owner,
            "host-control",
            ConnType::DEFAULT_CONN,
        );
        let close_requested = session.close_requested.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_by_worker = finished.clone();
        let (worker_reached_close_tx, worker_reached_close_rx) = mpsc::channel();
        let (release_worker_tx, release_worker_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            while !close_requested.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            worker_reached_close_tx.send(()).unwrap();
            release_worker_rx.recv().unwrap();
            finished_by_worker.store(true, Ordering::Release);
        });
        *session.thread.lock().unwrap() = Some(worker);

        let (transition_done_tx, transition_done_rx) = mpsc::channel();
        let transition = std::thread::spawn(move || {
            transition_done_tx
                .send(begin_android_client_owner())
                .unwrap();
        });
        let replacement_generation = transition_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("Activity owner transition blocked on predecessor finality")
            .expect("replacement Activity owner generation");
        worker_reached_close_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("exact drain did not close the predecessor worker");
        transition.join().unwrap();
        assert!(!finished.load(Ordering::Acquire));

        let replacement_owner = SessionID::new_v4();
        assert!(bind_android_client_owner(
            replacement_generation,
            replacement_owner
        ));
        let (wait_started_tx, wait_started_rx) = mpsc::channel();
        let (wait_done_tx, wait_done_rx) = mpsc::channel();
        let wait = std::thread::spawn(move || {
            wait_started_tx.send(()).unwrap();
            wait_done_tx
                .send(wait_for_android_client_owner_drain(&replacement_owner))
                .unwrap();
        });
        wait_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("replacement drain waiter did not start");
        assert!(
            wait_done_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "replacement admission crossed an incomplete predecessor drain"
        );

        release_worker_tx.send(()).unwrap();
        wait_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("replacement drain barrier did not complete")
            .expect("replacement owner changed while predecessor drained");
        wait.join().unwrap();
        assert!(finished.load(Ordering::Acquire));
        assert!(session.thread.lock().unwrap().is_none());
        assert_eq!(
            retire_android_client_owner(replacement_generation, &replacement_owner),
            (0, 0)
        );
        sessions::clear_for_test();
    }

    #[test]
    fn android_lifecycle_transition_does_not_wait_for_mobile_replacement_drain() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let generation = begin_android_client_owner().unwrap();
        let owner = SessionID::new_v4();
        assert!(bind_android_client_owner(generation, owner));
        let predecessor_session_id = SessionID::new_v4();
        let session = sessions::insert_test_session_for_owner(
            predecessor_session_id,
            owner,
            "host-control",
            ConnType::DEFAULT_CONN,
        );
        let close_requested = session.close_requested.clone();
        let (worker_reached_close_tx, worker_reached_close_rx) = mpsc::channel();
        let (release_worker_tx, release_worker_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            while !close_requested.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            worker_reached_close_tx.send(()).unwrap();
            release_worker_rx.recv().unwrap();
        });
        *session.thread.lock().unwrap() = Some(worker);

        let replacement_session_id = SessionID::new_v4();
        let predecessor_drain =
            take_previous_android_mobile_client_sessions(&owner, &replacement_session_id)
                .expect("active Android owner");
        let cleanup = std::thread::spawn(move || close_client_owner_drain(predecessor_drain));
        worker_reached_close_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mobile replacement drain did not close its predecessor worker");

        let (transition_done_tx, transition_done_rx) = mpsc::channel();
        let transition = std::thread::spawn(move || {
            transition_done_tx
                .send(begin_android_client_owner())
                .unwrap();
        });
        transition_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("Activity owner transition waited on mobile replacement finality")
            .expect("replacement Activity owner generation");
        transition.join().unwrap();

        release_worker_tx.send(()).unwrap();
        assert_eq!(cleanup.join().unwrap(), (1, 1));
        sessions::clear_for_test();
    }

    #[test]
    fn failed_session_start_rolls_back_and_joins_only_the_exact_session() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let owner = SessionID::new_v4();
        let failed_session_id = SessionID::new_v4();
        let replacement_session_id = SessionID::new_v4();
        let failed = sessions::insert_test_session_for_owner(
            failed_session_id,
            owner,
            "host-failed",
            ConnType::DEFAULT_CONN,
        );
        let replacement = sessions::insert_test_session_for_owner(
            replacement_session_id,
            owner,
            "host-replacement",
            ConnType::FILE_TRANSFER,
        );
        let close_requested = failed.close_requested.clone();
        rollback_failed_session_start(&failed_session_id, &SessionID::new_v4());
        assert!(sessions::contains_peer(
            "host-failed",
            ConnType::DEFAULT_CONN
        ));
        assert!(!close_requested.load(Ordering::Acquire));
        let (worker_reached_close_tx, worker_reached_close_rx) = mpsc::channel();
        let (release_worker_tx, release_worker_rx) = mpsc::channel();
        *failed.thread.lock().unwrap() = Some(std::thread::spawn(move || {
            while !close_requested.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            worker_reached_close_tx.send(()).unwrap();
            release_worker_rx.recv().unwrap();
        }));

        let (rollback_done_tx, rollback_done_rx) = mpsc::channel();
        let rollback = std::thread::spawn(move || {
            rollback_failed_session_start(&failed_session_id, &owner);
            rollback_done_tx.send(()).unwrap();
        });
        worker_reached_close_rx.recv().unwrap();
        assert!(
            rollback_done_rx.try_recv().is_err(),
            "failed-start rollback returned before the exact worker joined"
        );
        assert!(!replacement.close_requested.load(Ordering::Acquire));

        release_worker_tx.send(()).unwrap();
        rollback_done_rx.recv().unwrap();
        rollback.join().unwrap();
        assert!(!sessions::contains_peer(
            "host-failed",
            ConnType::DEFAULT_CONN
        ));
        assert!(sessions::contains_peer(
            "host-replacement",
            ConnType::FILE_TRANSFER
        ));
        assert!(!replacement.close_requested.load(Ordering::Acquire));
        sessions::clear_for_test();
    }

    #[test]
    fn delayed_android_owner_callbacks_cannot_retire_or_close_the_replacement_owner() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let mut owners = AndroidClientOwnerState::default();
        let old_session_id = SessionID::new_v4();
        let new_session_id = SessionID::new_v4();
        let (old_generation, previous) = owners.begin(0).unwrap();
        assert!(previous.is_none());
        assert!(owners.bind(old_generation, old_session_id));
        assert!(owners.allows(&old_session_id));

        let old_control = sessions::insert_test_session(
            old_session_id,
            "host-old-control",
            ConnType::DEFAULT_CONN,
        );
        let old_files = sessions::insert_test_session(
            old_session_id,
            "host-old-files",
            ConnType::FILE_TRANSFER,
        );
        let (new_generation, previous) = owners.begin(0).unwrap();
        assert_eq!(previous, Some(old_session_id));
        assert_eq!(close_sessions_owned_by(&previous.unwrap()), (2, 2));
        assert!(old_control.close_requested.load(Ordering::Acquire));
        assert!(old_files.close_requested.load(Ordering::Acquire));
        assert!(!owners.allows(&old_session_id));
        assert!(!owners.bind(old_generation, old_session_id));
        assert!(owners.bind(new_generation, new_session_id));

        let new_control = sessions::insert_test_session(
            new_session_id,
            "host-new-control",
            ConnType::DEFAULT_CONN,
        );
        assert!(!owners.retire(old_generation, &old_session_id));
        assert!(owners.allows(&new_session_id));
        assert!(!new_control.close_requested.load(Ordering::Acquire));
        assert!(sessions::contains_peer(
            "host-new-control",
            ConnType::DEFAULT_CONN
        ));
        assert!(owners.allows(&new_session_id));
        assert_eq!(close_sessions_owned_by(&old_session_id), (0, 0));

        assert!(owners.retire(new_generation, &new_session_id));
        assert_eq!(close_sessions_owned_by(&new_session_id), (1, 1));
        assert!(new_control.close_requested.load(Ordering::Acquire));
        sessions::clear_for_test();
    }

    #[test]
    fn android_owner_admission_excludes_a_generation_transition() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let generation = begin_android_client_owner().unwrap();
        let session_id = SessionID::new_v4();
        assert!(bind_android_client_owner(generation, session_id));

        let admission = acquire_android_client_owner(&session_id).unwrap();
        assert!(ANDROID_CLIENT_OWNER.try_write().is_err());
        drop(admission);

        let next_generation = begin_android_client_owner().unwrap();
        assert!(next_generation > generation);
        assert!(acquire_android_client_owner(&session_id).is_err());
        sessions::clear_for_test();
    }

    #[test]
    fn stale_android_activity_cannot_reclaim_the_replacement_owner() {
        let _guard = TEST_LOCK.lock().unwrap();
        sessions::clear_for_test();

        let first_generation = begin_android_client_owner().unwrap();
        let first_session_id = SessionID::new_v4();
        assert!(bind_android_client_owner(
            first_generation,
            first_session_id
        ));

        let second_generation = begin_android_client_owner().unwrap();
        let second_session_id = SessionID::new_v4();
        assert!(bind_android_client_owner(
            second_generation,
            second_session_id
        ));
        let second_control = sessions::insert_test_session(
            second_session_id,
            "host-second-control",
            ConnType::DEFAULT_CONN,
        );

        assert_eq!(
            resume_android_client_owner(first_generation, first_session_id),
            None
        );
        assert!(!second_control.close_requested.load(Ordering::Acquire));
        assert!(sessions::contains_peer(
            "host-second-control",
            ConnType::DEFAULT_CONN
        ));
        assert!(acquire_android_client_owner(&first_session_id).is_err());
        assert!(acquire_android_client_owner(&second_session_id).is_ok());
        assert_eq!(
            resume_android_client_owner(first_generation, second_session_id),
            Some(second_generation)
        );
        assert_eq!(
            resume_android_client_owner(second_generation + 1, second_session_id),
            None
        );
        assert!(!second_control.close_requested.load(Ordering::Acquire));

        sessions::clear_for_test();
    }
}
