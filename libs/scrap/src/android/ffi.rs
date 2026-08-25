use jni::objects::JValue;
use jni::objects::{JByteArray, JByteBuffer};
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;
use jni::{
    objects::{GlobalRef, JClass, JObject},
    strings::JNIString,
    JavaVM,
};

use hbb_common::{anyhow::anyhow, message_proto::MultiClipboards, protobuf::Message, ResultType};
use jni::errors::{Error as JniError, Result as JniResult};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::convert::TryFrom;
use std::os::raw::c_void;
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use super::frame_raw::{FrameRaw, GenerationOwnedFrameRaw};
use super::frame_raw_generation::GenerationOwnedScreenSize;

lazy_static! {
    static ref JVM: RwLock<Option<JavaVM>> = RwLock::new(None);
    static ref MAIN_SERVICE_CTX: RwLock<Option<MainServiceContext>> = RwLock::new(None); // MainService -> video service / audio service / info
    static ref APPLICATION_CONTEXT: RwLock<Option<GlobalRef>> = RwLock::new(None);
    static ref VIDEO_RAW: Mutex<GenerationOwnedFrameRaw> =
        Mutex::new(GenerationOwnedFrameRaw::new("video", MAX_VIDEO_FRAME_TIMEOUT));
    static ref SCREEN_SIZE: Mutex<GenerationOwnedScreenSize> =
        Mutex::new(GenerationOwnedScreenSize::default());
    static ref AUDIO_RAW: Mutex<FrameRaw> = Mutex::new(FrameRaw::new("audio", MAX_AUDIO_FRAME_TIMEOUT));
    static ref NDK_CONTEXT_INITED: Mutex<bool> = Default::default();
    static ref MEDIA_CODEC_INFOS: RwLock<Option<MediaCodecInfos>> = RwLock::new(None);
    static ref CLIPBOARD_MANAGER: RwLock<Option<GlobalRef>> = RwLock::new(None);
    static ref CLIPBOARDS_HOST: Mutex<Option<MultiClipboards>> = Mutex::new(None);
    static ref CLIPBOARDS_CLIENT: Mutex<Option<MultiClipboards>> = Mutex::new(None);
}

const MAX_VIDEO_FRAME_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_AUDIO_FRAME_TIMEOUT: Duration = Duration::from_millis(1000);
const MAX_ANDROID_VIDEO_RAW_BYTES: usize = 64 * 1024 * 1024;
const MAX_ANDROID_AUDIO_RAW_BYTES: usize = 4 * 1024 * 1024;
const ANDROID_CLIPBOARD_SIDE_PREFIX_BYTES: usize = 1;
const MAX_ANDROID_CLIPBOARD_PROTO_BYTES: usize = 64 * 1024 * 1024;
const MAX_ANDROID_CLIPBOARD_UPDATE_BYTES: usize =
    ANDROID_CLIPBOARD_SIDE_PREFIX_BYTES + MAX_ANDROID_CLIPBOARD_PROTO_BYTES;

struct MainServiceContext {
    generation: Option<u64>,
    listener_started: bool,
    owner: GlobalRef,
}

pub struct MainServiceGenerationRetirement {
    pub raw_video_retired: bool,
    pub screen_size_retired: bool,
}

pub fn get_video_raw(generation: u64, dst: &mut Vec<u8>, last: &mut Vec<u8>) -> Option<()> {
    VIDEO_RAW.lock().ok()?.take(generation, dst, last)
}

pub fn is_video_raw_enabled_for_generation(generation: u64) -> bool {
    VIDEO_RAW
        .lock()
        .map(|raw| raw.is_enabled(generation))
        .unwrap_or(false)
}

pub fn screen_size_for_generation(generation: u64) -> Option<(u16, u16, u16)> {
    SCREEN_SIZE.lock().ok()?.get(generation)
}

pub fn current_screen_size() -> Option<(u16, u16, u16)> {
    SCREEN_SIZE.lock().ok()?.current()
}

pub fn get_audio_raw<'a>(dst: &mut Vec<u8>, last: &mut Vec<u8>) -> Option<()> {
    AUDIO_RAW.lock().ok()?.take(dst, last)
}

pub fn get_clipboards(client: bool) -> Option<MultiClipboards> {
    if client {
        CLIPBOARDS_CLIENT.lock().ok()?.take()
    } else {
        CLIPBOARDS_HOST.lock().ok()?.take()
    }
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_onVideoFrameUpdate(
    env: JNIEnv,
    _class: JClass,
    generation: jni::sys::jlong,
    buffer: JObject,
) {
    let Ok(generation) = u64::try_from(generation) else {
        return;
    };
    let jb = JByteBuffer::from(buffer);
    if let Ok(data) = env.get_direct_buffer_address(&jb) {
        if let Ok(len) = env.get_direct_buffer_capacity(&jb) {
            VIDEO_RAW.lock().unwrap().update_from_jni_buffer(
                generation,
                data,
                len,
                MAX_ANDROID_VIDEO_RAW_BYTES,
            );
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_onAudioFrameUpdate(
    env: JNIEnv,
    _class: JClass,
    buffer: JObject,
) {
    let jb = JByteBuffer::from(buffer);
    if let Ok(data) = env.get_direct_buffer_address(&jb) {
        if let Ok(len) = env.get_direct_buffer_capacity(&jb) {
            AUDIO_RAW.lock().unwrap().update_from_jni_buffer(
                data,
                len,
                MAX_ANDROID_AUDIO_RAW_BYTES,
            );
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_onClipboardUpdate(
    env: JNIEnv,
    _class: JClass,
    buffer: JByteBuffer,
) {
    if let Ok(data) = env.get_direct_buffer_address(&buffer) {
        if let Ok(len) = env.get_direct_buffer_capacity(&buffer) {
            if data.is_null() {
                log::warn!("dropping null Android clipboard update before protobuf parse");
                return;
            }
            if len <= ANDROID_CLIPBOARD_SIDE_PREFIX_BYTES {
                log::warn!("dropping malformed Android clipboard update before protobuf parse");
                return;
            }
            if len > MAX_ANDROID_CLIPBOARD_UPDATE_BYTES {
                log::warn!(
                    "dropping oversized Android clipboard update before protobuf parse: {} > {}",
                    len,
                    MAX_ANDROID_CLIPBOARD_UPDATE_BYTES
                );
                return;
            }
            let data = unsafe { std::slice::from_raw_parts(data, len) };
            let Some(payload) = data.get(ANDROID_CLIPBOARD_SIDE_PREFIX_BYTES..) else {
                return;
            };
            if let Ok(clips) = MultiClipboards::parse_from_bytes(payload) {
                let is_client = data[0] == 1;
                if is_client {
                    *CLIPBOARDS_CLIENT.lock().unwrap() = Some(clips);
                } else {
                    *CLIPBOARDS_HOST.lock().unwrap() = Some(clips);
                }
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_setVideoFrameRawEnable(
    _env: JNIEnv,
    _class: JClass,
    generation: jni::sys::jlong,
    value: jboolean,
) -> jboolean {
    let Ok(generation) = u64::try_from(generation) else {
        return jboolean::from(false);
    };
    jboolean::from(
        VIDEO_RAW
            .lock()
            .unwrap()
            .set_enable(generation, value.eq(&1)),
    )
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_updateScreenInfo(
    _env: JNIEnv,
    _class: JClass,
    generation: jlong,
    width: jint,
    height: jint,
    scale: jint,
) -> jboolean {
    let (Ok(generation), Ok(width), Ok(height), Ok(scale)) = (
        u64::try_from(generation),
        u16::try_from(width),
        u16::try_from(height),
        u16::try_from(scale),
    ) else {
        return jboolean::from(false);
    };
    jboolean::from(
        SCREEN_SIZE
            .lock()
            .unwrap()
            .update(generation, (width, height, scale)),
    )
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_setAudioFrameRawEnable(
    _env: JNIEnv,
    _class: JClass,
    value: jboolean,
) {
    AUDIO_RAW.lock().unwrap().set_enable(value.eq(&1));
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_init(
    mut env: JNIEnv,
    _class: JClass,
    service: JObject,
    application_context: JObject,
) -> jboolean {
    log::debug!("MainService init from java");
    if service.is_null() || application_context.is_null() {
        log::error!("MainService or application context is null");
        return jboolean::from(false);
    }
    let jvm = match env.get_java_vm() {
        Ok(jvm) => jvm,
        Err(error) => {
            log::error!("failed to obtain JVM while initializing MainService: {error}");
            return jboolean::from(false);
        }
    };
    let retained_service = match env.new_global_ref(&service) {
        Ok(service) => service,
        Err(error) => {
            log::error!("failed to retain MainService callback owner: {error}");
            return jboolean::from(false);
        }
    };
    let application_context = match env.new_global_ref(application_context) {
        Ok(application_context) => application_context,
        Err(error) => {
            log::error!("failed to retain process application context: {error}");
            return jboolean::from(false);
        }
    };
    let java_vm = jvm.get_java_vm_pointer() as *mut c_void;
    let mut jvm_lock = JVM.write().unwrap();
    if jvm_lock.is_none() {
        *jvm_lock = Some(jvm);
    }
    drop(jvm_lock);
    if let Some(context_jobject) = install_application_context_once(java_vm, application_context) {
        try_init_rustls_platform_verifier(&mut env, context_jobject);
    }
    let mut current = MAIN_SERVICE_CTX.write().unwrap();
    if let Some(context) = current.as_ref() {
        match env.is_same_object(context.owner.as_obj(), &service) {
            Ok(true) => return jboolean::from(true),
            Ok(false) if context.generation.is_some() => {
                log::error!(
                    "refusing to replace an active MainService callback owner without exact retirement"
                );
                return jboolean::from(false);
            }
            Ok(false) => {}
            Err(error) => {
                log::error!("failed to compare MainService callback owner during init: {error}");
                return jboolean::from(false);
            }
        }
    }
    *current = Some(MainServiceContext {
        generation: None,
        listener_started: false,
        owner: retained_service,
    });
    jboolean::from(true)
}

pub fn bind_main_service_generation<Begin, Rollback>(
    env: &JNIEnv,
    service: &JObject,
    begin_generation: Begin,
    rollback_generation: Rollback,
) -> Option<u64>
where
    Begin: FnOnce() -> u64,
    Rollback: FnOnce(u64),
{
    if service.is_null() {
        return None;
    }
    let mut current = MAIN_SERVICE_CTX.write().unwrap();
    let Some(current) = current.as_mut() else {
        return None;
    };
    match env.is_same_object(current.owner.as_obj(), service) {
        Ok(true) => {}
        Ok(false) => return None,
        Err(error) => {
            log::error!("failed to compare MainService generation owner: {error}");
            return None;
        }
    }
    if current.generation.is_some() {
        return None;
    }
    // The direct-listener reservation is allocated only after the retained Service object has
    // been proved under the same lock that excludes callback-owner replacement. A stale Service
    // therefore cannot advance/supersede the listener lifecycle merely by calling startServer.
    let generation = begin_generation();
    if generation == 0 {
        return None;
    }
    if !VIDEO_RAW.lock().unwrap().begin_generation(generation) {
        log::error!("failed to begin Android raw-video generation {generation}");
        rollback_generation(generation);
        return None;
    }
    if !SCREEN_SIZE.lock().unwrap().begin_generation(generation) {
        log::error!("failed to begin Android screen-size generation {generation}");
        if !VIDEO_RAW.lock().unwrap().retire_generation(generation) {
            log::error!(
                "failed to roll back Android raw-video generation {generation} after screen-size admission failure"
            );
        }
        rollback_generation(generation);
        return None;
    }
    current.generation = Some(generation);
    current.listener_started = false;
    Some(generation)
}

pub fn claim_main_service_listener_start(
    env: &JNIEnv,
    service: &JObject,
    generation: u64,
) -> bool {
    if generation == 0 || service.is_null() {
        return false;
    }
    let mut current = MAIN_SERVICE_CTX.write().unwrap();
    let Some(current) = current.as_mut() else {
        return false;
    };
    if current.generation != Some(generation) || current.listener_started {
        return false;
    }
    match env.is_same_object(current.owner.as_obj(), service) {
        Ok(true) => {
            current.listener_started = true;
            true
        }
        Ok(false) => false,
        Err(error) => {
            log::error!("failed to compare MainService listener owner: {error}");
            false
        }
    }
}

pub fn owns_main_service_generation(
    env: &JNIEnv,
    service: &JObject,
    generation: u64,
) -> bool {
    if generation == 0 || service.is_null() {
        return false;
    }
    let current = MAIN_SERVICE_CTX.read().unwrap();
    let Some(current) = current.as_ref() else {
        return false;
    };
    if current.generation != Some(generation) {
        return false;
    }
    if !current.listener_started {
        return false;
    }
    match env.is_same_object(current.owner.as_obj(), service) {
        Ok(is_owner) => is_owner,
        Err(error) => {
            log::error!("failed to compare MainService health owner: {error}");
            false
        }
    }
}

pub fn retire_main_service_generation(
    env: &JNIEnv,
    service: &JObject,
    generation: u64,
) -> Option<MainServiceGenerationRetirement> {
    if generation == 0 || service.is_null() {
        return None;
    }
    let mut current = MAIN_SERVICE_CTX.write().unwrap();
    let Some(current) = current.as_mut() else {
        return None;
    };
    if current.generation != Some(generation) {
        return None;
    }
    match env.is_same_object(current.owner.as_obj(), service) {
        Ok(true) => {}
        Ok(false) => return None,
        Err(error) => {
            log::error!("failed to compare MainService generation owner: {error}");
            return None;
        }
    }

    let video_retired = VIDEO_RAW.lock().unwrap().retire_generation(generation);
    if !video_retired {
        log::warn!(
            "failed to retire Android raw-video generation {generation} during exact generation retirement"
        );
    }
    let screen_retired = SCREEN_SIZE.lock().unwrap().retire_generation(generation);
    if !screen_retired {
        log::warn!(
            "failed to retire Android screen-size generation {generation} during exact generation retirement"
        );
    }
    current.generation = None;
    current.listener_started = false;
    Some(MainServiceGenerationRetirement {
        raw_video_retired: video_retired,
        screen_size_retired: screen_retired,
    })
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_releaseService(
    env: JNIEnv,
    _class: JClass,
    service: JObject,
) -> jboolean {
    if service.is_null() {
        log::error!("cannot release a null MainService callback owner");
        return jboolean::from(false);
    }
    let mut current = MAIN_SERVICE_CTX.write().unwrap();
    let Some(owner) = current.as_ref() else {
        return jboolean::from(false);
    };
    let generation = owner.generation;
    let is_current = match env.is_same_object(owner.owner.as_obj(), &service) {
        Ok(is_current) => is_current,
        Err(error) => {
            log::error!("failed to compare MainService callback owner: {error}");
            return jboolean::from(false);
        }
    };
    if is_current {
        if let Some(generation) = generation {
            if !VIDEO_RAW.lock().unwrap().retire_generation(generation) {
                log::warn!(
                    "failed to retire Android raw-video generation {generation} during MainService release"
                );
            }
            if !SCREEN_SIZE.lock().unwrap().retire_generation(generation) {
                log::warn!(
                    "failed to retire Android screen-size generation {generation} during MainService release"
                );
            }
        }
        current.take();
    }
    jboolean::from(is_current)
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_setClipboardManager(
    env: JNIEnv,
    _class: JClass,
    clipboard_manager: JObject,
) {
    log::debug!("ClipboardManager init from java");
    if let Ok(jvm) = env.get_java_vm() {
        let java_vm = jvm.get_java_vm_pointer() as *mut c_void;
        let mut jvm_lock = JVM.write().unwrap();
        if jvm_lock.is_none() {
            *jvm_lock = Some(jvm);
        }
        drop(jvm_lock);
        if let Ok(manager) = env.new_global_ref(clipboard_manager) {
            *CLIPBOARD_MANAGER.write().unwrap() = Some(manager);
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct MediaCodecInfo {
    pub name: String,
    pub is_encoder: bool,
    #[serde(default)]
    pub hw: Option<bool>, // api 29+
    pub mime_type: String,
    pub surface: bool,
    pub nv12: bool,
    #[serde(default)]
    pub low_latency: Option<bool>, // api 30+, decoder
    pub min_bitrate: u32,
    pub max_bitrate: u32,
    pub min_width: usize,
    pub max_width: usize,
    pub min_height: usize,
    pub max_height: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MediaCodecInfos {
    pub version: usize,
    pub w: usize, // aligned
    pub h: usize, // aligned
    pub codecs: Vec<MediaCodecInfo>,
}

// Dead-code excision (JNI-paired): the `Java_ffi_FFI_setCodecInfo` export — populated at app start
// from Kotlin's `MainActivity.setCodecInfo` — is removed together with its Kotlin caller and the
// `FFI.setCodecInfo` declaration (removing only one side of a JNI pair breaks linkage). Its sole
// consumer was the MediaCodec probe in `scrap/src/common/hwcodec.rs`, gated behind
// `#[cfg(feature = "hwcodec")]` and compiled out on every shipped artifact (CPU-only, software
// codec). The reader half below (`get_codec_info`/`clear_codec_info`, `MEDIA_CODEC_INFOS`, and the
// `MediaCodecInfo(s)` structs) is deliberately kept because that compiled-out module still
// references it; with the writer gone `MEDIA_CODEC_INFOS` simply stays `None`, which is inert for
// the software capture path this fork ships.
pub fn get_codec_info() -> Option<MediaCodecInfos> {
    MEDIA_CODEC_INFOS.read().unwrap().as_ref().cloned()
}

pub fn clear_codec_info() {
    *MEDIA_CODEC_INFOS.write().unwrap() = None;
}

// another way to fix "reference table overflow" error caused by new_string and call_main_service_pointer_input frequently calld
// is below, but here I change kind from string to int for performance
/*
        env.with_local_frame(10, || {
            let kind = env.new_string(kind)?;
            env.call_method(
                ctx,
                "rustPointerInput",
                "(Ljava/lang/String;III)V",
                &[
                    JValue::Object(&JObject::from(kind)),
                    JValue::Int(mask),
                    JValue::Int(x),
                    JValue::Int(y),
                ],
            )?;
            Ok(JObject::null())
        })?;
*/
pub fn call_main_service_pointer_input_for_generation(
    generation: u64,
    connection_id: i32,
    kind: &str,
    mask: i32,
    x: i32,
    y: i32,
) -> JniResult<bool> {
    let jvm = JVM.read().unwrap();
    let context = MAIN_SERVICE_CTX.read().unwrap();
    let (Some(jvm), Some(context)) = (jvm.as_ref(), context.as_ref()) else {
        return Err(JniError::ThrowFailed(-1));
    };
    if generation == 0 || connection_id <= 0 || context.generation != Some(generation) {
        return Err(JniError::ThrowFailed(-1));
    }
    let mut env = jvm.attach_current_thread_as_daemon()?;
    let kind = if kind == "touch" { 0 } else { 1 };
    env.call_method(
        &context.owner,
        "rustPointerInput",
        "(IIIII)Z",
        &[
            JValue::Int(connection_id),
            JValue::Int(kind),
            JValue::Int(mask),
            JValue::Int(x),
            JValue::Int(y),
        ],
    )?
    .z()
}

pub fn call_main_service_key_event_for_generation(
    generation: u64,
    connection_id: i32,
    data: &[u8],
) -> JniResult<bool> {
    let jvm = JVM.read().unwrap();
    let context = MAIN_SERVICE_CTX.read().unwrap();
    let (Some(jvm), Some(context)) = (jvm.as_ref(), context.as_ref()) else {
        return Err(JniError::ThrowFailed(-1));
    };
    if generation == 0 || connection_id <= 0 || context.generation != Some(generation) {
        return Err(JniError::ThrowFailed(-1));
    }
    let mut env = jvm.attach_current_thread_as_daemon()?;
    let data = env.byte_array_from_slice(data)?;

    env.call_method(
        &context.owner,
        "rustKeyEventInput",
        "(I[B)Z",
        &[
            JValue::Int(connection_id),
            JValue::Object(&JObject::from(data)),
        ],
    )?
    .z()
}

fn _call_clipboard_manager<S, T>(name: S, sig: T, args: &[JValue]) -> JniResult<()>
where
    S: Into<JNIString>,
    T: Into<JNIString> + AsRef<str>,
{
    if let (Some(jvm), Some(cm)) = (
        JVM.read().unwrap().as_ref(),
        CLIPBOARD_MANAGER.read().unwrap().as_ref(),
    ) {
        let mut env = jvm.attach_current_thread()?;
        env.call_method(cm, name, sig, args)?;
        return Ok(());
    } else {
        return Err(JniError::ThrowFailed(-1));
    }
}

pub fn call_clipboard_manager_update_sanitized_clipboard(data: &[u8]) -> JniResult<()> {
    if let (Some(jvm), Some(cm)) = (
        JVM.read().unwrap().as_ref(),
        CLIPBOARD_MANAGER.read().unwrap().as_ref(),
    ) {
        let mut env = jvm.attach_current_thread()?;
        let data = env.byte_array_from_slice(data)?;

        env.call_method(
            cm,
            "rustUpdateSanitizedClipboard",
            "([B)V",
            &[JValue::Object(&JObject::from(data))],
        )?;
        return Ok(());
    } else {
        return Err(JniError::ThrowFailed(-1));
    }
}

pub fn call_clipboard_manager_enable_client_clipboard(enable: bool) -> JniResult<()> {
    _call_clipboard_manager(
        "rustEnableClientClipboard",
        "(Z)V",
        &[JValue::Bool(jboolean::from(enable))],
    )
}

pub fn call_main_service_set_by_name_for_generation(
    generation: u64,
    name: &str,
    arg1: Option<&str>,
    arg2: Option<&str>,
) -> JniResult<()> {
    let jvm = JVM.read().unwrap();
    let context = MAIN_SERVICE_CTX.read().unwrap();
    let (Some(jvm), Some(context)) = (jvm.as_ref(), context.as_ref()) else {
        return Err(JniError::ThrowFailed(-1));
    };
    if generation == 0 || context.generation != Some(generation) {
        return Err(JniError::ThrowFailed(-1));
    }
    let mut env = jvm.attach_current_thread_as_daemon()?;
    env.with_local_frame(10, |env| -> JniResult<()> {
        let name = env.new_string(name)?;
        let arg1 = env.new_string(arg1.unwrap_or(""))?;
        let arg2 = env.new_string(arg2.unwrap_or(""))?;

        env.call_method(
            &context.owner,
            "rustSetByName",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(&JObject::from(name)),
                JValue::Object(&JObject::from(arg1)),
                JValue::Object(&JObject::from(arg2)),
            ],
        )?;
        Ok(())
    })
}

pub fn call_main_service_set_half_scale_for_generation(
    generation: u64,
    half_scale: bool,
) -> JniResult<()> {
    let jvm = JVM.read().unwrap();
    let context = MAIN_SERVICE_CTX.read().unwrap();
    let (Some(jvm), Some(context)) = (jvm.as_ref(), context.as_ref()) else {
        return Err(JniError::ThrowFailed(-1));
    };
    if generation == 0 || context.generation != Some(generation) {
        return Err(JniError::ThrowFailed(-1));
    }
    let mut env = jvm.attach_current_thread_as_daemon()?;
    env.call_method(
        &context.owner,
        "rustSetHalfScale",
        "(Z)V",
        &[JValue::Bool(jboolean::from(half_scale))],
    )?;
    Ok(())
}

// Difference between MainService, MainActivity, JNI_OnLoad:
//  jvm is the same, ctx is differen and ctx of JNI_OnLoad is null.
//  cpal: all three works
//  Service callbacks: only ctx from MainService works, so use 2 init context functions
// On app start: retain the process application context for NDK consumers
// On service start: replace only the exact MainService callback owner

fn init_ndk_context(java_vm: *mut c_void, context_jobject: *mut c_void) {
    let mut lock = NDK_CONTEXT_INITED.lock().unwrap();
    if *lock {
        unsafe {
            ndk_context::release_android_context();
        }
        *lock = false;
    }
    unsafe {
        ndk_context::initialize_android_context(java_vm, context_jobject);
        #[cfg(feature = "hwcodec")]
        hwcodec::android::ffmpeg_set_java_vm(java_vm);
    }
    *lock = true;
}

fn install_application_context_once(
    java_vm: *mut c_void,
    context: GlobalRef,
) -> Option<*mut c_void> {
    let mut current = APPLICATION_CONTEXT.write().unwrap();
    if current.is_some() {
        return None;
    }
    let context_jobject = context.as_obj().as_raw() as *mut c_void;
    init_ndk_context(java_vm, context_jobject);
    *current = Some(context);
    Some(context_jobject)
}

fn try_init_rustls_platform_verifier(env: &mut JNIEnv, context_jobject: *mut c_void) {
    use hbb_common::config::ANDROID_RUSTLS_PLATFORM_VERIFIER_INITIALIZED as INITIALIZED;
    use std::sync::atomic::Ordering;
    let initialized = INITIALIZED.load(Ordering::Relaxed);
    if !initialized {
        let ctx_for_rustls = unsafe { JObject::from_raw(context_jobject as jni::sys::jobject) };
        if let Err(e) =
            hbb_common::rustls_platform_verifier::android::init_hosted(env, ctx_for_rustls)
        {
            log::error!("Failed to initialize rustls-platform-verifier: {:?}", e);
        } else {
            INITIALIZED.store(true, Ordering::Relaxed);
            log::info!("rustls-platform-verifier initialized successfully");
        }
    }
}

// https://cjycode.com/flutter_rust_bridge/guides/how-to/ndk-init
#[no_mangle]
pub extern "C" fn JNI_OnLoad(vm: jni::JavaVM, res: *mut std::os::raw::c_void) -> jni::sys::jint {
    if let Ok(env) = vm.get_env() {
        let vm = vm.get_java_vm_pointer() as *mut std::os::raw::c_void;
        init_ndk_context(vm, res);
    }
    jni::JNIVersion::V6.into()
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_onAppStart(mut env: JNIEnv, _class: JClass, ctx: JObject) {
    if ctx.is_null() {
        log::error!("application context is null");
        return;
    }
    if APPLICATION_CONTEXT.read().unwrap().is_some() {
        log::info!("application context already initialized");
        return;
    }
    if let Ok(jvm) = env.get_java_vm() {
        if let Ok(context) = env.new_global_ref(ctx) {
            let java_vm = jvm.get_java_vm_pointer() as *mut c_void;
            if let Some(context_jobject) = install_application_context_once(java_vm, context) {
                try_init_rustls_platform_verifier(&mut env, context_jobject);
            } else {
                log::info!("application context already initialized");
            }
        }
    }
}
