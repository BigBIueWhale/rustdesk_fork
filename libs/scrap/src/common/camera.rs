use std::{
    io,
    sync::{Arc, Mutex},
};

#[cfg(any(target_os = "windows", target_os = "linux"))]
use nokhwa::{
    pixel_format::RgbAFormat,
    query,
    utils::{ApiBackend, CameraIndex, RequestedFormat, RequestedFormatType},
};
#[cfg(target_os = "windows")]
use nokhwa::Camera;
#[cfg(target_os = "linux")]
use nokhwa::{backends::capture::V4LCaptureDevice as Camera, camera_traits::CaptureBackendTrait};

use hbb_common::message_proto::{DisplayInfo, Resolution};

#[cfg(feature = "vram")]
use crate::AdapterDevice;

use crate::common::{bail, ResultType};
use crate::{Frame, TraitCapturer};
#[cfg(any(target_os = "windows", target_os = "linux"))]
use crate::{PixelBuffer, Pixfmt};

pub const PRIMARY_CAMERA_IDX: usize = 0;

#[cfg(target_os = "linux")]
use std::{
    convert::TryFrom,
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Weak},
};

/// Linux currently publishes one primary camera. Each catalog retains that exact
/// open device; protocol ordinal zero is never converted back to a native index.
#[cfg(target_os = "linux")]
pub struct CameraCatalog {
    generation: u64,
    identity: (u64, u64, u64),
    display: DisplayInfo,
    camera: Mutex<Camera>,
    retired: AtomicBool,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct CameraCatalogPool {
    catalogs: Vec<Weak<CameraCatalog>>,
}

#[cfg(target_os = "linux")]
impl CameraCatalogPool {
    /// Native discovery and device inspection must run outside the async runtime.
    pub fn acquire(&mut self) -> ResultType<Arc<CameraCatalog>> {
        self.catalogs.retain(|catalog| catalog.strong_count() != 0);
        let cameras = query(ApiBackend::Auto)?;
        let info = cameras.iter().find(|info| matches!(info.index(), CameraIndex::Index(0)))
            .or_else(|| cameras.first()).ok_or_else(|| hbb_common::anyhow::anyhow!("No camera found"))?;
        let camera = Camera::new(info.index(), RequestedFormat::new::<RgbAFormat>(RequestedFormatType::None))?;
        let identity = camera.device_identity()?;
        for catalog in self.catalogs.iter().filter_map(Weak::upgrade) {
            if catalog.identity == identity && !catalog.is_retired() {
                // Inspect the retained registration as well as the fresh open.
                // A dead handle cannot grant reuse just because its node remains.
                let retained = catalog.camera.lock().unwrap();
                if retained.device_identity()? == identity
                    && retained.camera_format() == camera.camera_format()
                    && !catalog.is_retired()
                {
                    drop(retained);
                    return Ok(catalog);
                }
            }
        }
        // Sixteen authenticated sessions are admitted by the server. Reserve
        // another sixteen slots for generations whose exact workers are draining.
        if self.catalogs.len() >= 32 {
            bail!("Camera generations are still draining");
        }
        static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
        let generation = NEXT_GENERATION.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |value| value.checked_add(1)).map_err(|_| hbb_common::anyhow::anyhow!("Camera generation exhausted"))?;
        let resolution = camera.resolution();
        let width = i32::try_from(resolution.width())?;
        let height = i32::try_from(resolution.height())?;
        if width <= 0 || height <= 0 {
            bail!("Camera returned an empty resolution");
        }
        let catalog = Arc::new(CameraCatalog {
            generation,
            identity,
            display: DisplayInfo {
                name: camera.camera_info().human_name(),
                width, height, online: true, scale: 1.0,
                original_resolution: Some(Resolution { width, height, ..Default::default() }).into(),
                ..Default::default()
            },
            camera: Mutex::new(camera),
            retired: AtomicBool::new(false),
        });
        self.catalogs.push(Arc::downgrade(&catalog));
        Ok(catalog)
    }
}

#[cfg(target_os = "linux")]
impl CameraCatalog {
    pub fn generation(&self) -> u64 { self.generation }

    pub fn display(&self, index: usize) -> Option<&DisplayInfo> {
        (index == PRIMARY_CAMERA_IDX).then_some(&self.display)
    }

    pub fn is_retired(&self) -> bool { self.retired.load(Ordering::Acquire) }

    pub fn retire(&self) { self.retired.store(true, Ordering::Release); }

    pub fn capturer(self: &Arc<Self>, index: usize) -> ResultType<Box<dyn TraitCapturer>> {
        if self.display(index).is_none() || self.is_retired() {
            bail!("Camera catalog does not own this capture");
        }
        Ok(Box::new(CameraCapturer {
            catalog: Arc::clone(self), data: Vec::new(), last_data: Vec::new(),
        }))
    }

    fn frame(&self, timeout: std::time::Duration) -> io::Result<nokhwa::Buffer> {
        let mut camera = self.camera.lock().unwrap();
        if self.is_retired() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "Camera catalog retired"));
        }
        if !camera.is_stream_open() {
            camera.open_stream().map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        }
        let result = camera.frame_with_timeout(timeout);
        if matches!(&result, Err(error) if error.kind() != io::ErrorKind::WouldBlock) {
            self.retire();
            camera.stop_stream().map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        }
        result
    }
}

#[cfg(not(target_os = "linux"))]
lazy_static::lazy_static! {
    static ref SYNC_CAMERA_DISPLAYS: Arc<Mutex<Vec<DisplayInfo>>> = Arc::new(Mutex::new(Vec::new()));
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
const CAMERA_NOT_SUPPORTED: &str = "This platform doesn't support camera yet";

#[cfg(not(target_os = "linux"))]
pub struct Cameras;

// pre-condition
#[cfg(not(target_os = "linux"))]
pub fn primary_camera_exists() -> bool {
    Cameras::exists(PRIMARY_CAMERA_IDX)
}

#[cfg(target_os = "windows")]
impl Cameras {
    pub fn all_info() -> ResultType<Vec<DisplayInfo>> {
        match query(ApiBackend::Auto) {
            Ok(cameras) => {
                let mut camera_displays = SYNC_CAMERA_DISPLAYS.lock().unwrap();
                camera_displays.clear();
                let mut x = 0;
                for info in &cameras {
                    let camera = Self::create_camera(info.index())?;
                    let resolution = camera.resolution();
                    let (width, height) = (resolution.width() as i32, resolution.height() as i32);
                    camera_displays.push(DisplayInfo {
                        x,
                        y: 0,
                        name: info.human_name().clone(),
                        width,
                        height,
                        online: true,
                        cursor_embedded: false,
                        scale: 1.0,
                        original_resolution: Some(Resolution {
                            width,
                            height,
                            ..Default::default()
                        }).into(),
                        ..Default::default()
                    });
                    x += width;
                }
                Ok(camera_displays.clone())
            }
            Err(e) => {
                bail!("Query cameras error: {}", e)
            }
        }
    }

    pub fn exists(index: usize) -> bool {
        match query(ApiBackend::Auto) {
            Ok(cameras) => index < cameras.len(),
            _ => return false,
        }
    }

    fn create_camera(index: &CameraIndex) -> ResultType<Camera> {
        let requested = RequestedFormat::new::<RgbAFormat>(RequestedFormatType::AbsoluteHighestResolution);
        let result = Camera::new(index.clone(), requested);
        match result {
            Ok(camera) => Ok(camera),
            Err(e) => bail!("create camera{} error:  {}", index, e),
        }
    }

    pub fn get_sync_cameras() -> Vec<DisplayInfo> {
        SYNC_CAMERA_DISPLAYS.lock().unwrap().clone()
    }

    pub fn get_capturer(current: usize) -> ResultType<Box<dyn TraitCapturer>> {
        Ok(Box::new(CameraCapturer::new(current)?))
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
impl Cameras {
    pub fn all_info() -> ResultType<Vec<DisplayInfo>> {
        return Ok(Vec::new());
    }

    pub fn exists(_index: usize) -> bool {
        false
    }

    pub fn get_sync_cameras() -> Vec<DisplayInfo> {
        vec![]
    }

    pub fn get_capturer(_current: usize) -> ResultType<Box<dyn TraitCapturer>> {
        bail!(CAMERA_NOT_SUPPORTED);
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub struct CameraCapturer {
    #[cfg(target_os = "windows")]
    camera: Camera,
    #[cfg(target_os = "linux")]
    catalog: Arc<CameraCatalog>,
    data: Vec<u8>,
    last_data: Vec<u8>, // for faster compare and copy
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub struct CameraCapturer;

impl CameraCapturer {
    #[cfg(target_os = "windows")]
    fn new(current: usize) -> ResultType<Self> {
        let index = CameraIndex::Index(current as u32);
        let camera = Cameras::create_camera(&index)?;
        Ok(CameraCapturer {
            camera,
            data: Vec::new(),
            last_data: Vec::new(),
        })
    }

    #[allow(dead_code)]
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn new(_current: usize) -> ResultType<Self> {
        bail!(CAMERA_NOT_SUPPORTED);
    }
}

impl TraitCapturer for CameraCapturer {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    fn frame<'a>(&'a mut self, timeout: std::time::Duration) -> std::io::Result<Frame<'a>> {
        #[cfg(target_os = "windows")]
        if !self.camera.is_stream_open() {
            if let Err(e) = self.camera.open_stream() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Camera open stream error: {}", e),
                ));
            }
        }
        #[cfg(target_os = "linux")]
        let frame = self.catalog.frame(timeout);
        #[cfg(target_os = "windows")]
        let frame = self.camera.frame().map_err(|error| io::Error::new(
            io::ErrorKind::Other, format!("Camera frame error: {}", error),
        ));
        match frame {
            Ok(buffer) => {
                match buffer.decode_image::<RgbAFormat>() {
                    Ok(decoded) => {
                        self.data = decoded.as_raw().to_vec();
                        crate::would_block_if_equal(&mut self.last_data, &self.data)?;
                        // FIXME: macos's PixelBuffer cannot be directly created from bytes slice.
                        cfg_if::cfg_if! {
                            if #[cfg(target_os = "linux")] {
                                let width = decoded.width() as usize;
                                let height = decoded.height() as usize;
                                let row_stride = width
                                    .checked_mul(Pixfmt::RGBA.bytes_per_pixel())
                                    .ok_or_else(|| io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "camera RGBA row stride overflow",
                                    ))?;
                                Ok(Frame::PixelBuffer(PixelBuffer::new(
                                    &self.data,
                                    Pixfmt::RGBA,
                                    width,
                                    height,
                                    row_stride,
                                )?))
                            } else if #[cfg(target_os = "windows")] {
                                Ok(Frame::PixelBuffer(PixelBuffer::new(
                                    &self.data,
                                    Pixfmt::RGBA,
                                    decoded.width() as usize,
                                    decoded.height() as usize,
                                )))
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("Camera is not supported on this platform yet"),
                                ))
                            }
                        }
                    }
                    Err(e) => Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Camera frame decode error: {}", e),
                    )),
                }
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn frame<'a>(&'a mut self, _timeout: std::time::Duration) -> std::io::Result<Frame<'a>> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            CAMERA_NOT_SUPPORTED.to_string(),
        ))
    }

    #[cfg(windows)]
    fn is_gdi(&self) -> bool {
        true
    }

    #[cfg(windows)]
    fn set_gdi(&mut self) -> bool {
        true
    }

    #[cfg(feature = "vram")]
    fn device(&self) -> AdapterDevice {
        AdapterDevice::default()
    }

    #[cfg(feature = "vram")]
    fn set_output_texture(&mut self, _texture: bool) {}
}
