use crate::android::ffi::*;
use crate::{Frame, Pixfmt};
use std::{io, time::Duration};

pub struct Capturer {
    display: Display,
    rgba: Vec<u8>,
    saved_raw_data: Vec<u8>, // for faster compare and copy
}

impl Capturer {
    pub fn new(display: Display) -> io::Result<Capturer> {
        if display.service_generation == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android capture requires an exact MainService generation",
            ));
        }
        Ok(Capturer {
            display,
            rgba: Vec::new(),
            saved_raw_data: Vec::new(),
        })
    }

    pub fn width(&self) -> usize {
        self.display.width() as usize
    }

    pub fn height(&self) -> usize {
        self.display.height() as usize
    }
}

impl crate::TraitCapturer for Capturer {
    fn frame<'a>(&'a mut self, _timeout: Duration) -> io::Result<Frame<'a>> {
        if get_video_raw(
            self.display.service_generation,
            &mut self.rgba,
            &mut self.saved_raw_data,
        )
        .is_some()
        {
            Ok(Frame::PixelBuffer(PixelBuffer::new(
                &self.rgba,
                self.width(),
                self.height(),
            )))
        } else {
            return Err(io::ErrorKind::WouldBlock.into());
        }
    }
}

pub struct PixelBuffer<'a> {
    data: &'a [u8],
    width: usize,
    height: usize,
    stride: Vec<usize>,
}

impl<'a> PixelBuffer<'a> {
    pub fn new(data: &'a [u8], width: usize, height: usize) -> Self {
        let stride0 = data.len() / height;
        let mut stride = Vec::new();
        stride.push(stride0);
        PixelBuffer {
            data,
            width,
            height,
            stride,
        }
    }
}

impl<'a> crate::TraitPixelBuffer for PixelBuffer<'a> {
    fn data(&self) -> &[u8] {
        self.data
    }

    fn width(&self) -> usize {
        self.width
    }

    fn height(&self) -> usize {
        self.height
    }

    fn stride(&self) -> Vec<usize> {
        self.stride.clone()
    }

    fn pixfmt(&self) -> Pixfmt {
        Pixfmt::RGBA
    }
}

pub struct Display {
    default: bool,
    rect: Rect,
    service_generation: u64,
    scale: u16,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
struct Rect {
    pub x: i16,
    pub y: i16,
    pub w: u16,
    pub h: u16,
}

impl Display {
    fn from_size(size: (u16, u16, u16), service_generation: u64) -> Display {
        Display {
            default: true,
            rect: Rect {
                x: 0,
                y: 0,
                w: size.0,
                h: size.1,
            },
            service_generation,
            scale: size.2,
        }
    }

    pub fn primary() -> io::Result<Display> {
        let size = current_screen_size().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Android MainService screen information is unavailable",
            )
        })?;
        Ok(Self::from_size(size, 0))
    }

    pub fn primary_for_generation(generation: u64) -> io::Result<Display> {
        let size = screen_size_for_generation(generation).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android MainService screen generation is inactive",
            )
        })?;
        Ok(Self::from_size(size, generation))
    }

    pub fn all_for_generation(generation: u64) -> io::Result<Vec<Display>> {
        Ok(vec![Display::primary_for_generation(generation)?])
    }

    pub fn all() -> io::Result<Vec<Display>> {
        Ok(vec![Display::primary()?])
    }

    pub fn width(&self) -> usize {
        self.rect.w as usize
    }

    pub fn height(&self) -> usize {
        self.rect.h as usize
    }

    pub fn origin(&self) -> (i32, i32) {
        let r = self.rect;
        (r.x as _, r.y as _)
    }

    pub fn is_online(&self) -> bool {
        true
    }

    pub fn is_primary(&self) -> bool {
        self.default
    }

    pub fn name(&self) -> String {
        "Android".into()
    }

    pub fn scale(&self) -> u16 {
        self.scale
    }
}
