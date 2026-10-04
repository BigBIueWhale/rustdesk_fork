use std::rc::Rc;
use std::io;

use super::ffi::*;
use super::Server;
use crate::Pixfmt;

#[derive(Debug)]
pub struct Display {
    server: Rc<Server>,
    default: bool,
    rect: Rect,
    root: xcb_window_t,
    name: String,
    pixfmt: Pixfmt,
    scanline_pad: u8,
    depth: u8,
    visual: xcb_visualid_t,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct Rect {
    pub x: i16,
    pub y: i16,
    pub w: u16,
    pub h: u16,
}

impl Display {
    pub unsafe fn new(
        server: Rc<Server>,
        default: bool,
        rect: Rect,
        root: xcb_window_t,
        name: String,
        pixfmt: Pixfmt,
        scanline_pad: u8,
        depth: u8,
        visual: xcb_visualid_t,
    ) -> Display {
        Display {
            server,
            default,
            rect,
            root,
            name,
            pixfmt,
            scanline_pad,
            depth,
            visual,
        }
    }

    pub fn server(&self) -> &Rc<Server> {
        &self.server
    }
    pub fn is_default(&self) -> bool {
        self.default
    }
    pub fn rect(&self) -> Rect {
        self.rect
    }
    pub fn w(&self) -> usize {
        self.rect.w as _
    }
    pub fn h(&self) -> usize {
        self.rect.h as _
    }
    pub fn root(&self) -> xcb_window_t {
        self.root
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn pixfmt(&self) -> Pixfmt {
        self.pixfmt
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }
    pub fn visual(&self) -> xcb_visualid_t {
        self.visual
    }
    pub fn row_stride(&self) -> io::Result<usize> {
        if !matches!(self.scanline_pad, 8 | 16 | 32) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid X scanline padding"));
        }
        let pad = usize::from(self.scanline_pad);
        let row_bits = self.w().checked_mul(self.pixfmt.bpp())
            .and_then(|bits| bits.checked_add(pad - 1))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "X capture row size overflow"))?;
        Ok((row_bits / pad) * (pad / 8))
    }
}
