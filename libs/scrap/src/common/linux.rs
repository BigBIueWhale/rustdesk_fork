use crate::{
    common::{x11::{self}, TraitCapturer},
    Frame,
};
#[cfg(feature = "wayland")]
use crate::common::wayland;
use std::{io, time::Duration};

// R-X12 (§8): the Display/Capturer enum dispatches to X11 only on the fork — the WAYLAND variant +
// its arms + the wayland capture module are compiled out (no `wayland` feature; X11 is the pinned
// sole backend, is_x11()==true). The variant + arms are cfg-gated so this file still compiles under
// the (unused-on-the-fork) `wayland` feature too.

pub enum Capturer {
    X11(x11::Capturer),
    #[cfg(feature = "wayland")]
    WAYLAND(wayland::Capturer),
}

impl Capturer {
    pub fn new(display: Display) -> io::Result<Capturer> {
        Ok(match display {
            Display::X11(d) => Capturer::X11(x11::Capturer::new(d)?),
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => Capturer::WAYLAND(wayland::Capturer::new(d)?),
        })
    }

    pub fn width(&self) -> usize {
        match self {
            Capturer::X11(d) => d.width(),
            #[cfg(feature = "wayland")]
            Capturer::WAYLAND(d) => d.width(),
        }
    }

    pub fn height(&self) -> usize {
        match self {
            Capturer::X11(d) => d.height(),
            #[cfg(feature = "wayland")]
            Capturer::WAYLAND(d) => d.height(),
        }
    }
}

impl TraitCapturer for Capturer {
    fn frame<'a>(&'a mut self, timeout: Duration) -> io::Result<Frame<'a>> {
        match self {
            Capturer::X11(d) => d.frame(timeout),
            #[cfg(feature = "wayland")]
            Capturer::WAYLAND(d) => d.frame(timeout),
        }
    }
}

pub enum Display {
    X11(x11::Display),
    #[cfg(feature = "wayland")]
    WAYLAND(wayland::Display),
}

impl Display {
    pub fn primary() -> io::Result<Display> {
        #[cfg(feature = "wayland")]
        if !super::is_x11() {
            return Ok(Display::WAYLAND(wayland::Display::primary()?));
        }
        Ok(Display::X11(x11::Display::primary()?))
    }

    pub fn all() -> io::Result<Vec<Display>> {
        #[cfg(feature = "wayland")]
        if !super::is_x11() {
            return Ok(wayland::Display::all()?
                .drain(..)
                .map(|x| Display::WAYLAND(x))
                .collect());
        }
        Ok(x11::Display::all()?
            .drain(..)
            .map(|x| Display::X11(x))
            .collect())
    }

    pub fn width(&self) -> usize {
        match self {
            Display::X11(d) => d.width(),
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => d.width(),
        }
    }

    pub fn height(&self) -> usize {
        match self {
            Display::X11(d) => d.height(),
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => d.height(),
        }
    }

    pub fn scale(&self) -> f64 {
        match self {
            Display::X11(_d) => 1.0,
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => d.scale(),
        }
    }

    pub fn logical_width(&self) -> usize {
        match self {
            Display::X11(d) => d.width(),
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => d.logical_width(),
        }
    }

    pub fn logical_height(&self) -> usize {
        match self {
            Display::X11(d) => d.height(),
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => d.logical_height(),
        }
    }

    pub fn origin(&self) -> (i32, i32) {
        match self {
            Display::X11(d) => d.origin(),
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => d.origin(),
        }
    }

    pub fn is_online(&self) -> bool {
        match self {
            Display::X11(d) => d.is_online(),
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => d.is_online(),
        }
    }

    pub fn is_primary(&self) -> bool {
        match self {
            Display::X11(d) => d.is_primary(),
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => d.is_primary(),
        }
    }

    pub fn name(&self) -> String {
        match self {
            Display::X11(d) => d.name(),
            #[cfg(feature = "wayland")]
            Display::WAYLAND(d) => d.name(),
        }
    }
}

// R-X12 (§8): set_map_err is a no-op when the Wayland capture path is compiled out — the pipewire
// error-mapper it installed (wayland::set_map_err) is gone with `mod wayland`. Kept so the call site
// (server/wayland.rs init) stays feature-agnostic.
#[cfg(not(feature = "wayland"))]
pub fn set_map_err(_f: fn(String) -> std::io::Error) {}
